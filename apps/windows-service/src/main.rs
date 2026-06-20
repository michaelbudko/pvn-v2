use base64::{engine::general_purpose::STANDARD, Engine};
use rand_core::OsRng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::{ErrorKind, Read, Write},
    net::ToSocketAddrs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVICE_ADDR: &str = "127.0.0.1:47621";
const WINDOWS_SERVICE_NAME: &str = "PVNv2Helper";
const TUNNEL_NAME: &str = "pvn-v2";
const EXPECTED_PUBLIC_IP: &str = "45.63.22.174";
const DEFAULT_API_URL: &str = "https://api-v2.45.63.22.174.sslip.io";
const PUBLIC_IP_URL: &str = "https://api.ipify.org";
const INTERNET_CHECK_URL: &str = "https://ipv4.icanhazip.com";
const PROGRAM_DATA_DIR: &str = r"C:\ProgramData";
const SERVICE_DATA_DIR_NAME: &str = "PVN v2";
const HELPER_TOKEN_FILE_NAME: &str = "helper-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum VpnState {
    Off,
    Connecting,
    On,
    Disconnecting,
    Error,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceStatus {
    state: VpnState,
    last_error: String,
    last_verification: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectRequest {
    api_url: Option<String>,
    #[serde(default)]
    backend_token: String,
}

#[derive(Debug, Deserialize)]
struct DeviceResponse {
    config: ConfigMaterial,
}

#[derive(Debug, Deserialize)]
struct ConfigMaterial {
    client_address: String,
    server_public_key: String,
    endpoint: String,
    dns: String,
    allowed_ips: String,
}

#[derive(Debug, Clone)]
struct WireGuardConfig {
    private_key: String,
    client_address: String,
    server_public_key: String,
    endpoint: String,
    dns: String,
    allowed_ips: String,
}

#[derive(Clone)]
struct ServicePaths {
    root: PathBuf,
    token: PathBuf,
    private_key: PathBuf,
    config: PathBuf,
    endpoint_route: PathBuf,
}

struct TunnelController<R: Runner, V: Verifier> {
    paths: ServicePaths,
    wireguard_exe: PathBuf,
    runner: R,
    verifier: V,
    status: ServiceStatus,
}

trait Runner {
    fn run(&mut self, exe: &Path, args: &[&str]) -> Result<String, String>;
}

trait Verifier {
    fn public_ip(&self) -> Result<String, String>;
    fn internet_ok(&self) -> bool;
    fn tunnel_active(&self, name: &str) -> bool;
}

struct CommandRunner;

impl Runner for CommandRunner {
    fn run(&mut self, exe: &Path, args: &[&str]) -> Result<String, String> {
        let output = Command::new(exe)
            .args(args)
            .output()
            .map_err(|err| format!("wireguard command failed to start: {err}"))?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        Err(format!(
            "wireguard command failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

struct NetworkVerifier;

impl Verifier for NetworkVerifier {
    fn public_ip(&self) -> Result<String, String> {
        curl_ipv4_text(PUBLIC_IP_URL)
    }

    fn internet_ok(&self) -> bool {
        curl_ipv4_text(INTERNET_CHECK_URL).is_ok()
    }

    fn tunnel_active(&self, name: &str) -> bool {
        let service_name = format!("WireGuardTunnel${name}");
        Command::new("sc.exe")
            .args(["query", &service_name])
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .to_lowercase()
                        .contains("running")
            })
    }
}

impl ServicePaths {
    fn default() -> Self {
        let root = env::var("PVN_V2_SERVICE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(PROGRAM_DATA_DIR).join(SERVICE_DATA_DIR_NAME));
        Self {
            token: root.join(HELPER_TOKEN_FILE_NAME),
            private_key: root.join("client-private.key"),
            config: root.join("pvn-v2.conf"),
            endpoint_route: root.join("endpoint-route.txt"),
            root,
        }
    }
}

impl<R: Runner, V: Verifier> TunnelController<R, V> {
    fn new(paths: ServicePaths, wireguard_exe: PathBuf, runner: R, verifier: V) -> Self {
        Self {
            paths,
            wireguard_exe,
            runner,
            verifier,
            status: ServiceStatus {
                state: VpnState::Off,
                last_error: String::new(),
                last_verification: String::new(),
            },
        }
    }

    fn status(&self) -> ServiceStatus {
        self.status.clone()
    }

    fn connect(&mut self, request: ConnectRequest) -> Result<ServiceStatus, String> {
        self.status.state = VpnState::Connecting;
        self.status.last_error.clear();
        fs::create_dir_all(&self.paths.root).map_err(|err| err.to_string())?;
        let private_key = self.load_or_create_private_key()?;
        let public_key = public_key_for_private_key(&private_key)?;
        let config = match self.fetch_config(request.clone(), &public_key, &private_key) {
            Ok(config) => config,
            Err(err) if is_backend_conflict(&err) => {
                self.status.last_verification = "stale local VPN key was reset".to_string();
                self.reset_backend_device(&request)?;
                let private_key = self.replace_private_key()?;
                let public_key = public_key_for_private_key(&private_key)?;
                self.fetch_config(request, &public_key, &private_key)
                    .map_err(|retry_err| self.fail(retry_err))?
            }
            Err(err) => return Err(self.fail(err)),
        };
        validate_wireguard_config(&config).map_err(|err| self.fail(err))?;
        self.cleanup()?;
        let endpoint_ip = endpoint_ipv4(&config.endpoint).map_err(|err| self.fail(err))?;
        self.ensure_endpoint_route(&endpoint_ip)
            .map_err(|err| self.fail(err))?;
        fs::write(&self.paths.config, render_config(&config)).map_err(|err| err.to_string())?;
        let config_path = self
            .paths
            .config
            .to_str()
            .ok_or_else(|| "invalid config path".to_string())?
            .to_string();
        self.runner.run(
            &self.wireguard_exe,
            &["/installtunnelservice", config_path.as_str()],
        )?;
        if !self.wait_for_tunnel_active(tunnel_activation_timeout()) {
            let _ = self.cleanup();
            self.status.state = VpnState::Error;
            self.status.last_error = "PVN tunnel did not become active".to_string();
            return Err(self.status.last_error.clone());
        }
        let public_ip = match self.verifier.public_ip() {
            Ok(public_ip) => public_ip,
            Err(err) => {
                let _ = self.cleanup();
                return Err(self.fail(format!("IPv4 public IP verification failed: {err}")));
            }
        };
        if public_ip != EXPECTED_PUBLIC_IP {
            let _ = self.cleanup();
            self.status.state = VpnState::Error;
            self.status.last_error = format!(
                "VPN verification failed: expected_public_ip={EXPECTED_PUBLIC_IP} observed_public_ip={public_ip}"
            );
            return Err(self.status.last_error.clone());
        }
        if !self.verifier.internet_ok() {
            let _ = self.cleanup();
            self.status.state = VpnState::Error;
            self.status.last_error = format!(
                "VPN tunnel active but IPv4 internet check failed after public_ip={public_ip}"
            );
            return Err(self.status.last_error.clone());
        }
        self.status.state = VpnState::On;
        self.status.last_verification = format!("public_ip={public_ip}");
        Ok(self.status())
    }

    fn disconnect(&mut self) -> Result<ServiceStatus, String> {
        self.status.state = VpnState::Disconnecting;
        self.status.last_error.clear();
        self.cleanup()?;
        if self.verifier.tunnel_active(TUNNEL_NAME) {
            self.status.state = VpnState::Error;
            self.status.last_error = "PVN tunnel is still active after disconnect".to_string();
            return Err(self.status.last_error.clone());
        }
        let public_ip = self.verifier.public_ip()?;
        if public_ip == EXPECTED_PUBLIC_IP || !self.verifier.internet_ok() {
            self.status.state = VpnState::Error;
            self.status.last_error =
                format!("disconnect verification failed: public_ip={public_ip}");
            return Err(self.status.last_error.clone());
        }
        self.status.state = VpnState::Off;
        self.status.last_verification = format!("public_ip={public_ip}");
        Ok(self.status())
    }

    fn reset(&mut self) -> Result<ServiceStatus, String> {
        self.status.last_error.clear();
        self.cleanup()?;
        if self.paths.private_key.exists() {
            fs::remove_file(&self.paths.private_key).map_err(|err| err.to_string())?;
        }
        self.status.state = VpnState::Off;
        Ok(self.status())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let _ = self.runner.run(
            &self.wireguard_exe,
            &["/uninstalltunnelservice", TUNNEL_NAME],
        );
        self.remove_endpoint_route();
        if self.paths.config.exists() {
            fs::remove_file(&self.paths.config).map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    fn ensure_endpoint_route(&mut self, endpoint_ip: &str) -> Result<(), String> {
        let script = add_endpoint_route_script(endpoint_ip);
        let output = self.runner.run(
            Path::new("powershell.exe"),
            &["-NoProfile", "-Command", &script],
        )?;
        if output.contains("CREATED") {
            fs::write(&self.paths.endpoint_route, endpoint_ip).map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    fn remove_endpoint_route(&mut self) {
        if !self.paths.endpoint_route.exists() {
            return;
        }
        let endpoint_ip = match fs::read_to_string(&self.paths.endpoint_route) {
            Ok(value) => value.trim().to_string(),
            Err(_) => String::new(),
        };
        if !endpoint_ip.is_empty() {
            let script = delete_endpoint_route_script(&endpoint_ip);
            let _ = self.runner.run(
                Path::new("powershell.exe"),
                &["-NoProfile", "-Command", &script],
            );
        }
        let _ = fs::remove_file(&self.paths.endpoint_route);
    }

    fn load_or_create_private_key(&self) -> Result<String, String> {
        if self.paths.private_key.exists() {
            return fs::read_to_string(&self.paths.private_key)
                .map(|value| value.trim().to_string())
                .map_err(|err| err.to_string());
        }
        self.replace_private_key()
    }

    fn replace_private_key(&self) -> Result<String, String> {
        let private_key = generate_private_key();
        fs::write(&self.paths.private_key, private_key.as_bytes())
            .map_err(|err| err.to_string())?;
        Ok(private_key)
    }

    fn fetch_config(
        &self,
        request: ConnectRequest,
        public_key: &str,
        private_key: &str,
    ) -> Result<WireGuardConfig, String> {
        let api_url = request
            .api_url
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|err| err.to_string())?;
        let mut builder = client.post(format!("{}/api/devices", api_url.trim_end_matches('/')));
        if !request.backend_token.trim().is_empty() {
            builder = builder.bearer_auth(request.backend_token);
        }
        let response: DeviceResponse = builder
            .json(&serde_json::json!({
                "name": "Windows PC",
                "client_public_key": public_key,
            }))
            .send()
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?
            .json()
            .map_err(|err| err.to_string())?;
        Ok(WireGuardConfig {
            private_key: private_key.to_string(),
            client_address: response.config.client_address,
            server_public_key: response.config.server_public_key,
            endpoint: response.config.endpoint,
            dns: response.config.dns,
            allowed_ips: response.config.allowed_ips,
        })
    }

    fn reset_backend_device(&mut self, request: &ConnectRequest) -> Result<(), String> {
        let api_url = request
            .api_url
            .as_deref()
            .unwrap_or(DEFAULT_API_URL)
            .trim_end_matches('/');
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|err| self.fail(err.to_string()))?;
        let mut builder = client.post(format!("{api_url}/api/devices/reset"));
        if !request.backend_token.trim().is_empty() {
            builder = builder.bearer_auth(&request.backend_token);
        }
        builder
            .send()
            .map_err(|err| self.fail(err.to_string()))?
            .error_for_status()
            .map_err(|err| self.fail(err.to_string()))?;
        Ok(())
    }

    fn wait_for_tunnel_active(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.verifier.tunnel_active(TUNNEL_NAME) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    fn fail(&mut self, message: String) -> String {
        self.status.state = VpnState::Error;
        self.status.last_error = message.clone();
        message
    }
}

fn tunnel_activation_timeout() -> Duration {
    env::var("PVN_V2_TUNNEL_WAIT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30))
}

fn curl_ipv4_text(url: &str) -> Result<String, String> {
    let args = curl_ipv4_args(url);
    let output = Command::new("curl.exe")
        .args(&args)
        .output()
        .map_err(|err| format!("curl.exe IPv4 check could not start: {err}"))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        return Err(format!(
            "curl.exe -4 {url} failed with exit={:?}: {detail}",
            output.status.code()
        ));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        return Err(format!("curl.exe -4 {url} returned an empty response"));
    }
    Ok(value)
}

fn curl_ipv4_args(url: &str) -> Vec<String> {
    [
        "-4",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "15",
        url,
    ]
    .iter()
    .map(|arg| (*arg).to_string())
    .collect()
}

fn endpoint_ipv4(endpoint: &str) -> Result<String, String> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| "WireGuard endpoint must be host:port".to_string())?;
    if host.trim().is_empty() || port.trim().is_empty() {
        return Err("WireGuard endpoint must include host and port".to_string());
    }
    let addrs = (
        host.trim(),
        port.trim()
            .parse::<u16>()
            .map_err(|_| "WireGuard endpoint port must be numeric".to_string())?,
    )
        .to_socket_addrs()
        .map_err(|err| format!("resolve WireGuard endpoint failed: {err}"))?;
    for addr in addrs {
        if addr.ip().is_ipv4() {
            return Ok(addr.ip().to_string());
        }
    }
    Err("WireGuard endpoint did not resolve to an IPv4 address".to_string())
}

fn add_endpoint_route_script(endpoint_ip: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; \
         $target='{endpoint_ip}'; \
         $existing=Get-NetRoute -DestinationPrefix \"$target/32\" -ErrorAction SilentlyContinue | Select-Object -First 1; \
         if ($existing) {{ 'EXISTS'; exit 0 }}; \
         $route=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.NextHop -and $_.NextHop -ne '0.0.0.0' }} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; \
         if (-not $route) {{ throw 'no default IPv4 gateway route found' }}; \
         route.exe ADD $target MASK 255.255.255.255 $route.NextHop METRIC 1 IF $route.ifIndex | Out-Null; \
         if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; \
         'CREATED'"
    )
}

fn delete_endpoint_route_script(endpoint_ip: &str) -> String {
    format!(
        "$target='{endpoint_ip}'; \
         route.exe DELETE $target MASK 255.255.255.255 | Out-Null; \
         exit 0"
    )
}

fn validate_wireguard_config(config: &WireGuardConfig) -> Result<(), String> {
    let fields = [
        ("PrivateKey", &config.private_key),
        ("Address", &config.client_address),
        ("PublicKey", &config.server_public_key),
        ("Endpoint", &config.endpoint),
        ("AllowedIPs", &config.allowed_ips),
    ];
    for (name, value) in fields {
        if value.trim().is_empty() {
            return Err(format!("WireGuard config field {name} is blank"));
        }
    }
    Ok(())
}

fn render_config(config: &WireGuardConfig) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        config.private_key,
        config.client_address,
        config.dns,
        config.server_public_key,
        config.endpoint,
        config.allowed_ips
    )
}

fn generate_private_key() -> String {
    let secret = StaticSecret::random_from_rng(OsRng);
    STANDARD.encode(secret.to_bytes())
}

fn public_key_for_private_key(private_key: &str) -> Result<String, String> {
    let bytes = STANDARD
        .decode(private_key.trim())
        .map_err(|err| format!("private key decode failed: {err}"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "private key must decode to 32 bytes".to_string())?;
    let secret = StaticSecret::from(array);
    let public = PublicKey::from(&secret);
    Ok(STANDARD.encode(public.as_bytes()))
}

fn is_backend_conflict(error: &str) -> bool {
    error.contains("409 Conflict")
}

fn ensure_service_token(paths: &ServicePaths) -> Result<String, String> {
    fs::create_dir_all(&paths.root).map_err(|err| err.to_string())?;
    if paths.token.exists() {
        let token = fs::read_to_string(&paths.token)
            .map(|value| value.trim().to_string())
            .map_err(|err| err.to_string())?;
        if token.is_empty() {
            return Err(
                "PVN helper token is blank; reinstall PVN or repair helper service".to_string(),
            );
        }
        return Ok(token);
    }
    let token = generate_private_key();
    fs::write(&paths.token, token.as_bytes()).map_err(|err| err.to_string())?;
    Ok(token)
}

fn authorize(request: &str, token: &str) -> bool {
    let expected = format!("Authorization: Bearer {token}");
    request.lines().any(|line| line.trim() == expected)
}

fn requires_authorization(first_line: &str, path: &str) -> bool {
    !(first_line.starts_with("GET") && (path == "/status" || path == "/diagnostics"))
}

fn serve_http(
    controller: Arc<Mutex<TunnelController<CommandRunner, NetworkVerifier>>>,
    token: String,
    shutdown_rx: Option<mpsc::Receiver<()>>,
) -> Result<(), String> {
    let listener = TcpListener::bind(SERVICE_ADDR).map_err(|err| err.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;
    loop {
        if let Some(receiver) = &shutdown_rx {
            match receiver.try_recv() {
                Ok(_) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                let controller = Arc::clone(&controller);
                let token = token.clone();
                thread::spawn(move || {
                    let _ = handle_client(stream, controller, &token);
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    controller: Arc<Mutex<TunnelController<CommandRunner, NetworkVerifier>>>,
    token: &str,
) -> Result<(), String> {
    let mut buffer = [0u8; 64 * 1024];
    let read = stream.read(&mut buffer).map_err(|err| err.to_string())?;
    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
    let first = request.lines().next().unwrap_or_default();
    let path = first.split_whitespace().nth(1).unwrap_or("/");
    if requires_authorization(first, path) && !authorize(&request, token) {
        return write_response(
            &mut stream,
            401,
            &serde_json::json!({"error":"unauthorized"}),
        );
    }
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let mut controller = controller
        .lock()
        .map_err(|_| "service lock poisoned".to_string())?;
    let response = match (first.starts_with("GET"), first.starts_with("POST"), path) {
        (true, _, "/status") => serde_json::to_value(controller.status()).unwrap(),
        (_, true, "/connect") => {
            let input: ConnectRequest = match serde_json::from_str(body) {
                Ok(value) => value,
                Err(err) => {
                    return write_response(
                        &mut stream,
                        400,
                        &serde_json::json!({"error": format!("invalid request: {err}")}),
                    );
                }
            };
            match controller.connect(input) {
                Ok(status) => serde_json::to_value(status).unwrap(),
                Err(err) => {
                    controller.status.last_error = err.clone();
                    return write_response(
                        &mut stream,
                        500,
                        &serde_json::json!({"error": err, "status": controller.status()}),
                    );
                }
            }
        }
        (_, true, "/disconnect") => match controller.disconnect() {
            Ok(status) => serde_json::to_value(status).unwrap(),
            Err(err) => {
                controller.status.last_error = err.clone();
                return write_response(
                    &mut stream,
                    500,
                    &serde_json::json!({"error": err, "status": controller.status()}),
                );
            }
        },
        (_, true, "/reset") => match controller.reset() {
            Ok(status) => serde_json::to_value(status).unwrap(),
            Err(err) => {
                controller.status.last_error = err.clone();
                return write_response(
                    &mut stream,
                    500,
                    &serde_json::json!({"error": err, "status": controller.status()}),
                );
            }
        },
        (true, _, "/diagnostics") => serde_json::json!({
            "state": controller.status.state,
            "last_verification": controller.status.last_verification,
            "tunnel_name": TUNNEL_NAME,
        }),
        _ => return write_response(&mut stream, 404, &serde_json::json!({"error":"not found"})),
    };
    write_response(&mut stream, 200, &response)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &serde_json::Value,
) -> Result<(), String> {
    let body = serde_json::to_string(body).map_err(|err| err.to_string())?;
    let status_text = if status == 200 { "OK" } else { "ERROR" };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|err| err.to_string())
}

fn run_daemon(shutdown_rx: Option<mpsc::Receiver<()>>) -> Result<(), String> {
    let paths = ServicePaths::default();
    let token = ensure_service_token(&paths)?;
    let wireguard_exe = env::var("PVN_V2_WIREGUARD_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Program Files\WireGuard\wireguard.exe"));
    let controller = TunnelController::new(paths, wireguard_exe, CommandRunner, NetworkVerifier);
    let controller = Arc::new(Mutex::new(controller));
    serve_http(controller, token, shutdown_rx)
}

fn wants_windows_service<I>(args: I) -> bool
where
    I: IntoIterator<Item = String>,
{
    args.into_iter().any(|arg| arg == "--service")
}

#[cfg(windows)]
mod windows_service_runner {
    use super::*;
    use std::{ffi::OsString, time::Duration};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher, Result,
    };

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> Result<()> {
        service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, event_handler)?;
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let result = run_daemon(Some(shutdown_rx));

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        result.map_err(|err| {
            windows_service::Error::Winapi(std::io::Error::new(ErrorKind::Other, err))
        })
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if wants_windows_service(args) {
        #[cfg(windows)]
        {
            if let Err(err) = windows_service_runner::run() {
                eprintln!("PVN v2 Windows service failed: {err}");
                std::process::exit(1);
            }
            return;
        }
    }
    if let Err(err) = run_daemon(None) {
        eprintln!("PVN v2 service failed: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn status_returns_off_initially() {
        let controller = test_controller(MockRunner::default(), MockVerifier::off());
        assert_eq!(controller.status().state, VpnState::Off);
    }

    #[test]
    fn connect_refuses_blank_config_fields() {
        let config = WireGuardConfig {
            private_key: String::new(),
            client_address: "10.88.0.2/32".to_string(),
            server_public_key: "server".to_string(),
            endpoint: "example.com:51821".to_string(),
            dns: "1.1.1.1".to_string(),
            allowed_ips: "0.0.0.0/0".to_string(),
        };
        assert!(validate_wireguard_config(&config).is_err());
    }

    #[test]
    fn detects_backend_public_key_conflict() {
        assert!(is_backend_conflict(
            "HTTP status client error (409 Conflict) for url"
        ));
        assert!(!is_backend_conflict(
            "HTTP status client error (401 Unauthorized)"
        ));
    }

    #[test]
    fn connect_does_not_mark_on_until_verification_passes() {
        let mut controller = test_controller(MockRunner::default(), MockVerifier::off());
        let err = controller
            .connect_with_config(valid_config())
            .expect_err("verification should fail");
        assert!(err.contains("active"));
        assert_eq!(controller.status().state, VpnState::Error);
    }

    #[test]
    fn connect_does_not_mark_on_when_public_ip_is_wrong() {
        let mut controller = test_controller(
            MockRunner::default(),
            MockVerifier {
                public_ip: "108.204.244.53".to_string(),
                internet: true,
                active: true,
            },
        );
        let err = controller
            .connect_with_config(valid_config())
            .expect_err("wrong public IP should fail");
        assert!(err.contains("expected_public_ip"));
        assert_eq!(controller.status().state, VpnState::Error);
    }

    #[test]
    fn disconnect_does_not_mark_off_until_cleanup_verification_passes() {
        let mut controller = test_controller(MockRunner::default(), MockVerifier::on());
        let err = controller.disconnect().expect_err("tunnel still active");
        assert!(err.contains("still active"));
        assert_eq!(controller.status().state, VpnState::Error);
    }

    #[test]
    fn reset_removes_only_pvn_owned_state() {
        let mut controller = test_controller(MockRunner::default(), MockVerifier::off());
        fs::create_dir_all(&controller.paths.root).unwrap();
        fs::write(&controller.paths.private_key, "secret").unwrap();
        fs::write(controller.paths.root.join("unrelated.conf"), "keep").unwrap();
        controller.reset().unwrap();
        assert!(!controller.paths.private_key.exists());
        assert!(controller.paths.root.join("unrelated.conf").exists());
    }

    #[test]
    fn rejects_unauthorized_requests() {
        let raw = "GET /status HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n";
        assert!(!authorize(raw, "correct"));
    }

    #[test]
    fn accepts_authorized_mutation_requests() {
        let raw = "POST /connect HTTP/1.1\r\nAuthorization: Bearer correct\r\n\r\n{}";
        assert!(authorize(raw, "correct"));
    }

    #[test]
    fn status_does_not_require_helper_token_but_mutations_do() {
        assert!(!requires_authorization("GET /status HTTP/1.1", "/status"));
        assert!(!requires_authorization(
            "GET /diagnostics HTTP/1.1",
            "/diagnostics"
        ));
        assert!(requires_authorization("POST /connect HTTP/1.1", "/connect"));
        assert!(requires_authorization(
            "POST /disconnect HTTP/1.1",
            "/disconnect"
        ));
        assert!(requires_authorization("POST /reset HTTP/1.1", "/reset"));
    }

    #[test]
    fn helper_token_uses_canonical_program_data_path() {
        let paths = ServicePaths::default();
        assert_eq!(
            paths.token,
            PathBuf::from(PROGRAM_DATA_DIR)
                .join(SERVICE_DATA_DIR_NAME)
                .join(HELPER_TOKEN_FILE_NAME)
        );
    }

    #[test]
    fn service_restart_does_not_regenerate_token() {
        let paths = test_paths();
        let first = ensure_service_token(&paths).unwrap();
        let second = ensure_service_token(&paths).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn missing_token_is_regenerated() {
        let paths = test_paths();
        let first = ensure_service_token(&paths).unwrap();
        fs::remove_file(&paths.token).unwrap();
        let second = ensure_service_token(&paths).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn connect_request_allows_missing_backend_token_for_mvp_no_login() {
        let request: ConnectRequest =
            serde_json::from_str(r#"{"api_url":"https://api-v2.45.63.22.174.sslip.io"}"#).unwrap();
        assert!(request.backend_token.is_empty());
    }

    #[test]
    fn cannot_execute_arbitrary_commands() {
        let raw = "POST /run HTTP/1.1\r\nAuthorization: Bearer token\r\n\r\n{\"cmd\":\"calc\"}";
        assert!(authorize(raw, "token"));
        let path = raw
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        assert_ne!(path, "/connect");
        assert_ne!(path, "/disconnect");
        assert_ne!(path, "/reset");
    }

    #[test]
    fn service_binds_localhost_only() {
        assert!(SERVICE_ADDR.starts_with("127.0.0.1:"));
    }

    #[test]
    fn public_ip_verification_uses_curl_ipv4() {
        let args = curl_ipv4_args(PUBLIC_IP_URL);
        assert!(args.contains(&"-4".to_string()));
        assert!(args.contains(&PUBLIC_IP_URL.to_string()));
    }

    #[test]
    fn endpoint_route_scripts_target_vps_host_route() {
        let add = add_endpoint_route_script(EXPECTED_PUBLIC_IP);
        assert!(add.contains(EXPECTED_PUBLIC_IP));
        assert!(add.contains("0.0.0.0/0"));
        assert!(add.contains("route.exe ADD"));
        assert!(add.contains("255.255.255.255"));
        let delete = delete_endpoint_route_script(EXPECTED_PUBLIC_IP);
        assert!(delete.contains("route.exe DELETE"));
        assert!(delete.contains(EXPECTED_PUBLIC_IP));
    }

    #[test]
    fn windows_service_mode_requires_explicit_flag() {
        assert!(wants_windows_service(vec![
            "pvn-v2-service.exe".to_string(),
            "--service".to_string()
        ]));
        assert!(!wants_windows_service(vec![
            "pvn-v2-service.exe".to_string()
        ]));
    }

    #[derive(Default)]
    struct MockRunner {
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl Runner for MockRunner {
        fn run(&mut self, _exe: &Path, args: &[&str]) -> Result<String, String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|arg| (*arg).to_string()).collect());
            Ok(String::new())
        }
    }

    struct MockVerifier {
        public_ip: String,
        internet: bool,
        active: bool,
    }

    impl MockVerifier {
        fn on() -> Self {
            Self {
                public_ip: EXPECTED_PUBLIC_IP.to_string(),
                internet: true,
                active: true,
            }
        }

        fn off() -> Self {
            Self {
                public_ip: "108.204.244.53".to_string(),
                internet: true,
                active: false,
            }
        }
    }

    impl Verifier for MockVerifier {
        fn public_ip(&self) -> Result<String, String> {
            Ok(self.public_ip.clone())
        }

        fn internet_ok(&self) -> bool {
            self.internet
        }

        fn tunnel_active(&self, _name: &str) -> bool {
            self.active
        }
    }

    impl TunnelController<MockRunner, MockVerifier> {
        fn connect_with_config(
            &mut self,
            config: WireGuardConfig,
        ) -> Result<ServiceStatus, String> {
            self.status.state = VpnState::Connecting;
            fs::create_dir_all(&self.paths.root).unwrap();
            validate_wireguard_config(&config)?;
            self.cleanup()?;
            fs::write(&self.paths.config, render_config(&config)).unwrap();
            self.runner.run(
                &self.wireguard_exe,
                &["/installtunnelservice", "pvn-v2.conf"],
            )?;
            if !self.verifier.tunnel_active(TUNNEL_NAME) {
                let _ = self.cleanup();
                self.status.state = VpnState::Error;
                return Err("PVN tunnel did not become active".to_string());
            }
            let public_ip = self.verifier.public_ip()?;
            if public_ip != EXPECTED_PUBLIC_IP {
                let _ = self.cleanup();
                self.status.state = VpnState::Error;
                return Err(format!(
                    "VPN verification failed: expected_public_ip={EXPECTED_PUBLIC_IP} observed_public_ip={public_ip}"
                ));
            }
            if !self.verifier.internet_ok() {
                let _ = self.cleanup();
                self.status.state = VpnState::Error;
                return Err("VPN tunnel active but IPv4 internet check failed".to_string());
            }
            self.status.state = VpnState::On;
            Ok(self.status())
        }
    }

    fn test_controller(
        runner: MockRunner,
        verifier: MockVerifier,
    ) -> TunnelController<MockRunner, MockVerifier> {
        let paths = test_paths();
        TunnelController::new(paths, PathBuf::from("wireguard.exe"), runner, verifier)
    }

    fn test_paths() -> ServicePaths {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("pvn-v2-service-test-{id}"));
        ServicePaths {
            token: root.join(HELPER_TOKEN_FILE_NAME),
            private_key: root.join("client-private.key"),
            config: root.join("pvn-v2.conf"),
            endpoint_route: root.join("endpoint-route.txt"),
            root,
        }
    }

    fn valid_config() -> WireGuardConfig {
        WireGuardConfig {
            private_key: generate_private_key(),
            client_address: "10.88.0.2/32".to_string(),
            server_public_key: generate_private_key(),
            endpoint: "api-v2.45.63.22.174.sslip.io:51821".to_string(),
            dns: "1.1.1.1".to_string(),
            allowed_ips: "0.0.0.0/0".to_string(),
        }
    }
}
