#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use reqwest::blocking::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

const SERVICE_URL: &str = "http://127.0.0.1:47621";
const SERVICE_NAME: &str = "PVNv2Helper";
const DEFAULT_API_URL: &str = "https://api-v2.45.63.22.174.sslip.io";
const PROGRAM_DATA_DIR: &str = r"C:\ProgramData";
const SERVICE_DATA_DIR_NAME: &str = "PVN v2";
const HELPER_TOKEN_FILE_NAME: &str = "helper-token";

#[derive(Debug, Deserialize, Serialize)]
struct ServiceStatus {
    state: String,
    last_error: String,
    last_verification: String,
}

#[derive(Debug, Serialize)]
struct ConnectInput {
    api_url: String,
}

#[tauri::command]
fn service_status() -> Result<ServiceStatus, String> {
    service_request("GET", "/status", None)
}

#[tauri::command]
fn service_connect(api_url: String) -> Result<ServiceStatus, String> {
    service_request(
        "POST",
        "/connect",
        Some(
            serde_json::to_value(ConnectInput {
                api_url: normalize_api_url(api_url),
            })
            .map_err(|err| err.to_string())?,
        ),
    )
}

#[tauri::command]
fn service_disconnect() -> Result<ServiceStatus, String> {
    service_request("POST", "/disconnect", Some(serde_json::json!({})))
}

#[tauri::command]
fn service_reset() -> Result<ServiceStatus, String> {
    service_request("POST", "/reset", Some(serde_json::json!({})))
}

#[tauri::command]
fn service_diagnostics() -> Result<Value, String> {
    let mut diagnostics = serde_json::Map::new();
    diagnostics.insert("helper_url".to_string(), Value::String(SERVICE_URL.to_string()));
    diagnostics.insert(
        "helper_service_name".to_string(),
        Value::String(SERVICE_NAME.to_string()),
    );
    diagnostics.insert(
        "ui_token_path".to_string(),
        Value::String(service_token_path().to_string_lossy().to_string()),
    );
    diagnostics.insert(
        "token_file_present".to_string(),
        Value::Bool(service_token_path().exists()),
    );
    diagnostics.insert(
        "helper_service_status".to_string(),
        Value::String(command_output("sc.exe", &["query", SERVICE_NAME])),
    );
    diagnostics.insert(
        "helper_binary_path".to_string(),
        Value::String(service_binary_path()),
    );

    match service_request::<Value>("GET", "/status", None) {
        Ok(status) => {
            diagnostics.insert("status_returns_200".to_string(), Value::Bool(true));
            diagnostics.insert("status".to_string(), status);
        }
        Err(err) => {
            diagnostics.insert("status_returns_200".to_string(), Value::Bool(false));
            diagnostics.insert("status_error".to_string(), Value::String(err));
        }
    }

    match service_request::<Value>("GET", "/auth-check", None) {
        Ok(auth) => {
            diagnostics.insert("connect_auth_preflight_passes".to_string(), Value::Bool(true));
            diagnostics.insert("auth_check".to_string(), auth);
        }
        Err(err) => {
            diagnostics.insert(
                "connect_auth_preflight_passes".to_string(),
                Value::Bool(false),
            );
            diagnostics.insert("auth_check_error".to_string(), Value::String(err));
        }
    }

    match service_request::<Value>("GET", "/diagnostics", None) {
        Ok(helper) => {
            diagnostics.insert("helper_diagnostics".to_string(), helper);
        }
        Err(err) => {
            diagnostics.insert("helper_diagnostics_error".to_string(), Value::String(err));
        }
    }

    Ok(Value::Object(diagnostics))
}

#[tauri::command]
fn service_repair_helper() -> Result<String, String> {
    let mut steps = Vec::new();

    match service_request::<Value>("GET", "/status", None) {
        Ok(_) => steps.push("/status returned 200 before repair".to_string()),
        Err(err) => steps.push(format!("/status failed before repair: {err}")),
    }

    match service_auth_preflight() {
        Ok(_) => {
            steps.push("connect auth preflight passed before repair".to_string());
            return Ok(steps.join("\n"));
        }
        Err(err) => steps.push(format!("connect auth preflight failed before repair: {err}")),
    }

    run_elevated_helper_repair()?;
    steps.push("elevated helper repair command completed".to_string());

    wait_for_status_200(Duration::from_secs(45))?;
    steps.push("/status returned 200 after repair".to_string());

    service_auth_preflight()
        .map_err(|err| format!("helper repair failed at auth preflight after restart: {err}"))?;
    steps.push("connect auth preflight passed after repair".to_string());

    Ok(steps.join("\n"))
}

fn normalize_api_url(api_url: String) -> String {
    let trimmed = api_url.trim();
    if trimmed.is_empty() {
        DEFAULT_API_URL.to_string()
    } else {
        trimmed.to_string()
    }
}

fn service_request<T>(method: &str, path: &str, body: Option<Value>) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|err| err.to_string())?;
    let url = format!("{SERVICE_URL}{path}");
    let mut request = match method {
        "GET" => client.get(url),
        "POST" => client
            .post(url)
            .json(&body.unwrap_or_else(|| serde_json::json!({}))),
        _ => return Err("unsupported service method".to_string()),
    };
    request = maybe_authorize_service_request(request, method, path)?;
    request
        .send()
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .json::<T>()
        .map_err(|err| err.to_string())
}

fn maybe_authorize_service_request(
    request: RequestBuilder,
    method: &str,
    path: &str,
) -> Result<RequestBuilder, String> {
    if !service_request_requires_authorization(method, path) {
        return Ok(request);
    }
    Ok(request.bearer_auth(read_service_token()?))
}

fn service_request_is_read_only(method: &str, path: &str) -> bool {
    method == "GET" && (path == "/status" || path == "/diagnostics")
}

fn service_request_requires_authorization(method: &str, path: &str) -> bool {
    !service_request_is_read_only(method, path)
}

fn read_service_token() -> Result<String, String> {
    let token = fs::read_to_string(service_token_path())
        .map(|value| value.trim().to_string())
        .map_err(|_| "PVN helper token is missing. Open Advanced and use Repair Helper, or reinstall PVN as Administrator.".to_string())?;
    if token.is_empty() {
        return Err("PVN helper token is blank. Open Advanced and use Repair Helper.".to_string());
    }
    Ok(token)
}

fn service_token_path() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(PROGRAM_DATA_DIR))
        .join(SERVICE_DATA_DIR_NAME)
        .join(HELPER_TOKEN_FILE_NAME)
}

fn service_auth_preflight() -> Result<(), String> {
    let _: Value = service_request("GET", "/auth-check", None)?;
    Ok(())
}

fn wait_for_status_200(timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match service_request::<Value>("GET", "/status", None) {
            Ok(_) => return Ok(()),
            Err(err) => last_error = err,
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "PVN helper /status did not return 200 after repair: {last_error}"
    ))
}

fn run_elevated_helper_repair() -> Result<(), String> {
    let resources = resources_dir()?;
    let script = resources.join("install-helper-service.ps1");
    let service_exe = resources.join("pvn-v2-service.exe");
    let payload = resources.join("pvn-v2-service-payload.exe");
    for required in [&script, &service_exe, &payload] {
        if !required.exists() {
            return Err(format!(
                "helper repair file is missing: {}",
                required.to_string_lossy()
            ));
        }
    }

    let arg_items = [
        "'-NoProfile'".to_string(),
        "'-ExecutionPolicy'".to_string(),
        "'Bypass'".to_string(),
        "'-File'".to_string(),
        ps_quote_path(&script),
        "'-ServiceExe'".to_string(),
        ps_quote_path(&service_exe),
        "'-ServicePayload'".to_string(),
        ps_quote_path(&payload),
        "'-ResetToken'".to_string(),
    ];
    let command = format!(
        "$p = Start-Process -FilePath 'powershell.exe' -ArgumentList @({}) -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
        arg_items.join(", ")
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &command])
        .output()
        .map_err(|err| format!("helper repair command could not start: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    Err(format!(
        "elevated helper repair failed with exit={:?}: {detail}",
        output.status.code()
    ))
}

fn resources_dir() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let installed = parent.join("resources");
            if installed.join("install-helper-service.ps1").exists() {
                return Ok(installed);
            }
        }
    }
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources");
    if source.join("install-helper-service.ps1").exists() {
        return Ok(source);
    }
    Err("PVN helper repair resources were not found.".to_string())
}

fn ps_quote_path(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\'', "''");
    format!("'{value}'")
}

fn command_output(exe: &str, args: &[&str]) -> String {
    Command::new(exe)
        .args(args)
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                stdout
            } else {
                format!("{stdout}\n{stderr}")
            }
        })
        .unwrap_or_else(|err| err.to_string())
}

fn service_binary_path() -> String {
    let output = command_output("sc.exe", &["qc", SERVICE_NAME]);
    output
        .lines()
        .find_map(|line| {
            line.split_once("BINARY_PATH_NAME")
                .map(|(_, value)| value.trim().trim_start_matches(':').trim().to_string())
        })
        .unwrap_or(output)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            service_status,
            service_connect,
            service_disconnect,
            service_reset,
            service_diagnostics,
            service_repair_helper
        ])
        .run(tauri::generate_context!())
        .expect("error while running PVN v2");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_diagnostics_do_not_require_helper_token() {
        assert!(!service_request_requires_authorization("GET", "/status"));
        assert!(!service_request_requires_authorization(
            "GET",
            "/diagnostics"
        ));
    }

    #[test]
    fn connect_disconnect_and_reset_require_helper_token() {
        assert!(service_request_requires_authorization("POST", "/connect"));
        assert!(service_request_requires_authorization(
            "POST",
            "/disconnect"
        ));
        assert!(service_request_requires_authorization("POST", "/reset"));
        assert!(service_request_requires_authorization("GET", "/auth-check"));
    }

    #[test]
    fn ui_uses_canonical_program_data_token_path() {
        assert_eq!(
            service_token_path(),
            PathBuf::from(PROGRAM_DATA_DIR)
                .join(SERVICE_DATA_DIR_NAME)
                .join(HELPER_TOKEN_FILE_NAME)
        );
    }

    #[test]
    fn powershell_path_quoting_escapes_single_quotes() {
        let quoted = ps_quote_path(Path::new(r"C:\Program Files\PVN's v2\repair.ps1"));
        assert_eq!(quoted, r"'C:\Program Files\PVN''s v2\repair.ps1'");
    }
}
