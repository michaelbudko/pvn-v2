#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use reqwest::blocking::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, path::PathBuf, time::Duration};

const SERVICE_URL: &str = "http://127.0.0.1:47621";
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
    service_request("GET", "/diagnostics", None)
}

#[tauri::command]
fn service_repair_helper() -> Result<String, String> {
    let token_path = service_token_path();
    if token_path.exists() {
        return Ok("PVN helper token exists. If GO still fails, reinstall PVN as Administrator so the UI and helper service are replaced together.".to_string());
    }
    Err("PVN helper token is missing. Reinstall PVN as Administrator so the helper service can recreate it.".to_string())
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
    fs::read_to_string(service_token_path())
        .map(|value| value.trim().to_string())
        .map_err(|_| "PVN helper token is missing. Open Advanced and use Repair Helper, or reinstall PVN as Administrator.".to_string())
}

fn service_token_path() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(PROGRAM_DATA_DIR))
        .join(SERVICE_DATA_DIR_NAME)
        .join(HELPER_TOKEN_FILE_NAME)
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
}
