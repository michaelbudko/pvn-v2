#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use reqwest::blocking::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, path::PathBuf, time::Duration};

const SERVICE_URL: &str = "http://127.0.0.1:47621";
const DEFAULT_API_URL: &str = "https://api-v2.45.63.22.174.sslip.io";

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
    if method == "GET" && path == "/status" {
        return Ok(request);
    }
    Ok(request.bearer_auth(read_service_token()?))
}

fn read_service_token() -> Result<String, String> {
    fs::read_to_string(service_token_path())
        .map(|value| value.trim().to_string())
        .map_err(|_| "PVN helper service is not installed or not ready".to_string())
}

fn service_token_path() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join("PVNv2")
        .join("service-token.txt")
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            service_status,
            service_connect,
            service_disconnect,
            service_reset,
            service_diagnostics
        ])
        .run(tauri::generate_context!())
        .expect("error while running PVN v2");
}
