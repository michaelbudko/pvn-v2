import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

const DEFAULT_API_URL = "https://api-v2.45.63.22.174.sslip.io";

type VpnState = "off" | "connecting" | "on" | "disconnecting" | "error";

type ServiceStatus = {
  state: VpnState;
  last_error: string;
  last_verification: string;
};

function friendlyError(error: unknown): string {
  const text = String(error);
  if (text.toLowerCase().includes("helper token")) {
    return "PVN helper needs repair. Open Advanced and click Repair Helper.";
  }
  if (text.includes("401") || text.toLowerCase().includes("unauthorized")) {
    return "PVN helper authorization failed. Open Advanced and click Repair Helper.";
  }
  if (text.toLowerCase().includes("wireguard")) {
    return "WireGuard is not ready. Reinstall PVN or restart Windows.";
  }
  if (text.toLowerCase().includes("public_ip") || text.toLowerCase().includes("blank")) {
    return "VPN profile is broken. Open Advanced and reset PVN.";
  }
  if (text.toLowerCase().includes("connection") || text.toLowerCase().includes("failed to connect")) {
    return "PVN server is unreachable.";
  }
  return "Something went wrong. Try again or send diagnostics to Mike.";
}

function App() {
  const [apiUrl, setApiUrl] = useState(() => localStorage.getItem("pvn-v2-api-url") || DEFAULT_API_URL);
  const [status, setStatus] = useState<ServiceStatus>({ state: "off", last_error: "", last_verification: "" });
  const [busy, setBusy] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [technical, setTechnical] = useState("");
  const [error, setError] = useState("");

  const isOn = status.state === "on";
  const isWorking = busy || status.state === "connecting" || status.state === "disconnecting";
  const mainLabel = useMemo(() => {
    if (status.state === "on") return "ON";
    if (status.state === "connecting") return "CONNECTING";
    if (status.state === "disconnecting") return "DISCONNECTING";
    if (status.state === "error") return "ERROR";
    return "OFF";
  }, [status.state]);

  async function refreshStatus() {
    try {
      const next = await invoke<ServiceStatus>("service_status");
      setStatus(next);
      setTechnical(JSON.stringify(next, null, 2));
    } catch (err) {
      setError(friendlyError(err));
      setTechnical(String(err));
    }
  }

  useEffect(() => {
    refreshStatus();
    const timer = window.setInterval(refreshStatus, 2500);
    return () => window.clearInterval(timer);
  }, []);

  async function connect() {
    setBusy(true);
    setError("");
    try {
      localStorage.setItem("pvn-v2-api-url", apiUrl);
      const next = await invoke<ServiceStatus>("service_connect", { apiUrl });
      setStatus(next);
      setTechnical(JSON.stringify(next, null, 2));
    } catch (err) {
      setError(friendlyError(err));
      setTechnical(String(err));
      await refreshStatus();
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    setError("");
    try {
      const next = await invoke<ServiceStatus>("service_disconnect");
      setStatus(next);
      setTechnical(JSON.stringify(next, null, 2));
    } catch (err) {
      setError(friendlyError(err));
      setTechnical(String(err));
      await refreshStatus();
    } finally {
      setBusy(false);
    }
  }

  async function reset() {
    setBusy(true);
    setError("");
    try {
      const next = await invoke<ServiceStatus>("service_reset");
      setStatus(next);
      setTechnical(JSON.stringify(next, null, 2));
    } catch (err) {
      setError(friendlyError(err));
      setTechnical(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function repairHelper() {
    setBusy(true);
    setError("");
    try {
      const message = await invoke<string>("service_repair_helper");
      const report = await invoke<unknown>("service_diagnostics");
      setTechnical(`${message}\n\n${JSON.stringify(report, null, 2)}`);
    } catch (err) {
      setError(friendlyError(err));
      setTechnical(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function runDiagnostics() {
    setBusy(true);
    setError("");
    try {
      const report = await invoke<unknown>("service_diagnostics");
      setTechnical(JSON.stringify(report, null, 2));
    } catch (err) {
      setError(friendlyError(err));
      setTechnical(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <section className={`panel vpn ${status.state}`}>
        <div className="brand">PVN</div>
        <div className="status">Status: {mainLabel}</div>
        <button className={`power ${isOn ? "stop" : "go"}`} disabled={isWorking} onClick={isOn ? disconnect : connect}>
          {isOn ? "STOP" : "GO"}
        </button>
        {error && <p className="error">{error}</p>}
        <button className="link" onClick={() => setAdvanced(!advanced)}>
          Advanced
        </button>
        {advanced && (
          <div className="advanced">
            <label>
              API URL
              <input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)} />
            </label>
            <button onClick={refreshStatus}>Refresh status</button>
            <button onClick={runDiagnostics}>Run diagnostics</button>
            <button onClick={repairHelper}>Repair Helper</button>
            <button onClick={reset}>Reset PVN profile</button>
            <pre>{technical || "No diagnostics yet."}</pre>
          </div>
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
