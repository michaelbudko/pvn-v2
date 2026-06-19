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

type LoginResponse = {
  token: string;
};

function friendlyError(error: unknown): string {
  const text = String(error);
  if (text.includes("401") || text.toLowerCase().includes("unauthorized")) {
    return "Email or password is incorrect.";
  }
  if (text.toLowerCase().includes("wireguard")) {
    return "WireGuard is not ready. Reinstall PVN or restart Windows.";
  }
  if (text.toLowerCase().includes("public_ip") || text.toLowerCase().includes("blank")) {
    return "VPN profile is broken. Open Advanced and reset PVN.";
  }
  if (text.toLowerCase().includes("connection") || text.toLowerCase().includes("failed to connect")) {
    return "Could not reach VPN server. Check your internet connection.";
  }
  return "Something went wrong. Try again or send diagnostics to Mike.";
}

function App() {
  const [apiUrl, setApiUrl] = useState(() => localStorage.getItem("pvn-v2-api-url") || DEFAULT_API_URL);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(() => localStorage.getItem("pvn-v2-token") || "");
  const [status, setStatus] = useState<ServiceStatus>({ state: "off", last_error: "", last_verification: "" });
  const [busy, setBusy] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [technical, setTechnical] = useState("");
  const [error, setError] = useState("");

  const loggedIn = token.length > 0;
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
      setTechnical(String(err));
    }
  }

  useEffect(() => {
    if (!loggedIn) return;
    refreshStatus();
    const timer = window.setInterval(refreshStatus, 2500);
    return () => window.clearInterval(timer);
  }, [loggedIn]);

  async function login() {
    setBusy(true);
    setError("");
    setTechnical("");
    try {
      localStorage.setItem("pvn-v2-api-url", apiUrl);
      const result = await invoke<LoginResponse>("login", { apiUrl, email, password });
      localStorage.setItem("pvn-v2-token", result.token);
      setToken(result.token);
      setPassword("");
      await refreshStatus();
    } catch (err) {
      setError(friendlyError(err));
      setTechnical(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function connect() {
    setBusy(true);
    setError("");
    try {
      const next = await invoke<ServiceStatus>("service_connect", { apiUrl, backendToken: token });
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

  function logout() {
    localStorage.removeItem("pvn-v2-token");
    setToken("");
    setStatus({ state: "off", last_error: "", last_verification: "" });
  }

  if (!loggedIn) {
    return (
      <main className="shell">
        <section className="panel login">
          <div className="brand">PVN</div>
          <label>
            Email
            <input value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" />
          </label>
          <label>
            Password
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              type="password"
              autoComplete="current-password"
              onKeyDown={(event) => {
                if (event.key === "Enter") login();
              }}
            />
          </label>
          <button className="primary" disabled={busy || !email || !password} onClick={login}>
            Log in
          </button>
          <button className="link" onClick={() => setAdvanced(!advanced)}>
            Advanced
          </button>
          {advanced && (
            <label>
              API URL
              <input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)} />
            </label>
          )}
          {error && <p className="error">{error}</p>}
          {advanced && technical && <pre>{technical}</pre>}
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <section className={`panel vpn ${status.state}`}>
        <button className="logout" onClick={logout}>
          Logout
        </button>
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
            <button onClick={reset}>Reset PVN profile</button>
            <pre>{technical || "No diagnostics yet."}</pre>
          </div>
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
