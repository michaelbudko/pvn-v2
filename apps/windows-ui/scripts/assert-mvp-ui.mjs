import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const appSource = readFileSync(join(here, "..", "src", "main.tsx"), "utf8");
const tauriSource = readFileSync(join(here, "..", "src-tauri", "src", "main.rs"), "utf8");

const forbidden = [
  "Email or password is incorrect",
  "autoComplete=\"email\"",
  "autoComplete=\"current-password\"",
  "pvn-v2-token",
  "fn login",
  "/api/auth/login",
];

for (const value of forbidden) {
  if (appSource.includes(value) || tauriSource.includes(value)) {
    throw new Error(`MVP no-login UI contains forbidden login flow text: ${value}`);
  }
}

for (const required of ["GO", "STOP", "Advanced", "service_connect"]) {
  if (!appSource.includes(required)) {
    throw new Error(`MVP no-login UI is missing required main-screen behavior: ${required}`);
  }
}

console.log("MVP no-login UI assertions passed.");
