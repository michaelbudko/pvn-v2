import { copyFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

const source = resolve("../windows-service/target/release/pvn-v2-service.exe");
const destDir = resolve("src-tauri/resources");
const dest = resolve(destDir, "pvn-v2-service.exe");
const payload = resolve(destDir, "pvn-v2-service-payload.exe");

mkdirSync(destDir, { recursive: true });
copyFileSync(source, dest);
copyFileSync(source, payload);
console.log(`Copied helper service to ${dest}`);
console.log(`Copied helper service payload to ${payload}`);
