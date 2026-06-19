import { copyFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

const source = resolve("../windows-service/target/release/pvn-v2-service.exe");
const destDir = resolve("src-tauri/resources");
const dest = resolve(destDir, "pvn-v2-service.exe");

mkdirSync(destDir, { recursive: true });
copyFileSync(source, dest);
console.log(`Copied helper service to ${dest}`);
