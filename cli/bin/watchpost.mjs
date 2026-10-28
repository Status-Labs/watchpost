#!/usr/bin/env node
import { spawn } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { runBridge } from "../lib/bridge.mjs";

// Watchpost on your own machine: the web app, the MCP server and a full local
// copy of OSV and CISA KEV. Checks run offline.

const DEFAULT_PORT = 4141;
const START_TIMEOUT_MS = 60_000;
const here = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.join(here, "..");
const { version } = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8"));

const HELP = `Watchpost ${version}: CVE alerts for your stack, checked on your machine.

Usage:
  watchpost [start]   Start the app at http://127.0.0.1:${DEFAULT_PORT} and open it
  watchpost mcp       MCP server for AI apps (stdio); starts the app if needed
  watchpost stop      Stop the app

Options:
  --port <n>          Port (default ${DEFAULT_PORT})
  --no-open           Don't open the browser
  --version, --help

Data folder: ${dataDir()}
`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    port: { type: "string" },
    "no-open": { type: "boolean" },
    version: { type: "boolean" },
    help: { type: "boolean", short: "h" },
  },
});
const port = Number(values.port ?? DEFAULT_PORT);
if (!Number.isInteger(port) || port < 1 || port > 65_535) fail(`Invalid port: ${values.port}`);
const command = positionals[0] ?? "start";
const baseUrl = `http://127.0.0.1:${port}`;

if (values.version) console.log(version);
else if (values.help) console.log(HELP);
else if (command === "start") await start();
else if (command === "mcp") await mcp();
else if (command === "stop") stop();
else fail(`Unknown command: ${command}\n\n${HELP}`);

function dataDir() {
  if (process.env.WATCHPOST_DATA_DIR) return process.env.WATCHPOST_DATA_DIR;
  if (process.platform === "darwin") return path.join(homedir(), "Library", "Application Support", "Watchpost");
  if (process.platform === "win32") {
    return path.join(process.env.LOCALAPPDATA ?? path.join(homedir(), "AppData", "Local"), "Watchpost");
  }
  return path.join(process.env.XDG_DATA_HOME ?? path.join(homedir(), ".local", "share"), "watchpost");
}

function pidFile() {
  return path.join(dataDir(), "server.json");
}

// The running app, if any: from the pid file, confirmed by asking it.
async function running() {
  let saved;
  try {
    saved = JSON.parse(readFileSync(pidFile(), "utf8"));
    process.kill(saved.pid, 0);
  } catch {
    return null;
  }
  return (await isWatchpost(`http://127.0.0.1:${saved.port}`)) ? saved : null;
}

async function isWatchpost(url) {
  try {
    const res = await fetch(`${url}/api/status`, { signal: AbortSignal.timeout(3_000) });
    return (await res.json()).app === "watchpost";
  } catch {
    return false;
  }
}

async function start() {
  const existing = await running();
  if (existing) {
    console.log(`Watchpost is already running at http://127.0.0.1:${existing.port}`);
    if (!values["no-open"]) openBrowser(`http://127.0.0.1:${existing.port}`);
    return;
  }

  mkdirSync(dataDir(), { recursive: true });
  const { startServer } = await import("../lib/server.mjs");
  try {
    await startServer({ appDir: path.join(packageDir, "app"), port, dataDir: dataDir() });
  } catch (error) {
    if (error?.code === "EADDRINUSE") fail(`Port ${port} is in use. Try --port <another port>.`);
    throw error;
  }
  writeFileSync(pidFile(), JSON.stringify({ pid: process.pid, port }));
  const cleanup = () => rmSync(pidFile(), { force: true });
  process.on("exit", cleanup);
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => process.exit(0));

  console.log(`Watchpost is running at ${baseUrl}`);
  console.log(`MCP endpoint: ${baseUrl}/api/mcp`);
  console.log("The first run downloads about 300 MB of vulnerability data (about 1.5 GB on disk). Press Ctrl+C to stop.");
  if (!values["no-open"]) openBrowser(baseUrl);
}

async function mcp() {
  let app = await running();
  if (!app) {
    // Start the app in the background; it keeps running for the next session.
    mkdirSync(dataDir(), { recursive: true });
    const log = openSync(path.join(dataDir(), "server.log"), "a");
    spawn(process.execPath, [fileURLToPath(import.meta.url), "start", "--no-open", "--port", String(port)], {
      detached: true,
      stdio: ["ignore", log, log],
    }).unref();
    closeSync(log);

    const deadline = Date.now() + START_TIMEOUT_MS;
    while (!app && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      app = await running();
    }
    if (!app) fail(`Watchpost didn't start. See ${path.join(dataDir(), "server.log")}`);
  }
  await runBridge(`http://127.0.0.1:${app.port}/api/mcp`);
}

function stop() {
  try {
    const { pid } = JSON.parse(readFileSync(pidFile(), "utf8"));
    process.kill(pid, "SIGTERM");
    console.log("Stopped Watchpost.");
  } catch {
    console.log("Watchpost isn't running.");
  }
}

function openBrowser(url) {
  const [cmd, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["cmd", ["/c", "start", "", url]]
        : ["xdg-open", [url]];
  spawn(cmd, args, { stdio: "ignore", detached: true }).on("error", () => {}).unref();
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
