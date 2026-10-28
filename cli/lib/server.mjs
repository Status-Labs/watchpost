import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import path from "node:path";

// Runs the bundled Next.js app on 127.0.0.1. Every request passes two checks
// first, because any website the user visits can make their browser send
// requests to localhost:
// - The Host header must be localhost or 127.0.0.1. A site that points its own
//   domain at 127.0.0.1 (DNS rebinding) sends its own domain, and is refused.
// - Browsers mark requests from other sites with Sec-Fetch-Site: cross-site.
//   Those are refused too, so a site can't use the API or MCP endpoint.

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function allowedRequest(headers, port) {
  const host = String(headers.host ?? "").toLowerCase();
  const [name, hostPort] = host.startsWith("[") ? [host.slice(0, host.indexOf("]") + 1), host.split("]:")[1]] : host.split(":");
  if (!LOCAL_HOSTS.has(name) || (hostPort ?? "80") !== String(port)) return false;
  return headers["sec-fetch-site"] !== "cross-site";
}

export async function startServer({ appDir, port, dataDir }) {
  const config = JSON.parse(readFileSync(path.join(appDir, ".next", "required-server-files.json"), "utf8")).config;

  Object.assign(process.env, {
    NODE_ENV: "production",
    WATCHPOST_MODE: "local",
    WATCHPOST_DATA_DIR: dataDir,
    SITE_URL: `http://127.0.0.1:${port}`,
    // Only the app's own scheduler calls the sync routes; a fresh secret each run.
    CRON_SECRET: randomBytes(32).toString("base64url"),
    __NEXT_PRIVATE_STANDALONE_CONFIG: JSON.stringify(config),
  });
  // Migrations and static files are read relative to the app folder.
  process.chdir(appDir);

  // Claim the port before opening the database, so a second copy fails here
  // instead of opening the same database files.
  let handle = null;
  const server = http.createServer((req, res) => {
    if (!allowedRequest(req.headers, port)) {
      res.writeHead(403, { "Content-Type": "text/plain" }).end("Forbidden\n");
      return;
    }
    if (!handle) {
      res.writeHead(503, { "Content-Type": "text/plain", "Retry-After": "1" }).end("Starting\n");
      return;
    }
    handle(req, res);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });

  const require = createRequire(path.join(appDir, "server.js"));
  const next = require("next");
  const app = next({ dev: false, dir: appDir, conf: config, hostname: "127.0.0.1", port });
  await app.prepare();
  handle = app.getRequestHandler();
  return server;
}
