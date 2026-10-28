import { homedir } from "node:os";
import path from "node:path";

// Local mode runs the whole app on the user's machine, with PGlite instead of
// a Postgres server. The CLI sets WATCHPOST_MODE=local; hosted deploys never do.
export function isLocalMode(): boolean {
  return process.env.WATCHPOST_MODE === "local";
}

// Where the local database and downloads live.
export function dataDir(): string {
  if (process.env.WATCHPOST_DATA_DIR) return process.env.WATCHPOST_DATA_DIR;
  if (process.platform === "darwin") return path.join(homedir(), "Library", "Application Support", "Watchpost");
  if (process.platform === "win32") {
    return path.join(process.env.LOCALAPPDATA ?? path.join(homedir(), "AppData", "Local"), "Watchpost");
  }
  return path.join(process.env.XDG_DATA_HOME ?? path.join(homedir(), ".local", "share"), "watchpost");
}
