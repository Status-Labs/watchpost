// Next.js calls this once per server start. Only local mode needs it: it
// migrates the PGlite database and starts the sync timers.
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs" && process.env.WATCHPOST_MODE === "local") {
    const { startLocal } = await import("./local/start");
    await startLocal();
  }
}
