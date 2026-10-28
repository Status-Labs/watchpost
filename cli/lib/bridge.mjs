import { createInterface } from "node:readline";

// Connects an AI app that speaks MCP over stdio to the local app's HTTP MCP
// endpoint. One JSON-RPC message per line in each direction. stdout carries
// only protocol messages; anything for people goes to stderr.

const TIMEOUT_MS = 120_000;

export async function runBridge(endpoint) {
  let session;
  let protocolVersion;
  const pending = new Set();

  const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
  const fail = (id, message) => {
    if (id !== undefined && id !== null) send({ jsonrpc: "2.0", id, error: { code: -32000, message } });
  };

  async function forward(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          ...(session ? { "Mcp-Session-Id": session } : {}),
          ...(protocolVersion ? { "Mcp-Protocol-Version": protocolVersion } : {}),
        },
        body: JSON.stringify(message),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      session = res.headers.get("mcp-session-id") ?? session;
      if (res.status === 202 || res.status === 204) return;

      const type = res.headers.get("content-type") ?? "";
      const replies = type.includes("text/event-stream") ? parseEvents(await res.text()) : [await res.json()];
      for (const reply of replies.flat()) {
        if (message.method === "initialize" && reply?.result?.protocolVersion) protocolVersion = reply.result.protocolVersion;
        send(reply);
      }
    } catch (error) {
      fail(message?.id, `Watchpost isn't reachable: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    const task = forward(line).finally(() => pending.delete(task));
    pending.add(task);
  }
  await Promise.all(pending);
}

// The JSON payloads of a server-sent event stream.
export function parseEvents(text) {
  const messages = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).replace(/^ /, ""))
      .join("\n");
    if (!data) continue;
    try {
      messages.push(JSON.parse(data));
    } catch {
      // Not a JSON-RPC message; skip it.
    }
  }
  return messages;
}
