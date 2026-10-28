import { describe, expect, it } from "vitest";
import { parseEvents } from "./bridge.mjs";

describe("parseEvents", () => {
  it("reads JSON-RPC messages from a server-sent event stream", () => {
    const stream = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\nevent: message\r\ndata: {"jsonrpc":"2.0",\r\ndata: "id":2,"result":{}}\r\n\r\n';
    expect(parseEvents(stream)).toEqual([
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: 2, result: {} },
    ]);
  });

  it("skips comments and data that isn't JSON", () => {
    expect(parseEvents(": keep-alive\n\ndata: hello\n\n")).toEqual([]);
  });
});
