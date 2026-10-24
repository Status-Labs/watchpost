// Runs in every test process. Tests must never reach a real database or outside API.

const url = process.env.DATABASE_URL;
if (url) {
  const host = new URL(url).hostname;
  if (!["localhost", "127.0.0.1", "::1"].includes(host)) {
    throw new Error(`Refusing to run tests against a non-local database (${host}).`);
  }
}

// Any test that forgets to inject a fake fetch fails loudly instead of calling out.
globalThis.fetch = (async (input: RequestInfo | URL) => {
  throw new Error(`Tests must not make network requests (${String(input)}). Inject a fake fetch.`);
}) as typeof fetch;
