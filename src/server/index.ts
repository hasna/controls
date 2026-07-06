#!/usr/bin/env bun
import { resolveStorageMode } from "../config.js";
import { createApp } from "./app.js";
import { isApiAuthConfigured } from "./auth.js";
import { assertServeSafe, authRequired, getBindHost, getPort } from "./runtime.js";

export { createApp } from "./app.js";

function main(): void {
  // Fail-closed: refuse to serve open on a non-loopback / cloud bind (§6.3).
  assertServeSafe(isApiAuthConfigured());

  const app = createApp();
  const port = getPort();
  const hostname = getBindHost();

  Bun.serve({ port, hostname, fetch: app.fetch });

  console.log(`@hasna/controls serve listening on http://${hostname}:${port} (mode=${resolveStorageMode()})`);
  console.log(`API auth ${authRequired() ? "REQUIRED" : isApiAuthConfigured() ? "enabled" : "open (loopback + local mode only)"}`);
}

if (import.meta.main) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
