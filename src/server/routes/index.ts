// The /v1 resource routers for @hasna/controls are generated from the shared
// operation registry (src/services/registry.ts) in src/server/app.ts, so CLI,
// MCP, and API stay in lockstep (interface parity, §7). This module re-exports
// the registry view of the REST surface for tooling that expects a routes entry.
import { OPERATIONS } from "../../services/registry.js";

export interface RouteView {
  method: string;
  path: string;
  op: string;
}

export function listRoutes(): RouteView[] {
  return OPERATIONS.map((o) => ({ method: o.rest.method, path: o.rest.path, op: o.op }));
}
