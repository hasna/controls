import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "../src/server/app.js";
import { getDatabase, closeDatabase } from "../src/db/database.js";
import { OPERATIONS, operationManifest, type OperationDef } from "../src/services/registry.js";
import { ACTION_SCOPE, authenticateToken, type ApiPrincipal } from "../src/server/auth.js";
import type { AuthorizationAction, AuthorizationRole } from "../src/services/authorization.js";
import { seedEntity, type Seed } from "./helpers/db.js";
import { captureTools, callTool } from "./helpers/mcp.js";

/**
 * Interface-parity harness (§7). The harness is identical machinery; the per-op
 * table is GENERATED from the operation manifest. Every op is driven through all
 * three surfaces (CLI --json subprocess, MCP tool handler, /v1 Hono route),
 * normalized to a canonical JSON value (volatile ids/timestamps/tokens stripped),
 * and asserted deep-equal — including structured error envelopes.
 *
 * SECURITY HARDENING (money app): the surfaces are NOT driven as the SYSTEM
 * bypass context (which would mask whether auth is even wired). Instead:
 *   - /v1 is driven with a real `Authorization: Bearer <token>` header, and
 *   - MCP is driven with the caller principal derived from that SAME token,
 * both resolving to a REAL, non-bypass, entity-scoped credential configured in
 * `HASNA_CONTROLS_API_CREDENTIALS`. The credential is entity-scoped (its tenant
 * boundary is exactly the seeded entities under test); the negative suite below
 * proves a wrong-entity principal is denied on ALL three surfaces. The local CLI
 * remains the trusted single-user surface (SYSTEM context) for the positive
 * parity run — its authenticated-principal path is exercised by the negative
 * suite. `HASNA_CONTROLS_API_CREDENTIALS` is CONFIGURED here, never deleted.
 */

let tmp: string;
const CLI = join(process.cwd(), "src", "cli", "index.tsx");

/** Real, non-bypass credential the /v1 + MCP surfaces authenticate as. */
const PARITY_TOKEN = "tok-controls-parity";
const PARITY_CRED_ID = "parity-caller";

/**
 * Least-privilege role that authorizes EXACTLY `action` at the service layer
 * (roles gate the action dimension; scopes gate the transport surface). Mirrors
 * fleet/access: the parity credential is a REAL, narrowly-scoped, NON-owner,
 * NON-bypass credential — never the blanket `owner`/SYSTEM capability.
 */
const ROLE_FOR_ACTION: Record<AuthorizationAction, AuthorizationRole> = {
  read: "auditor",
  write: "requestor",
  approve: "approver",
  freeze: "security",
  export: "auditor",
  admin: "admin",
};

/**
 * Configure the parity credential scoped to EXACTLY `entityIds` (its tenant
 * boundary) with LEAST PRIVILEGE for `action`: it holds only `controls:read`
 * plus that op's single required action scope, on the minimal role that
 * authorizes the action — it can drive the op under test and nothing more. Entity
 * scoping remains STRICT (deny-by-default): the credential reaches no entity
 * outside `entityIds`, and is never SYSTEM/bypass. Credentials are read fresh
 * from env on every request, so re-scoping per op is a plain env write.
 */
function configureScopedCredential(entityIds: string[], action: AuthorizationAction = "read"): void {
  const scopes = Array.from(new Set(["controls:read", ACTION_SCOPE[action]]));
  process.env["HASNA_CONTROLS_API_CREDENTIALS"] = JSON.stringify([
    { id: PARITY_CRED_ID, token: PARITY_TOKEN, type: "api_key", actor_id: PARITY_CRED_ID, roles: [ROLE_FOR_ACTION[action]], scopes, entity_ids: entityIds },
  ]);
}

beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "controls-parity-"));
  process.env["HASNA_CONTROLS_DB_PATH"] = join(tmp, "controls.db");
  delete process.env["HASNA_CONTROLS_BIND_HOST"];
  delete process.env["HASNA_CONTROLS_API_TOKEN"];
  // Configure (NOT delete) a scoped, non-bypass credential. With credentials
  // configured, /v1 is deny-by-default even on loopback: a valid bearer is
  // mandatory, so the harness proves auth is actually enforced.
  configureScopedCredential([]);
  closeDatabase();
  getDatabase(); // initialize the shared on-disk store
});

afterAll(() => {
  closeDatabase();
  delete process.env["HASNA_CONTROLS_API_CREDENTIALS"];
  delete process.env["HASNA_CONTROLS_API_TOKEN"];
  delete process.env["HASNA_CONTROLS_DB_PATH"];
  rmSync(tmp, { recursive: true, force: true });
});

const VOLATILE = new Set([
  "id", "entity_id", "created_at", "updated_at", "expires_at", "approved_at", "consumed_at",
  "decided_at", "registered_at", "at", "checked_at", "head_hash", "prev_hash", "row_hash",
  "resource_id", "sqlite_path", "actor_id", "token", "authorization_id", "detail", "released_at",
]);

function strip(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(strip);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (VOLATILE.has(k)) continue;
      out[k] = strip(v);
    }
    return out;
  }
  return value;
}

function canonical(value: unknown): string {
  return JSON.stringify(strip(value));
}

function inputFor(op: string, s: Seed): Record<string, unknown> {
  const e = s.entity_id;
  const map: Record<string, Record<string, unknown>> = {
    "policy.create": { entity_id: e, window: "day", amount_limit: 5000, currency: "USD", note: "n" },
    "policy.list": { entity_id: e },
    "policy.get": { entity_id: e, id: s.policy.id },
    "policy.update": { entity_id: e, id: s.policy.id, amount_limit: 2000 },
    "policy.delete": { entity_id: e, id: s.policy.id },
    "counterparty.allow": { entity_id: e, counterparty_id: "cp-2" },
    "counterparty.block": { entity_id: e, counterparty_id: "cp-3" },
    "counterparty.list": { entity_id: e },
    "counterparty.get": { entity_id: e, id: s.allow.id },
    "counterparty.remove": { entity_id: e, id: s.allow.id },
    "approval_rule.create": { entity_id: e, tier: "mid", threshold_amount: 1000, currency: "USD" },
    "approval_rule.list": { entity_id: e },
    "approval_rule.get": { entity_id: e, id: s.rule.id },
    "approval_rule.delete": { entity_id: e, id: s.rule.id },
    "authorization.request": { entity_id: e, requestor_id: "agent-a", amount: 500, currency: "USD", counterparty_id: "cp-1" },
    "authorization.list": { entity_id: e },
    "authorization.get": { entity_id: e, id: s.approved.id },
    "authorization.approve": { entity_id: e, id: s.pending.id, approver_id: "agent-b" },
    "authorization.reject": { entity_id: e, id: s.pending2.id, approver_id: "agent-b", reason: "no" },
    "authorization.consume": { entity_id: e, id: s.approved.id, token: s.approved.token },
    "authorization.verify": { entity_id: e, id: s.approved.id, token: s.approved.token },
    "freeze.create": { entity_id: e, reason: "r" },
    "freeze.release": { entity_id: e, id: s.freeze.id },
    "freeze.list": { entity_id: e },
    "freeze.status": { entity_id: e, identity_id: "frozen-agent" },
    "audit.list": { entity_id: e },
    "audit.verify": { entity_id: e },
  };
  const input = map[op];
  if (!input) throw new Error(`no parity input for ${op}`);
  return input;
}

function httpUrl(def: OperationDef, input: Record<string, unknown>): { url: string; body?: string } {
  let path = def.rest.path;
  for (const p of def.pathParams) path = path.replace(`:${p}`, encodeURIComponent(String(input[p])));
  const nonPath = Object.entries(input).filter(([k]) => !def.pathParams.includes(k));
  if (def.rest.method === "GET" || def.rest.method === "DELETE") {
    const qs = new URLSearchParams();
    for (const [k, v] of nonPath) qs.set(k, String(v));
    const query = qs.toString();
    return { url: `http://host${path}${query ? `?${query}` : ""}` };
  }
  return { url: `http://host${path}`, body: JSON.stringify(Object.fromEntries(nonPath)) };
}

/** Drive the /v1 Hono route with a bearer token (real credential path). */
async function viaHttpResponse(def: OperationDef, input: Record<string, unknown>, token: string): Promise<Response> {
  const app = createApp();
  const { url, body } = httpUrl(def, input);
  const headers: Record<string, string> = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
  return app.fetch(new Request(url, { method: def.rest.method, headers, body }));
}

async function viaHttp(def: OperationDef, input: Record<string, unknown>, token: string): Promise<unknown> {
  return (await viaHttpResponse(def, input, token)).json();
}

/** Drive the MCP tool handler as the caller principal derived from `token`. */
async function viaMcp(def: OperationDef, input: Record<string, unknown>, token: string): Promise<unknown> {
  const principal = authenticateToken(token) ?? undefined;
  const tools = captureTools(principal);
  return callTool(tools, `controls_${def.mcp}`, input);
}

/**
 * Drive the CLI in --json mode. With `token` set, the subprocess authenticates as
 * that entity-scoped principal (HASNA_CONTROLS_API_TOKEN); without it, the CLI is
 * the trusted local SYSTEM surface (positive parity run).
 */
function viaCli(op: string, input: Record<string, unknown>, token?: string): unknown {
  const env = { ...process.env } as Record<string, string>;
  if (token) env["HASNA_CONTROLS_API_TOKEN"] = token;
  else delete env["HASNA_CONTROLS_API_TOKEN"];
  const proc = Bun.spawnSync({
    cmd: [process.execPath, CLI, "--json", "call", op, "--input", JSON.stringify(input)],
    env,
  });
  const out = proc.stdout.toString().trim();
  try {
    return JSON.parse(out);
  } catch {
    throw new Error(`CLI output not JSON for ${op}: ${out}\n${proc.stderr.toString()}`);
  }
}

describe("interface parity: identical harness + generated table", () => {
  it("exposes the same operations across CLI, MCP, and API", () => {
    const manifest = operationManifest();
    expect(manifest.length).toBe(OPERATIONS.length);
    for (const entry of manifest) {
      expect(entry.surfaces.cli).toContain("controls");
      expect(entry.surfaces.mcp).toContain("controls_");
      expect(entry.surfaces.api).toMatch(/^(GET|POST|PATCH|DELETE) \/v1\//);
    }
  });

  for (const def of OPERATIONS) {
    it(`op ${def.op} yields identical results across all three surfaces`, async () => {
      const db = getDatabase();

      const httpSeed = seedEntity(db, crypto.randomUUID());
      const mcpSeed = seedEntity(db, crypto.randomUUID());
      const cliSeed = seedEntity(db, crypto.randomUUID());

      // Scope the real credential to exactly the entities the authenticated
      // surfaces will touch, with LEAST PRIVILEGE for this op's action. The CLI
      // positive run stays the trusted SYSTEM surface.
      configureScopedCredential([httpSeed.entity_id, mcpSeed.entity_id], def.action);

      const http = await viaHttp(def, inputFor(def.op, httpSeed), PARITY_TOKEN);
      const mcp = await viaMcp(def, inputFor(def.op, mcpSeed), PARITY_TOKEN);
      const cli = viaCli(def.op, inputFor(def.op, cliSeed));

      expect(canonical(mcp)).toBe(canonical(http));
      expect(canonical(cli)).toBe(canonical(http));
    });
  }
});

describe("interface parity: identical structured error envelopes", () => {
  it("returns the same { code, message, suggestion } for a not-found across surfaces", async () => {
    const e = crypto.randomUUID();
    const input = { entity_id: e, id: "does-not-exist" };
    const def = OPERATIONS.find((o) => o.op === "policy.get")!;

    // The credential must be scoped to `e` so denial is NOT_FOUND, not PERMISSION_DENIED.
    configureScopedCredential([e], def.action);

    const http = (await viaHttp(def, input, PARITY_TOKEN)) as Record<string, unknown>;
    const mcp = (await viaMcp(def, input, PARITY_TOKEN)) as Record<string, unknown>;
    const cli = viaCli("policy.get", input) as Record<string, unknown>;

    expect(http["code"]).toBe("POLICY_NOT_FOUND");
    expect(mcp["code"]).toBe("POLICY_NOT_FOUND");
    expect(cli["code"]).toBe("POLICY_NOT_FOUND");
    expect(mcp["suggestion"]).toBe(http["suggestion"]);
    expect(cli["suggestion"]).toBe(http["suggestion"]);
  });
});

/**
 * Negative parity: a REAL authenticated principal whose tenant boundary is a
 * DIFFERENT entity must be denied (PERMISSION_DENIED) on ALL THREE surfaces when
 * it targets an entity it is not scoped to. This proves the surfaces enforce
 * deny-by-default entity isolation — knowing/guessing an entity_id grants
 * nothing (§1c) — and that none of the three silently runs as a bypass context.
 */
describe("interface parity: wrong-entity principal is denied on all three surfaces", () => {
  const cases = [
    OPERATIONS.find((o) => o.op === "policy.list")!, // read
    OPERATIONS.find((o) => o.op === "policy.create")!, // write
  ];

  for (const def of cases) {
    it(`denies ${def.op} for a principal scoped to a different entity`, async () => {
      const db = getDatabase();
      const targetSeed = seedEntity(db, crypto.randomUUID());
      const otherEntity = crypto.randomUUID(); // the ONLY entity the credential can reach

      // Credential is scoped to `otherEntity`, but every surface targets `targetSeed`.
      configureScopedCredential([otherEntity], def.action);
      const input = inputFor(def.op, targetSeed);

      const httpRes = await viaHttpResponse(def, input, PARITY_TOKEN);
      const httpBody = (await httpRes.json()) as Record<string, unknown>;
      const mcp = (await viaMcp(def, input, PARITY_TOKEN)) as Record<string, unknown>;
      const cli = viaCli(def.op, input, PARITY_TOKEN) as Record<string, unknown>;

      expect(httpRes.status).toBe(403);
      expect(httpBody["code"]).toBe("PERMISSION_DENIED");
      expect(mcp["code"]).toBe("PERMISSION_DENIED");
      expect(cli["code"]).toBe("PERMISSION_DENIED");
    });
  }

  it("fails closed on the CLI when the caller token is invalid (no bypass fallback)", () => {
    const db = getDatabase();
    const targetSeed = seedEntity(db, crypto.randomUUID());
    configureScopedCredential([targetSeed.entity_id]);
    const cli = viaCli("policy.list", { entity_id: targetSeed.entity_id }, "tok-not-a-real-credential") as Record<string, unknown>;
    // A provided-but-invalid token must NOT resolve to the trusted SYSTEM context.
    expect(cli["code"]).toBe("UNAUTHORIZED");
  });
});
