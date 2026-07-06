import { afterEach, describe, expect, it } from "bun:test";
import { OPERATIONS } from "../src/services/registry.js";
import { captureTools, callTool } from "./helpers/mcp.js";
import { handleMcpHttpRequest } from "../src/mcp/http.js";
import { createApp } from "../src/server/app.js";

function resetEnv() {
  delete process.env["HASNA_CONTROLS_STORAGE_MODE"];
  delete process.env["HASNA_CONTROLS_DATABASE_URL"];
  delete process.env["HASNA_CONTROLS_API_CREDENTIALS"];
  delete process.env["HASNA_CONTROLS_MCP_AUTH"];
  process.env["HASNA_CONTROLS_DB_PATH"] = ":memory:";
}

afterEach(resetEnv);

describe("mcp-safety: mutation gating", () => {
  it("every mutating domain op requires a write-class action (never read)", () => {
    for (const op of OPERATIONS) {
      if (op.mutates) expect(["write", "approve", "freeze", "admin"]).toContain(op.action);
    }
  });

  it("destructive (delete/admin) tools are absent from the minimal profile", () => {
    resetEnv();
    const minimal = captureTools(undefined, "minimal");
    const destructive = OPERATIONS.filter((o) => o.action === "admin" && o.mutates).map((o) => `controls_${o.mcp}`);
    for (const name of destructive) expect(minimal.names).not.toContain(name);
  });

  it("registers the four standard tools + four storage tools regardless of profile", () => {
    resetEnv();
    const minimal = captureTools(undefined, "minimal");
    for (const t of ["register_agent", "heartbeat", "set_focus", "send_feedback"]) expect(minimal.names).toContain(t);
    for (const t of ["controls_storage_status", "controls_storage_push", "controls_storage_pull", "controls_storage_sync"]) {
      expect(minimal.names).toContain(t);
    }
  });
});

describe("mcp-safety: storage_status never leaks a DSN (§4.6)", () => {
  it("omits any substring of the configured DATABASE_URL", async () => {
    resetEnv();
    const secret = "postgres://controls:SUPERSECRETPW@db.internal:5432/controls?sslmode=verify-full";
    process.env["HASNA_CONTROLS_STORAGE_MODE"] = "cloud";
    process.env["HASNA_CONTROLS_DATABASE_URL"] = secret;
    const tools = captureTools();
    const status = (await callTool(tools, "controls_storage_status")) as Record<string, unknown>;
    const serialized = JSON.stringify(status);
    expect(serialized).not.toContain("SUPERSECRETPW");
    expect(serialized).not.toContain(secret);
    expect(status).toHaveProperty("dsn_present", true);
    expect(status).not.toHaveProperty("dsn");
  });
});

describe("mcp-safety: storage push/pull gated by storage:admin", () => {
  it("denies a principal without storage:admin", async () => {
    resetEnv();
    const principal = { credential_id: "c", credential_type: "api_key" as const, actor_id: "c", roles: ["requestor" as const], scopes: ["controls:write" as const] };
    const tools = captureTools(principal);
    const result = (await callTool(tools, "controls_storage_pull")) as { code?: string };
    expect(result.code).toBe("PERMISSION_DENIED");
  });

  it("allows a principal with storage:admin and excludes audit tables", async () => {
    resetEnv();
    const principal = { credential_id: "c", credential_type: "api_key" as const, actor_id: "c", roles: ["admin" as const], scopes: ["storage:admin" as const] };
    const tools = captureTools(principal);
    const result = (await callTool(tools, "controls_storage_push", { tables: ["policies", "controls_audit"] })) as { tables: string[]; excluded_audit_tables: string[] };
    expect(result.tables).toContain("policies");
    expect(result.tables).not.toContain("controls_audit");
    expect(result.excluded_audit_tables).toContain("controls_audit");
  });
});

describe("mcp-safety: MCP domain tools enforce scopes like /v1 (§5.1a)", () => {
  it("denies a scope-limited principal the same write op /v1 denies", async () => {
    resetEnv();
    // role defaults to `integration` (grants write at the role/service layer) but
    // scopes are read-only. /v1 denies via authorizeScopeAndEntity; MCP must too.
    const principal = {
      credential_id: "c", credential_type: "api_key" as const, actor_id: "c",
      roles: ["integration" as const], scopes: ["controls:read" as const],
    };
    const tools = captureTools(principal);
    const result = (await callTool(tools, "controls_policy_create", {
      entity_id: crypto.randomUUID(), window: "day", amount_limit: 1000, currency: "USD",
    })) as { code?: string };
    expect(result.code).toBe("PERMISSION_DENIED");
  });

  it("/v1 denies the identical scope-limited credential (parity confirmation)", async () => {
    resetEnv();
    process.env["HASNA_CONTROLS_API_CREDENTIALS"] = JSON.stringify([
      { id: "c", token: "tok", roles: ["integration"], scopes: ["controls:read"] },
    ]);
    const app = createApp();
    const res = await app.fetch(
      new Request(`http://host/v1/entities/${crypto.randomUUID()}/policies`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer tok" },
        body: JSON.stringify({ window: "day", amount_limit: 1000, currency: "USD" }),
      }),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { code?: string }).code).toBe("PERMISSION_DENIED");
  });

  it("allows a principal whose scope AND entity access permit the op", async () => {
    resetEnv();
    const entityId = crypto.randomUUID();
    const principal = {
      credential_id: "c", credential_type: "api_key" as const, actor_id: "c",
      roles: ["requestor" as const], scopes: ["controls:write" as const],
      entity_ids: [entityId],
    };
    const tools = captureTools(principal);
    const result = (await callTool(tools, "controls_policy_create", {
      entity_id: entityId, window: "day", amount_limit: 1000, currency: "USD",
    })) as { code?: string; id?: string };
    expect(result.code).toBeUndefined();
    expect(typeof result.id).toBe("string");
  });

  it("denies an UNSCOPED non-bypass principal (strict deny-by-default, §1c)", async () => {
    resetEnv();
    // Scope permits the action, but the principal has NO entity/org set: knowing
    // an entity_id is not a bearer capability, so it must reach NO entity.
    const principal = {
      credential_id: "c", credential_type: "api_key" as const, actor_id: "c",
      roles: ["requestor" as const], scopes: ["controls:write" as const],
    };
    const tools = captureTools(principal);
    const result = (await callTool(tools, "controls_policy_create", {
      entity_id: crypto.randomUUID(), window: "day", amount_limit: 1000, currency: "USD",
    })) as { code?: string };
    expect(result.code).toBe("PERMISSION_DENIED");
  });
});

describe("mcp-safety: /mcp bearer auth (§5.1a)", () => {
  it("rejects an unauthenticated /mcp request with 401", async () => {
    resetEnv();
    const res = await handleMcpHttpRequest(new Request("http://127.0.0.1:8886/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }), { host: "127.0.0.1" });
    expect(res.status).toBe(401);
  });

  it("allows a request with a valid bearer token", async () => {
    resetEnv();
    process.env["HASNA_CONTROLS_API_CREDENTIALS"] = JSON.stringify([{ id: "c", token: "tok", roles: ["owner"] }]);
    const res = await handleMcpHttpRequest(
      new Request("http://127.0.0.1:8886/mcp", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: "Bearer tok" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      }),
      { host: "127.0.0.1" },
    );
    expect(res.status).toBe(200);
  });
});
