import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { authenticateToken, authorizeScopeAndEntity } from "../src/server/auth.js";
import { createApp } from "../src/server/app.js";

const CREDS = [
  { id: "reader", token: "tok-reader", roles: ["auditor"], entity_ids: ["E1"] },
  { id: "writer", token: "tok-writer", roles: ["requestor"], entity_ids: ["E1"] },
  { id: "approver", token: "tok-approver", roles: ["approver"], entity_ids: ["E1"] },
  { id: "expired", token: "tok-expired", roles: ["owner"], expires_at: "2000-01-01T00:00:00Z" },
  { id: "revoked", token: "tok-revoked", roles: ["owner"], revoked: true },
];

let app: ReturnType<typeof createApp>;

beforeAll(() => {
  process.env["HASNA_CONTROLS_DB_PATH"] = ":memory:";
  process.env["HASNA_CONTROLS_BIND_HOST"] = "0.0.0.0"; // force auth required
  process.env["HASNA_CONTROLS_API_CREDENTIALS"] = JSON.stringify(CREDS);
  app = createApp();
});

afterAll(() => {
  delete process.env["HASNA_CONTROLS_BIND_HOST"];
  delete process.env["HASNA_CONTROLS_API_CREDENTIALS"];
});

function req(method: string, path: string, token?: string, body?: unknown): Request {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return new Request(`http://host${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
}

describe("auth: credential stack", () => {
  it("authenticates a valid token to a principal with scopes", () => {
    const p = authenticateToken("tok-writer");
    expect(p?.credential_id).toBe("writer");
    expect(p?.scopes).toContain("controls:write");
  });

  it("timing-safe compare rejects a wrong token (no match)", () => {
    expect(authenticateToken("nope")).toBeNull();
    expect(authenticateToken("")).toBeNull();
  });

  it("honors expiry", () => {
    expect(authenticateToken("tok-expired")).toBeNull();
  });

  it("honors revocation", () => {
    expect(authenticateToken("tok-revoked")).toBeNull();
  });

  it("enforces scope in authorizeScopeAndEntity", () => {
    const p = authenticateToken("tok-reader")!;
    expect(authorizeScopeAndEntity(p, "controls:read", "E1").allowed).toBe(true);
    expect(authorizeScopeAndEntity(p, "controls:write", "E1").allowed).toBe(false);
  });

  it("enforces entity scoping (cross-entity denied)", () => {
    const p = authenticateToken("tok-reader")!;
    expect(authorizeScopeAndEntity(p, "controls:read", "E1").allowed).toBe(true);
    expect(authorizeScopeAndEntity(p, "controls:read", "E2").allowed).toBe(false);
  });
});

describe("auth: /v1 deny-by-default over Hono", () => {
  it("rejects an unauthenticated request with 401 when auth is required", async () => {
    const res = await app.fetch(req("GET", "/v1/entities/E1/policies"));
    expect(res.status).toBe(401);
  });

  it("allows a reader to list policies for its entity", async () => {
    const res = await app.fetch(req("GET", "/v1/entities/E1/policies", "tok-reader"));
    expect(res.status).toBe(200);
  });

  it("denies a reader from creating a policy (missing write scope)", async () => {
    const res = await app.fetch(req("POST", "/v1/entities/E1/policies", "tok-reader", { window: "day", amount_limit: 100, currency: "USD" }));
    expect(res.status).toBe(403);
  });

  it("allows a writer to create a policy for its entity", async () => {
    const res = await app.fetch(req("POST", "/v1/entities/E1/policies", "tok-writer", { window: "day", amount_limit: 100, currency: "USD" }));
    expect(res.status).toBe(200);
  });

  it("denies a writer creating a policy for an entity it is not scoped to", async () => {
    const res = await app.fetch(req("POST", "/v1/entities/E2/policies", "tok-writer", { window: "day", amount_limit: 100, currency: "USD" }));
    expect(res.status).toBe(403);
  });

  it("keeps system endpoints unauthenticated", async () => {
    const health = await app.fetch(req("GET", "/health"));
    expect(health.status).toBe(200);
    const body = (await health.json()) as { status: string; version: string; mode: string };
    expect(body.status).toBe("ok");
    expect(body).toHaveProperty("version");
    expect(body).toHaveProperty("mode");
  });
});
