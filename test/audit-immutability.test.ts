import { describe, expect, it } from "bun:test";
import { memoryDb, SYS } from "./helpers/db.js";
import { createPolicy } from "../src/services/policies.js";
import { listAuditEvents, recordAuditEvent, verifyAuditIntegrity } from "../src/db/audit.js";

describe("audit: append-only + tamper-evident (§4.7)", () => {
  it("chains hashes across events and verifies clean", () => {
    const db = memoryDb();
    const e = crypto.randomUUID();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1000, currency: "USD" }, SYS);
    createPolicy(db, { entity_id: e, window: "month", amount_limit: 5000, currency: "USD" }, SYS);
    const result = verifyAuditIntegrity(db, e);
    expect(result.valid).toBe(true);
    expect(result.event_count).toBe(2);
    const events = listAuditEvents(db, e);
    expect(events[0]!.prev_hash).toBe("");
    expect(events[1]!.prev_hash).toBe(events[0]!.row_hash);
  });

  it("forbids UPDATE on audit rows via trigger", () => {
    const db = memoryDb();
    const e = crypto.randomUUID();
    recordAuditEvent(db, { entity_id: e, actor_id: "a", action: "policy.create", resource_type: "policy", detail: {} });
    expect(() => db.run("UPDATE controls_audit SET action = 'policy.delete'")).toThrow(/append-only/);
  });

  it("forbids DELETE on audit rows via trigger", () => {
    const db = memoryDb();
    const e = crypto.randomUUID();
    recordAuditEvent(db, { entity_id: e, actor_id: "a", action: "policy.create", resource_type: "policy", detail: {} });
    expect(() => db.run("DELETE FROM controls_audit")).toThrow(/append-only/);
  });

  it("detects a tampered chain (out-of-band hash mutation)", () => {
    const db = memoryDb();
    const e = crypto.randomUUID();
    recordAuditEvent(db, { entity_id: e, actor_id: "a", action: "policy.create", resource_type: "policy", amount: 100, currency: "USD", detail: {} });
    recordAuditEvent(db, { entity_id: e, actor_id: "a", action: "policy.update", resource_type: "policy", amount: 200, currency: "USD", detail: {} });
    // Simulate tampering by disabling the trigger through a raw table rebuild is
    // not possible with the guard, so we corrupt via a temp table copy to prove
    // verifyAuditIntegrity catches a hash mismatch when contents change.
    db.run("DROP TRIGGER controls_audit_no_update");
    db.run("UPDATE controls_audit SET amount = 999 WHERE amount = 200");
    const result = verifyAuditIntegrity(db, e);
    expect(result.valid).toBe(false);
    expect(result.issues.some((i) => i.code === "hash_mismatch")).toBe(true);
  });
});
