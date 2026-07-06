import { describe, expect, it } from "bun:test";
import { memoryDb, SYS } from "./helpers/db.js";
import { createPolicy } from "../src/services/policies.js";
import { allowCounterparty, blockCounterparty } from "../src/services/allowlists.js";
import { createApprovalRule } from "../src/services/approval-rules.js";
import { createFreeze } from "../src/services/freezes.js";
import {
  approveAuthorization,
  consumeAuthorization,
  rejectAuthorization,
  requestAuthorization,
  verifyAuthorization,
} from "../src/services/authorizations.js";
import type { Authorization } from "../src/types/index.js";

function entity(): string {
  return crypto.randomUUID();
}

describe("authorizations: counterparty allowlist enforcement", () => {
  it("rejects a request to a non-allowlisted counterparty", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 100_000, currency: "USD" }, SYS);
    expect(() =>
      requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 100, currency: "USD", counterparty_id: "cp-x" }, SYS),
    ).toThrow(/not on the allowlist/);
  });

  it("rejects a blocked counterparty", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 100_000, currency: "USD" }, SYS);
    blockCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    expect(() =>
      requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 100, currency: "USD", counterparty_id: "cp-1" }, SYS),
    ).toThrow(/not on the allowlist/);
  });
});

describe("authorizations: spend caps", () => {
  it("rejects an amount that would exceed the day cap", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    expect(() =>
      requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 1500, currency: "USD", counterparty_id: "cp-1" }, SYS),
    ).toThrow(/Spend cap exceeded/);
  });

  it("accumulates approved spend within the window", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    // first 600 auto-approves (no rule), consuming budget
    requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 600, currency: "USD", counterparty_id: "cp-1" }, SYS);
    expect(() =>
      requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 500, currency: "USD", counterparty_id: "cp-1" }, SYS),
    ).toThrow(/Spend cap exceeded/);
  });

  it("enforces agent-scoped caps only against that agent", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, agent_id: "a", window: "day", amount_limit: 500, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    // agent b is not capped
    const ok = requestAuthorization(db, { entity_id: e, requestor_id: "b", amount: 5000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    expect(ok.status).toBe("approved");
    // agent a is capped
    expect(() =>
      requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 600, currency: "USD", counterparty_id: "cp-1" }, SYS),
    ).toThrow(/Spend cap exceeded/);
  });
});

describe("authorizations: approval tiers + segregation of duties", () => {
  function seed(db: ReturnType<typeof memoryDb>, e: string): void {
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    createApprovalRule(db, { entity_id: e, tier: "high", threshold_amount: 50_000, currency: "USD", required_approvals: 1 }, SYS);
  }

  it("auto-approves below the threshold and issues a token", () => {
    const db = memoryDb();
    const e = entity();
    seed(db, e);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 10_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    expect(auth.status).toBe("approved");
    expect(auth.token).toBeTruthy();
  });

  it("holds high-value requests pending approval", () => {
    const db = memoryDb();
    const e = entity();
    seed(db, e);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 60_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    expect(auth.status).toBe("pending");
    expect(auth.token).toBeNull();
    expect(auth.required_approvals).toBe(1);
  });

  it("blocks the requestor from approving their own authorization (SoD)", () => {
    const db = memoryDb();
    const e = entity();
    seed(db, e);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 60_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    expect(() => approveAuthorization(db, { entity_id: e, id: auth.id, approver_id: "a" }, SYS)).toThrow(/requestor/);
  });

  it("approves with a distinct approver and issues a token", () => {
    const db = memoryDb();
    const e = entity();
    seed(db, e);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 60_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    const approved = approveAuthorization(db, { entity_id: e, id: auth.id, approver_id: "b" }, SYS) as Authorization;
    expect(approved.status).toBe("approved");
    expect(approved.token).toBeTruthy();
  });

  it("requires two distinct approvers when required_approvals=2", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    createApprovalRule(db, { entity_id: e, tier: "critical", threshold_amount: 10_000, currency: "USD", required_approvals: 2 }, SYS);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 20_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    const one = approveAuthorization(db, { entity_id: e, id: auth.id, approver_id: "b" }, SYS) as Authorization;
    expect(one.status).toBe("pending");
    const two = approveAuthorization(db, { entity_id: e, id: auth.id, approver_id: "c" }, SYS) as Authorization;
    expect(two.status).toBe("approved");
    expect(two.token).toBeTruthy();
  });

  it("rejects a pending authorization", () => {
    const db = memoryDb();
    const e = entity();
    seed(db, e);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 60_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    const rejected = rejectAuthorization(db, { entity_id: e, id: auth.id, approver_id: "b", reason: "no" }, SYS) as Authorization;
    expect(rejected.status).toBe("rejected");
  });
});

describe("authorizations: single-use token + consume + verify", () => {
  function approvedAuth(db: ReturnType<typeof memoryDb>, e: string): Authorization {
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    return requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 10_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
  }

  it("verifies a valid token without consuming it", () => {
    const db = memoryDb();
    const e = entity();
    const auth = approvedAuth(db, e);
    const v = verifyAuthorization(db, { entity_id: e, id: auth.id, token: auth.token! }, SYS);
    expect(v.valid).toBe(true);
  });

  it("rejects a bad token", () => {
    const db = memoryDb();
    const e = entity();
    const auth = approvedAuth(db, e);
    expect(() => consumeAuthorization(db, { entity_id: e, id: auth.id, token: "deadbeef" }, SYS)).toThrow(/Token does not match/);
  });

  it("consumes once and refuses a second consume (single-use)", () => {
    const db = memoryDb();
    const e = entity();
    const auth = approvedAuth(db, e);
    const consumed = consumeAuthorization(db, { entity_id: e, id: auth.id, token: auth.token! }, SYS) as Authorization;
    expect(consumed.status).toBe("consumed");
    expect(() => consumeAuthorization(db, { entity_id: e, id: auth.id, token: auth.token! }, SYS)).toThrow(/only approved/);
  });

  it("expires an approved token past its TTL and blocks consume", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 10_000, currency: "USD", counterparty_id: "cp-1", ttl_seconds: -1 }, SYS) as Authorization;
    // ttl in the past => expired on next read
    expect(() => consumeAuthorization(db, { entity_id: e, id: auth.id, token: auth.token! }, SYS)).toThrow(/expired|only approved/);
  });
});

describe("authorizations: emergency freeze", () => {
  it("blocks new requests for a frozen identity", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    createFreeze(db, { entity_id: e, reason: "incident" }, SYS);
    expect(() =>
      requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 100, currency: "USD", counterparty_id: "cp-1" }, SYS),
    ).toThrow(/freeze/);
  });

  it("blocks consuming an approved token once frozen", () => {
    const db = memoryDb();
    const e = entity();
    createPolicy(db, { entity_id: e, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS);
    allowCounterparty(db, { entity_id: e, counterparty_id: "cp-1" }, SYS);
    const auth = requestAuthorization(db, { entity_id: e, requestor_id: "a", amount: 10_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
    createFreeze(db, { entity_id: e, reason: "incident" }, SYS);
    expect(() => consumeAuthorization(db, { entity_id: e, id: auth.id, token: auth.token! }, SYS)).toThrow(/freeze/);
  });
});
