import { describe, expect, it } from "bun:test";
import { memoryDb, SYS } from "./helpers/db.js";
import { allowCounterparty } from "../src/services/allowlists.js";
import { requestAuthorization } from "../src/services/authorizations.js";
import { createFreeze } from "../src/services/freezes.js";
import { createPolicy } from "../src/services/policies.js";
import { assertMoneyMovementControls, evaluateMoneyMovementControls } from "../src/services/money-movement-contract.js";
import type { Authorization } from "../src/types/index.js";

function seedApproved(): { db: ReturnType<typeof memoryDb>; entity_id: string; auth: Authorization } {
  const db = memoryDb();
  const entity_id = crypto.randomUUID();
  createPolicy(db, { entity_id, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS);
  allowCounterparty(db, { entity_id, counterparty_id: "vendor-1" }, SYS);
  const auth = requestAuthorization(
    db,
    { entity_id, requestor_id: "payments-agent", amount: 10_000, currency: "USD", counterparty_id: "vendor-1" },
    SYS,
  ) as Authorization;
  return { db, entity_id, auth };
}

function movement(entity_id: string, auth: Authorization) {
  return {
    app_id: "iapp-payments",
    entity_id,
    authorization_id: auth.id,
    token: auth.token!,
    amount: auth.amount,
    currency: auth.currency,
    counterparty_id: auth.counterparty_id,
    requestor_id: auth.requestor_id,
    idempotency_key: "payreq_123",
    execution_mode: "sandbox" as const,
    counterparty_verification_ref: "vendor-verification/vendor-1/2026-07-06",
    policy_snapshot_hash: "sha256:policy-snapshot",
    reconciliation_ref: "recon/payreq_123",
    emergency_freeze_checked_at: new Date().toISOString(),
  };
}

describe("money-moving app controls contract", () => {
  it("allows a sandbox movement only when all mandatory controls are present", () => {
    const { db, entity_id, auth } = seedApproved();
    const result = evaluateMoneyMovementControls(db, movement(entity_id, auth), SYS);
    expect(result.allowed).toBe(true);
    expect(result.decisions.every((d) => d.ok)).toBe(true);
  });

  it("denies replay into a different amount even with a valid token", () => {
    const { db, entity_id, auth } = seedApproved();
    const result = evaluateMoneyMovementControls(db, { ...movement(entity_id, auth), amount: auth.amount + 1 }, SYS);
    expect(result.allowed).toBe(false);
    expect(result.decisions.find((d) => d.control === "token_binding")?.ok).toBe(false);
  });

  it("denies missing idempotency, counterparty, snapshot, and reconciliation evidence", () => {
    const { db, entity_id, auth } = seedApproved();
    const result = evaluateMoneyMovementControls(
      db,
      {
        ...movement(entity_id, auth),
        idempotency_key: "",
        counterparty_verification_ref: "",
        policy_snapshot_hash: "",
        reconciliation_ref: "",
      },
      SYS,
    );
    expect(result.allowed).toBe(false);
    expect(result.decisions.filter((d) => !d.ok).map((d) => d.control)).toEqual([
      "idempotency",
      "counterparty_verification",
      "policy_snapshot",
      "reconciliation",
    ]);
  });

  it("requires operator approval and sandbox evidence before live movement", () => {
    const { db, entity_id, auth } = seedApproved();
    const denied = evaluateMoneyMovementControls(db, { ...movement(entity_id, auth), execution_mode: "live" }, SYS);
    expect(denied.allowed).toBe(false);
    expect(denied.decisions.find((d) => d.control === "live_mode_gate")?.ok).toBe(false);

    const allowed = evaluateMoneyMovementControls(
      db,
      {
        ...movement(entity_id, auth),
        execution_mode: "live",
        operator_approval_ref: "approval/ticket-1",
        sandbox_evidence_ref: "sandbox/run-1",
      },
      SYS,
    );
    expect(allowed.allowed).toBe(true);
  });

  it("fails closed when an emergency freeze invalidates the controls token", () => {
    const { db, entity_id, auth } = seedApproved();
    createFreeze(db, { entity_id, reason: "incident" }, SYS);
    expect(() => assertMoneyMovementControls(db, movement(entity_id, auth), SYS)).toThrow(/emergency_freeze|controls_token/);
  });
});
