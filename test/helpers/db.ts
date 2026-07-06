import { Database } from "bun:sqlite";
import { applySchema } from "../../src/db/schema.js";
import { SYSTEM_AUTHORIZATION_CONTEXT } from "../../src/services/authorization.js";
import { createPolicy } from "../../src/services/policies.js";
import { allowCounterparty } from "../../src/services/allowlists.js";
import { createApprovalRule } from "../../src/services/approval-rules.js";
import { requestAuthorization } from "../../src/services/authorizations.js";
import { createFreeze } from "../../src/services/freezes.js";
import type { Authorization, CounterpartyAllowlistEntry, ApprovalRule, Freeze, Policy } from "../../src/types/index.js";

export function memoryDb(): Database {
  const db = new Database(":memory:");
  applySchema(db);
  return db;
}

export const SYS = SYSTEM_AUTHORIZATION_CONTEXT;

export interface Seed {
  entity_id: string;
  policy: Policy;
  allow: CounterpartyAllowlistEntry;
  rule: ApprovalRule;
  pending: Authorization;
  pending2: Authorization;
  approved: Authorization;
  freeze: Freeze;
}

/**
 * Seed one entity with a coherent controls configuration used by parity + unit
 * tests: a day cap, an allowed counterparty (cp-1), a high-value approval rule,
 * two pending authorizations, one auto-approved authorization (+token), and an
 * identity-scoped freeze on "frozen-agent" (does not block agent-a).
 */
export function seedEntity(db: Database, entity_id: string): Seed {
  const policy = createPolicy(db, { entity_id, window: "day", amount_limit: 1_000_000, currency: "USD" }, SYS) as Policy;
  const allow = allowCounterparty(db, { entity_id, counterparty_id: "cp-1", counterparty_name: "Acme" }, SYS) as CounterpartyAllowlistEntry;
  const rule = createApprovalRule(db, { entity_id, tier: "high", threshold_amount: 50_000, currency: "USD", required_approvals: 1 }, SYS) as ApprovalRule;
  const pending = requestAuthorization(db, { entity_id, requestor_id: "agent-a", amount: 60_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
  const pending2 = requestAuthorization(db, { entity_id, requestor_id: "agent-a", amount: 70_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
  const approved = requestAuthorization(db, { entity_id, requestor_id: "agent-a", amount: 10_000, currency: "USD", counterparty_id: "cp-1" }, SYS) as Authorization;
  const freeze = createFreeze(db, { entity_id, identity_id: "frozen-agent", reason: "seed freeze" }, SYS) as Freeze;
  return { entity_id, policy, allow, rule, pending, pending2, approved, freeze };
}
