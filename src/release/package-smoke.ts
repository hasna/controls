#!/usr/bin/env bun
// Package smoke entry (referenced by `smoke:package` and package-smoke-script.test.ts).
// Exercises the core money-authorization flow end-to-end against an in-memory
// SQLite store to prove the published package's service surface is wired.
import { Database } from "bun:sqlite";
import { applySchema } from "../db/schema.js";
import { SYSTEM_AUTHORIZATION_CONTEXT } from "../services/authorization.js";
import { createPolicy } from "../services/policies.js";
import { allowCounterparty } from "../services/allowlists.js";
import { createApprovalRule } from "../services/approval-rules.js";
import {
  approveAuthorization,
  consumeAuthorization,
  requestAuthorization,
} from "../services/authorizations.js";
import { verifyAuditIntegrity } from "../db/audit.js";

export interface SmokeResult {
  ok: boolean;
  steps: string[];
  audit_valid: boolean;
  audit_events: number;
}

export function runSmoke(): SmokeResult {
  const steps: string[] = [];
  const db = new Database(":memory:");
  applySchema(db);
  const ctx = SYSTEM_AUTHORIZATION_CONTEXT;
  const entity_id = crypto.randomUUID();

  createPolicy(db, { entity_id, window: "day", amount_limit: 100_000, currency: "USD" }, ctx);
  steps.push("policy.create");

  allowCounterparty(db, { entity_id, counterparty_id: "cp-1", counterparty_name: "Acme" }, ctx);
  steps.push("counterparty.allow");

  createApprovalRule(db, { entity_id, tier: "high", threshold_amount: 50_000, currency: "USD", required_approvals: 1 }, ctx);
  steps.push("approval_rule.create");

  const req = requestAuthorization(
    db,
    { entity_id, requestor_id: "agent-a", amount: 60_000, currency: "USD", counterparty_id: "cp-1" },
    ctx,
  ) as { id: string; status: string };
  if (req.status !== "pending") throw new Error(`expected pending, got ${req.status}`);
  steps.push("authorization.request(pending)");

  const approved = approveAuthorization(db, { entity_id, id: req.id, approver_id: "agent-b" }, ctx) as { status: string; token: string };
  if (approved.status !== "approved" || !approved.token) throw new Error("approval did not issue a token");
  steps.push("authorization.approve");

  const consumed = consumeAuthorization(db, { entity_id, id: req.id, token: approved.token }, ctx) as { status: string };
  if (consumed.status !== "consumed") throw new Error("consume failed");
  steps.push("authorization.consume");

  const integrity = verifyAuditIntegrity(db, entity_id);
  db.close();

  return { ok: integrity.valid, steps, audit_valid: integrity.valid, audit_events: integrity.event_count };
}

if (import.meta.main) {
  try {
    const result = runSmoke();
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exit(1);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
