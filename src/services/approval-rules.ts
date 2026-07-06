import type { Database } from "bun:sqlite";
import { now, uuid } from "../db/database.js";
import { recordAuditEvent } from "../db/audit.js";
import { ApprovalRuleNotFoundError, type ApprovalRule } from "../types/index.js";
import { authorize, type AuthorizationContext } from "./authorization.js";
import {
  actorId,
  entityResource,
  optionalInt,
  optionalString,
  requireCurrency,
  requirePositiveInt,
  requireString,
  type Input,
} from "./common.js";

export function createApprovalRule(db: Database, input: Input, ctx?: AuthorizationContext): ApprovalRule {
  const entity_id = requireString(input, "entity_id");
  authorize("admin", ctx, entityResource(entity_id, "approval_rule"));
  const rule: ApprovalRule = {
    id: uuid(),
    entity_id,
    tier: requireString(input, "tier"),
    threshold_amount: requirePositiveInt(input, "threshold_amount"),
    currency: requireCurrency(input),
    required_approvals: optionalInt(input, "required_approvals", 1),
    approver_role: optionalString(input, "approver_role"),
    created_at: now(),
  };
  if (rule.required_approvals < 1) rule.required_approvals = 1;
  db.run(
    `INSERT INTO approval_rules (id, entity_id, tier, threshold_amount, currency, required_approvals, approver_role, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [rule.id, rule.entity_id, rule.tier, rule.threshold_amount, rule.currency, rule.required_approvals, rule.approver_role, rule.created_at],
  );
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx),
    action: "approval_rule.create",
    resource_type: "approval_rule",
    resource_id: rule.id,
    amount: rule.threshold_amount,
    currency: rule.currency,
    detail: { tier: rule.tier, required_approvals: rule.required_approvals },
  });
  return rule;
}

export function getApprovalRule(db: Database, input: Input, ctx?: AuthorizationContext): ApprovalRule {
  const entity_id = requireString(input, "entity_id");
  const id = requireString(input, "id");
  authorize("read", ctx, entityResource(entity_id, "approval_rule"));
  const row = db.query("SELECT * FROM approval_rules WHERE id = ? AND entity_id = ?").get(id, entity_id) as ApprovalRule | null;
  if (!row) throw new ApprovalRuleNotFoundError(`Approval rule ${id} not found for entity ${entity_id}.`);
  return row;
}

export function listApprovalRules(db: Database, input: Input, ctx?: AuthorizationContext): ApprovalRule[] {
  const entity_id = requireString(input, "entity_id");
  authorize("read", ctx, entityResource(entity_id, "approval_rule"));
  return db.query("SELECT * FROM approval_rules WHERE entity_id = ? ORDER BY threshold_amount, id").all(entity_id) as ApprovalRule[];
}

export function deleteApprovalRule(db: Database, input: Input, ctx?: AuthorizationContext): { id: string; deleted: true } {
  const existing = getApprovalRule(db, input, ctx);
  authorize("admin", ctx, entityResource(existing.entity_id, "approval_rule"));
  db.run("DELETE FROM approval_rules WHERE id = ?", [existing.id]);
  recordAuditEvent(db, {
    entity_id: existing.entity_id,
    actor_id: actorId(ctx),
    action: "approval_rule.delete",
    resource_type: "approval_rule",
    resource_id: existing.id,
    detail: {},
  });
  return { id: existing.id, deleted: true };
}

/**
 * How many approvals a proposed amount requires for an entity+currency: the max
 * required_approvals across all rules whose threshold the amount meets/exceeds.
 * 0 => no human approval required (below all tiers).
 */
export function requiredApprovalsFor(db: Database, entity_id: string, amount: number, currency: string): number {
  const rows = db
    .query("SELECT required_approvals FROM approval_rules WHERE entity_id = ? AND currency = ? AND threshold_amount <= ?")
    .all(entity_id, currency, amount) as Array<{ required_approvals: number }>;
  return rows.reduce((max, r) => Math.max(max, r.required_approvals), 0);
}
