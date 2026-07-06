import type { Database } from "bun:sqlite";
import { now, uuid } from "../db/database.js";
import { recordAuditEvent } from "../db/audit.js";
import { PolicyNotFoundError, SPEND_WINDOWS, type Policy, type SpendWindow } from "../types/index.js";
import { authorize, type AuthorizationContext } from "./authorization.js";
import {
  actorId,
  entityResource,
  optionalBool,
  optionalString,
  requireCurrency,
  requireEnum,
  requirePositiveInt,
  requireString,
  sqliteBool,
  type Input,
} from "./common.js";

interface PolicyRow {
  id: string;
  entity_id: string;
  agent_id: string | null;
  window: string;
  amount_limit: number;
  currency: string;
  active: number;
  note: string | null;
  created_at: string;
  updated_at: string;
  version: number;
}

function mapRow(row: PolicyRow): Policy {
  return { ...row, window: row.window as SpendWindow, active: row.active === 1 };
}

export function createPolicy(db: Database, input: Input, ctx?: AuthorizationContext): Policy {
  const entity_id = requireString(input, "entity_id");
  authorize("write", ctx, entityResource(entity_id, "policy"));
  const id = uuid();
  const ts = now();
  const row: Policy = {
    id,
    entity_id,
    agent_id: optionalString(input, "agent_id"),
    window: requireEnum<SpendWindow>(input, "window", SPEND_WINDOWS),
    amount_limit: requirePositiveInt(input, "amount_limit"),
    currency: requireCurrency(input),
    active: true,
    note: optionalString(input, "note"),
    created_at: ts,
    updated_at: ts,
    version: 1,
  };
  db.run(
    `INSERT INTO policies (id, entity_id, agent_id, window, amount_limit, currency, active, note, created_at, updated_at, version)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.id, row.entity_id, row.agent_id, row.window, row.amount_limit, row.currency, sqliteBool(row.active), row.note, row.created_at, row.updated_at, row.version],
  );
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx),
    action: "policy.create",
    resource_type: "policy",
    resource_id: id,
    amount: row.amount_limit,
    currency: row.currency,
    detail: { window: row.window, agent_id: row.agent_id },
  });
  return row;
}

export function getPolicy(db: Database, input: Input, ctx?: AuthorizationContext): Policy {
  const entity_id = requireString(input, "entity_id");
  const id = requireString(input, "id");
  authorize("read", ctx, entityResource(entity_id, "policy"));
  const row = db.query("SELECT * FROM policies WHERE id = ? AND entity_id = ?").get(id, entity_id) as PolicyRow | null;
  if (!row) throw new PolicyNotFoundError(`Policy ${id} not found for entity ${entity_id}.`);
  return mapRow(row);
}

export function listPolicies(db: Database, input: Input, ctx?: AuthorizationContext): Policy[] {
  const entity_id = requireString(input, "entity_id");
  authorize("read", ctx, entityResource(entity_id, "policy"));
  const rows = db.query("SELECT * FROM policies WHERE entity_id = ? ORDER BY created_at, id").all(entity_id) as PolicyRow[];
  return rows.map(mapRow);
}

export function updatePolicy(db: Database, input: Input, ctx?: AuthorizationContext): Policy {
  const existing = getPolicy(db, input, ctx);
  authorize("write", ctx, entityResource(existing.entity_id, "policy"));
  const active = optionalBool(input, "active");
  const amountRaw = input["amount_limit"];
  const amount_limit = amountRaw === undefined || amountRaw === null || amountRaw === "" ? existing.amount_limit : requirePositiveInt(input, "amount_limit");
  const note = input["note"] === undefined ? existing.note : optionalString(input, "note");
  const ts = now();
  const nextActive = active === undefined ? existing.active : active;
  db.run(
    "UPDATE policies SET amount_limit = ?, active = ?, note = ?, updated_at = ?, version = version + 1 WHERE id = ?",
    [amount_limit, sqliteBool(nextActive), note, ts, existing.id],
  );
  recordAuditEvent(db, {
    entity_id: existing.entity_id,
    actor_id: actorId(ctx),
    action: "policy.update",
    resource_type: "policy",
    resource_id: existing.id,
    amount: amount_limit,
    currency: existing.currency,
    detail: { active: nextActive },
  });
  return getPolicy(db, { entity_id: existing.entity_id, id: existing.id }, ctx);
}

export function deletePolicy(db: Database, input: Input, ctx?: AuthorizationContext): { id: string; deleted: true } {
  const existing = getPolicy(db, input, ctx);
  authorize("admin", ctx, entityResource(existing.entity_id, "policy"));
  db.run("DELETE FROM policies WHERE id = ?", [existing.id]);
  recordAuditEvent(db, {
    entity_id: existing.entity_id,
    actor_id: actorId(ctx),
    action: "policy.delete",
    resource_type: "policy",
    resource_id: existing.id,
    detail: {},
  });
  return { id: existing.id, deleted: true };
}

/** Windows -> lookback in ms for cap evaluation. `transaction` has no lookback. */
const WINDOW_MS: Record<SpendWindow, number> = {
  transaction: 0,
  day: 86_400_000,
  week: 604_800_000,
  month: 2_592_000_000,
};

export interface CapEvaluation {
  entity_id: string;
  amount: number;
  currency: string;
  within_caps: boolean;
  breached: Array<{ policy_id: string; window: SpendWindow; amount_limit: number; already_consumed: number; would_total: number }>;
}

/**
 * Evaluate a proposed spend against all active policies for the entity (and the
 * requesting agent, if the policy is agent-scoped). "already_consumed" counts
 * approved+consumed authorizations within the policy window.
 */
export function evaluateCaps(
  db: Database,
  entity_id: string,
  amount: number,
  currency: string,
  agent_id: string | null,
  atIso: string = now(),
): CapEvaluation {
  const rows = db.query("SELECT * FROM policies WHERE entity_id = ? AND active = 1 AND currency = ?").all(entity_id, currency) as PolicyRow[];
  const breached: CapEvaluation["breached"] = [];
  const at = Date.parse(atIso);

  for (const raw of rows) {
    const policy = mapRow(raw);
    if (policy.agent_id && policy.agent_id !== agent_id) continue;
    const consumed = consumedInWindow(db, entity_id, currency, policy.window, at, policy.agent_id);
    const wouldTotal = policy.window === "transaction" ? amount : consumed + amount;
    if (wouldTotal > policy.amount_limit) {
      breached.push({
        policy_id: policy.id,
        window: policy.window,
        amount_limit: policy.amount_limit,
        already_consumed: policy.window === "transaction" ? 0 : consumed,
        would_total: wouldTotal,
      });
    }
  }

  return { entity_id, amount, currency, within_caps: breached.length === 0, breached };
}

function consumedInWindow(
  db: Database,
  entity_id: string,
  currency: string,
  window: SpendWindow,
  at: number,
  agent_id: string | null,
): number {
  if (window === "transaction") return 0;
  const since = new Date(at - WINDOW_MS[window]).toISOString();
  const params: (string | number)[] = [entity_id, currency, since];
  let agentClause = "";
  if (agent_id) {
    agentClause = " AND requestor_id = ?";
    params.push(agent_id);
  }
  const row = db
    .query(
      `SELECT COALESCE(SUM(amount), 0) AS total FROM authorizations
       WHERE entity_id = ? AND currency = ? AND status IN ('approved','consumed') AND created_at >= ?${agentClause}`,
    )
    .get(...params) as { total: number };
  return row.total;
}
