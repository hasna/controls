import type { Database } from "bun:sqlite";
import { now, uuid } from "../db/database.js";
import { recordAuditEvent } from "../db/audit.js";
import {
  AuthorizationNotFoundError,
  CounterpartyNotAllowedError,
  EntityFrozenError,
  InvalidAuthorizationTransitionError,
  InvalidTokenError,
  SegregationOfDutiesError,
  SpendCapExceededError,
  type Authorization,
  type AuthorizationApproval,
  type AuthorizationStatus,
} from "../types/index.js";
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
import { evaluateCaps } from "./policies.js";
import { isCounterpartyAllowed } from "./allowlists.js";
import { requiredApprovalsFor } from "./approval-rules.js";
import { isFrozen } from "./freezes.js";
import { signAuthorizationToken, verifyAuthorizationToken } from "./token.js";

const DEFAULT_TTL_SECONDS = 3600;

interface AuthRow {
  id: string;
  entity_id: string;
  requestor_id: string;
  amount: number;
  currency: string;
  counterparty_id: string;
  counterparty_name: string | null;
  status: string;
  required_approvals: number;
  approvals: string;
  token: string | null;
  reason: string | null;
  created_at: string;
  updated_at: string;
  expires_at: string;
  approved_at: string | null;
  consumed_at: string | null;
}

function mapRow(row: AuthRow): Authorization {
  return {
    ...row,
    status: row.status as AuthorizationStatus,
    approvals: JSON.parse(row.approvals || "[]") as AuthorizationApproval[],
  };
}

function compareVisibleAuthorizationFields(left: Authorization, right: Authorization): number {
  const fields = [
    "status",
    "requestor_id",
    "amount",
    "currency",
    "counterparty_id",
    "counterparty_name",
    "required_approvals",
    "reason",
  ] as const;
  for (const field of fields) {
    const a = left[field] ?? "";
    const b = right[field] ?? "";
    if (a < b) return -1;
    if (a > b) return 1;
  }
  const approvals = JSON.stringify(left.approvals).localeCompare(JSON.stringify(right.approvals));
  if (approvals !== 0) return approvals;
  return left.id.localeCompare(right.id);
}

/** Lazily flip an approved/pending authorization to expired once past its TTL. */
function applyExpiry(db: Database, row: AuthRow): AuthRow {
  if ((row.status === "pending" || row.status === "approved") && Date.parse(row.expires_at) <= Date.now()) {
    db.run("UPDATE authorizations SET status = 'expired', updated_at = ? WHERE id = ?", [now(), row.id]);
    recordAuditEvent(db, {
      entity_id: row.entity_id,
      actor_id: null,
      action: "authorization.expire",
      resource_type: "authorization",
      resource_id: row.id,
      amount: row.amount,
      currency: row.currency,
      detail: {},
    });
    return { ...row, status: "expired" };
  }
  return row;
}

function loadRow(db: Database, entity_id: string, id: string): AuthRow {
  const row = db.query("SELECT * FROM authorizations WHERE id = ? AND entity_id = ?").get(id, entity_id) as AuthRow | null;
  if (!row) throw new AuthorizationNotFoundError(`Authorization ${id} not found for entity ${entity_id}.`);
  return applyExpiry(db, row);
}

/**
 * Request a single-use money authorization. Enforces (in order): emergency
 * freeze, counterparty allowlist, and per-entity/per-agent spend caps. Then
 * computes required approvals from the tiered rules; if none are required the
 * token is issued immediately (status=approved), otherwise it is held pending.
 */
export function requestAuthorization(db: Database, input: Input, ctx?: AuthorizationContext): Authorization {
  const entity_id = requireString(input, "entity_id");
  authorize("write", ctx, entityResource(entity_id, "authorization"));
  const requestor_id = requireString(input, "requestor_id");
  const amount = requirePositiveInt(input, "amount");
  const currency = requireCurrency(input);
  const counterparty_id = requireString(input, "counterparty_id");
  const counterparty_name = optionalString(input, "counterparty_name");
  const reason = optionalString(input, "reason");
  const ttl = optionalInt(input, "ttl_seconds", DEFAULT_TTL_SECONDS);

  if (isFrozen(db, entity_id, requestor_id)) {
    throw new EntityFrozenError(`Entity ${entity_id} (or identity ${requestor_id}) is under an emergency freeze.`);
  }
  if (!isCounterpartyAllowed(db, entity_id, counterparty_id)) {
    throw new CounterpartyNotAllowedError(`Counterparty ${counterparty_id} is not on the allowlist for entity ${entity_id}.`);
  }
  const caps = evaluateCaps(db, entity_id, amount, currency, requestor_id);
  if (!caps.within_caps) {
    throw new SpendCapExceededError(
      `Spend cap exceeded for entity ${entity_id}: ${caps.breached.map((b) => `${b.window} limit ${b.amount_limit} (would total ${b.would_total})`).join("; ")}.`,
    );
  }

  const required = requiredApprovalsFor(db, entity_id, amount, currency);
  const id = uuid();
  const ts = now();
  const expires_at = new Date(Date.parse(ts) + ttl * 1000).toISOString();
  const status: AuthorizationStatus = required === 0 ? "approved" : "pending";
  const base = { id, entity_id, amount, currency, counterparty_id, requestor_id };
  const token = status === "approved" ? signAuthorizationToken(base) : null;
  const approved_at = status === "approved" ? ts : null;

  db.run(
    `INSERT INTO authorizations
       (id, entity_id, requestor_id, amount, currency, counterparty_id, counterparty_name, status, required_approvals, approvals, token, reason, created_at, updated_at, expires_at, approved_at, consumed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?, ?, ?, NULL)`,
    [id, entity_id, requestor_id, amount, currency, counterparty_id, counterparty_name, status, required, token, reason, ts, ts, expires_at, approved_at],
  );
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx) ?? requestor_id,
    action: "authorization.request",
    resource_type: "authorization",
    resource_id: id,
    amount,
    currency,
    detail: { counterparty_id, required_approvals: required, status },
  });
  return mapRow(loadRow(db, entity_id, id));
}

export function approveAuthorization(db: Database, input: Input, ctx?: AuthorizationContext): Authorization {
  const entity_id = requireString(input, "entity_id");
  authorize("approve", ctx, entityResource(entity_id, "authorization"));
  const id = requireString(input, "id");
  const approver_id = requireString(input, "approver_id");
  const reason = optionalString(input, "reason");
  const row = loadRow(db, entity_id, id);
  if (row.status !== "pending") {
    throw new InvalidAuthorizationTransitionError(`Authorization ${id} is '${row.status}'; only pending authorizations can be approved.`);
  }
  // Segregation of duties: a requestor must not approve their own authorization.
  if (approver_id === row.requestor_id) {
    throw new SegregationOfDutiesError(`Approver ${approver_id} is the requestor of authorization ${id}.`);
  }
  const approvals = JSON.parse(row.approvals || "[]") as AuthorizationApproval[];
  if (approvals.some((a) => a.approver_id === approver_id)) {
    throw new InvalidAuthorizationTransitionError(`Approver ${approver_id} has already voted on authorization ${id}.`);
  }
  approvals.push({ approver_id, decided_at: now(), decision: "approved", reason });
  const ts = now();

  const approvedCount = approvals.filter((a) => a.decision === "approved").length;
  const fullyApproved = approvedCount >= row.required_approvals;
  const token = fullyApproved
    ? signAuthorizationToken({ id: row.id, entity_id, amount: row.amount, currency: row.currency, counterparty_id: row.counterparty_id, requestor_id: row.requestor_id })
    : null;
  const status: AuthorizationStatus = fullyApproved ? "approved" : "pending";
  const approved_at = fullyApproved ? ts : null;

  db.run(
    "UPDATE authorizations SET approvals = ?, status = ?, token = ?, approved_at = ?, updated_at = ? WHERE id = ?",
    [JSON.stringify(approvals), status, token, approved_at, ts, id],
  );
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx) ?? approver_id,
    action: "authorization.approve",
    resource_type: "authorization",
    resource_id: id,
    amount: row.amount,
    currency: row.currency,
    detail: { approver_id, approvals: approvedCount, required: row.required_approvals, status },
  });
  return mapRow(loadRow(db, entity_id, id));
}

export function rejectAuthorization(db: Database, input: Input, ctx?: AuthorizationContext): Authorization {
  const entity_id = requireString(input, "entity_id");
  authorize("approve", ctx, entityResource(entity_id, "authorization"));
  const id = requireString(input, "id");
  const approver_id = requireString(input, "approver_id");
  const reason = optionalString(input, "reason");
  const row = loadRow(db, entity_id, id);
  if (row.status !== "pending") {
    throw new InvalidAuthorizationTransitionError(`Authorization ${id} is '${row.status}'; only pending authorizations can be rejected.`);
  }
  if (approver_id === row.requestor_id) {
    throw new SegregationOfDutiesError(`Approver ${approver_id} is the requestor of authorization ${id}.`);
  }
  const approvals = JSON.parse(row.approvals || "[]") as AuthorizationApproval[];
  approvals.push({ approver_id, decided_at: now(), decision: "rejected", reason });
  const ts = now();
  db.run("UPDATE authorizations SET approvals = ?, status = 'rejected', updated_at = ? WHERE id = ?", [JSON.stringify(approvals), ts, id]);
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx) ?? approver_id,
    action: "authorization.reject",
    resource_type: "authorization",
    resource_id: id,
    amount: row.amount,
    currency: row.currency,
    detail: { approver_id, reason },
  });
  return mapRow(loadRow(db, entity_id, id));
}

/**
 * Consume a single-use authorization token (the mover calls this once a payment
 * is actually executed). Requires status=approved, a matching token, no active
 * freeze, and not expired. Transitions to consumed (single-use).
 */
export function consumeAuthorization(db: Database, input: Input, ctx?: AuthorizationContext): Authorization {
  const entity_id = requireString(input, "entity_id");
  authorize("write", ctx, entityResource(entity_id, "authorization"));
  const id = requireString(input, "id");
  const token = requireString(input, "token");
  const row = loadRow(db, entity_id, id);
  if (row.status !== "approved") {
    throw new InvalidAuthorizationTransitionError(`Authorization ${id} is '${row.status}'; only approved authorizations can be consumed.`);
  }
  const base = { id: row.id, entity_id, amount: row.amount, currency: row.currency, counterparty_id: row.counterparty_id, requestor_id: row.requestor_id };
  if (!row.token || !verifyAuthorizationToken(base, token)) {
    throw new InvalidTokenError(`Token does not match authorization ${id}.`);
  }
  if (isFrozen(db, entity_id, row.requestor_id)) {
    throw new EntityFrozenError(`Entity ${entity_id} is under an emergency freeze; consumption blocked.`);
  }
  const ts = now();
  db.run("UPDATE authorizations SET status = 'consumed', consumed_at = ?, updated_at = ? WHERE id = ?", [ts, ts, id]);
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx),
    action: "authorization.consume",
    resource_type: "authorization",
    resource_id: id,
    amount: row.amount,
    currency: row.currency,
    detail: { counterparty_id: row.counterparty_id },
  });
  return mapRow(loadRow(db, entity_id, id));
}

export function getAuthorization(db: Database, input: Input, ctx?: AuthorizationContext): Authorization {
  const entity_id = requireString(input, "entity_id");
  const id = requireString(input, "id");
  authorize("read", ctx, entityResource(entity_id, "authorization"));
  return mapRow(loadRow(db, entity_id, id));
}

export function listAuthorizations(db: Database, input: Input, ctx?: AuthorizationContext): Authorization[] {
  const entity_id = requireString(input, "entity_id");
  authorize("read", ctx, entityResource(entity_id, "authorization"));
  const status = optionalString(input, "status");
  const rows = (
    status
      ? db.query("SELECT * FROM authorizations WHERE entity_id = ? AND status = ? ORDER BY created_at, id").all(entity_id, status)
      : db.query("SELECT * FROM authorizations WHERE entity_id = ? ORDER BY created_at, id").all(entity_id)
  ) as AuthRow[];
  return rows.map((r) => mapRow(applyExpiry(db, r))).sort(compareVisibleAuthorizationFields);
}

export interface AuthorizationVerification {
  authorization_id: string;
  valid: boolean;
  reason: string;
  status: AuthorizationStatus;
}

/**
 * The enforcement contract the movers (wallets/payments) adopt: verify (without
 * mutating) that a token is a live, approved, unexpired, unfrozen authorization
 * bound to the given money parameters.
 */
export function verifyAuthorization(db: Database, input: Input, ctx?: AuthorizationContext): AuthorizationVerification {
  const entity_id = requireString(input, "entity_id");
  const id = requireString(input, "id");
  const token = requireString(input, "token");
  authorize("read", ctx, entityResource(entity_id, "authorization"));
  const row = loadRow(db, entity_id, id);
  const base = { id: row.id, entity_id, amount: row.amount, currency: row.currency, counterparty_id: row.counterparty_id, requestor_id: row.requestor_id };
  let valid = true;
  let reason = "ok";
  if (row.status !== "approved") {
    valid = false;
    reason = `authorization is '${row.status}', not approved`;
  } else if (!row.token || !verifyAuthorizationToken(base, token)) {
    valid = false;
    reason = "token mismatch";
  } else if (isFrozen(db, entity_id, row.requestor_id)) {
    valid = false;
    reason = "entity/identity is frozen";
  }
  return { authorization_id: id, valid, reason, status: row.status as AuthorizationStatus };
}
