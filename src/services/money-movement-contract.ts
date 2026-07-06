import type { Database } from "bun:sqlite";
import type { Authorization } from "../types/index.js";
import { getAuthorization, verifyAuthorization } from "./authorizations.js";
import type { AuthorizationContext } from "./authorization.js";

export const MONEY_MOVING_APPS = [
  "iapp-payments",
  "iapp-treasury",
  "iapp-wallets",
  "iapp-billing",
  "iapp-accounting",
] as const;

export type MoneyMovingApp = (typeof MONEY_MOVING_APPS)[number] | (string & {});
export type MoneyMovementMode = "sandbox" | "read_only" | "live";

export interface MoneyMovementControlsInput {
  app_id: MoneyMovingApp;
  entity_id: string;
  authorization_id: string;
  token: string;
  amount: number;
  currency: string;
  counterparty_id: string;
  requestor_id: string;
  idempotency_key: string;
  execution_mode: MoneyMovementMode;
  operator_approval_ref?: string | null;
  sandbox_evidence_ref?: string | null;
  counterparty_verification_ref?: string | null;
  policy_snapshot_hash?: string | null;
  reconciliation_ref?: string | null;
  emergency_freeze_checked_at?: string | null;
}

export interface MoneyMovementControlDecision {
  control:
    | "controls_token"
    | "token_binding"
    | "idempotency"
    | "counterparty_verification"
    | "policy_snapshot"
    | "emergency_freeze"
    | "live_mode_gate"
    | "reconciliation";
  ok: boolean;
  reason: string;
}

export interface MoneyMovementControlsResult {
  allowed: boolean;
  app_id: MoneyMovingApp;
  entity_id: string;
  authorization_id: string;
  execution_mode: MoneyMovementMode;
  controls_version: 1;
  decisions: MoneyMovementControlDecision[];
  authorization: Pick<Authorization, "id" | "status" | "amount" | "currency" | "counterparty_id" | "requestor_id" | "approved_at" | "expires_at">;
}

function hasValue(value: string | null | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

function decision(control: MoneyMovementControlDecision["control"], ok: boolean, reason: string): MoneyMovementControlDecision {
  return { control, ok, reason };
}

/**
 * Shared fail-closed contract money-moving apps must call before a provider
 * mutation. This is intentionally read-only: execution services still call
 * `authorization.consume` exactly once after a provider-side success.
 */
export function evaluateMoneyMovementControls(
  db: Database,
  input: MoneyMovementControlsInput,
  ctx?: AuthorizationContext,
): MoneyMovementControlsResult {
  const verification = verifyAuthorization(
    db,
    {
      entity_id: input.entity_id,
      id: input.authorization_id,
      token: input.token,
    },
    ctx,
  );
  const authorization = getAuthorization(db, { entity_id: input.entity_id, id: input.authorization_id }, ctx);

  const decisions: MoneyMovementControlDecision[] = [
    decision("controls_token", verification.valid, verification.reason),
    decision(
      "token_binding",
      authorization.amount === input.amount &&
        authorization.currency === input.currency &&
        authorization.counterparty_id === input.counterparty_id &&
        authorization.requestor_id === input.requestor_id,
      "authorization must exactly match amount, currency, counterparty, and requestor",
    ),
    decision("idempotency", hasValue(input.idempotency_key), "movement must carry a stable idempotency key"),
    decision("counterparty_verification", hasValue(input.counterparty_verification_ref), "counterparty must have an external verification reference"),
    decision("policy_snapshot", hasValue(input.policy_snapshot_hash), "movement must include the immutable policy snapshot hash evaluated at approval time"),
    decision(
      "emergency_freeze",
      verification.valid && hasValue(input.emergency_freeze_checked_at),
      "controls verification must be current and freeze check timestamp must be recorded",
    ),
    decision(
      "live_mode_gate",
      input.execution_mode !== "live" || (hasValue(input.operator_approval_ref) && hasValue(input.sandbox_evidence_ref)),
      "live mode requires explicit operator approval and sandbox evidence references",
    ),
    decision("reconciliation", hasValue(input.reconciliation_ref), "movement must provide a reconciliation record reference"),
  ];

  return {
    allowed: decisions.every((d) => d.ok),
    app_id: input.app_id,
    entity_id: input.entity_id,
    authorization_id: input.authorization_id,
    execution_mode: input.execution_mode,
    controls_version: 1,
    decisions,
    authorization: {
      id: authorization.id,
      status: authorization.status,
      amount: authorization.amount,
      currency: authorization.currency,
      counterparty_id: authorization.counterparty_id,
      requestor_id: authorization.requestor_id,
      approved_at: authorization.approved_at,
      expires_at: authorization.expires_at,
    },
  };
}

export function assertMoneyMovementControls(
  db: Database,
  input: MoneyMovementControlsInput,
  ctx?: AuthorizationContext,
): MoneyMovementControlsResult {
  const result = evaluateMoneyMovementControls(db, input, ctx);
  if (!result.allowed) {
    const failed = result.decisions.filter((d) => !d.ok).map((d) => `${d.control}: ${d.reason}`).join("; ");
    throw new Error(`Money movement denied by controls contract: ${failed}`);
  }
  return result;
}
