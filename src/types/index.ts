// === @hasna/controls domain types, enums, and error classes ===

// ---- Enums ----

export const SPEND_WINDOWS = ["transaction", "day", "week", "month"] as const;
export type SpendWindow = (typeof SPEND_WINDOWS)[number];

export const ALLOWLIST_STATUSES = ["allowed", "blocked"] as const;
export type AllowlistStatus = (typeof ALLOWLIST_STATUSES)[number];

export const AUTHORIZATION_STATUSES = [
  "pending",
  "approved",
  "rejected",
  "consumed",
  "expired",
] as const;
export type AuthorizationStatus = (typeof AUTHORIZATION_STATUSES)[number];

export const AUDIT_ACTIONS = [
  "policy.create",
  "policy.update",
  "policy.delete",
  "allowlist.upsert",
  "allowlist.remove",
  "approval_rule.create",
  "approval_rule.delete",
  "authorization.request",
  "authorization.approve",
  "authorization.reject",
  "authorization.consume",
  "authorization.expire",
  "freeze.create",
  "freeze.release",
  "storage.push",
  "storage.pull",
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

// ---- Domain rows ----

export interface Policy {
  id: string;
  entity_id: string;
  agent_id: string | null;
  window: SpendWindow;
  amount_limit: number; // minor units (e.g. cents)
  currency: string;
  active: boolean;
  note: string | null;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface CounterpartyAllowlistEntry {
  id: string;
  entity_id: string;
  counterparty_id: string;
  counterparty_name: string | null;
  status: AllowlistStatus;
  note: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApprovalRule {
  id: string;
  entity_id: string;
  tier: string;
  threshold_amount: number; // minor units; rule applies to amounts >= threshold
  currency: string;
  required_approvals: number;
  approver_role: string | null;
  created_at: string;
}

export interface AuthorizationApproval {
  approver_id: string;
  decided_at: string;
  decision: "approved" | "rejected";
  reason: string | null;
}

export interface Authorization {
  id: string;
  entity_id: string;
  requestor_id: string;
  amount: number; // minor units
  currency: string;
  counterparty_id: string;
  counterparty_name: string | null;
  status: AuthorizationStatus;
  required_approvals: number;
  approvals: AuthorizationApproval[];
  token: string | null; // single-use signed token, present once approved
  reason: string | null;
  created_at: string;
  updated_at: string;
  expires_at: string;
  approved_at: string | null;
  consumed_at: string | null;
}

export interface Freeze {
  id: string;
  entity_id: string;
  identity_id: string | null; // null => whole-entity freeze
  active: boolean;
  reason: string;
  created_at: string;
  released_at: string | null;
}

export interface AuditEvent {
  id: string;
  entity_id: string | null;
  actor_id: string | null;
  action: AuditAction;
  resource_type: string;
  resource_id: string | null;
  amount: number | null;
  currency: string | null;
  detail: Record<string, unknown>;
  prev_hash: string;
  row_hash: string;
  created_at: string;
}

export interface AuditIntegrityIssue {
  index: number;
  event_id: string;
  code: "hash_mismatch" | "previous_hash_mismatch";
  message: string;
}

export interface AuditIntegrityResult {
  entity_id: string | null;
  valid: boolean;
  event_count: number;
  head_hash: string | null;
  checked_at: string;
  issues: AuditIntegrityIssue[];
}

// ---- Error classes (each carries a stable `code` + static `suggestion`) ----

export class ControlsError extends Error {
  static code = "CONTROLS_ERROR";
  static suggestion = "";
  code: string;
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
    this.code = (new.target as typeof ControlsError).code;
  }
}

export class ValidationError extends ControlsError {
  static override code = "VALIDATION_ERROR";
  static override suggestion = "Fix the invalid field and retry.";
}

export class PolicyNotFoundError extends ControlsError {
  static override code = "POLICY_NOT_FOUND";
  static override suggestion = "List policies for the entity to find a valid id.";
}

export class AllowlistEntryNotFoundError extends ControlsError {
  static override code = "ALLOWLIST_ENTRY_NOT_FOUND";
  static override suggestion = "List allowlist entries for the entity to find a valid id.";
}

export class ApprovalRuleNotFoundError extends ControlsError {
  static override code = "APPROVAL_RULE_NOT_FOUND";
  static override suggestion = "List approval rules for the entity to find a valid id.";
}

export class AuthorizationNotFoundError extends ControlsError {
  static override code = "AUTHORIZATION_NOT_FOUND";
  static override suggestion = "List authorizations for the entity to find a valid id.";
}

export class FreezeNotFoundError extends ControlsError {
  static override code = "FREEZE_NOT_FOUND";
  static override suggestion = "List freezes for the entity to find a valid id.";
}

export class SpendCapExceededError extends ControlsError {
  static override code = "SPEND_CAP_EXCEEDED";
  static override suggestion = "Lower the amount, raise the cap, or request approval under a higher tier.";
}

export class CounterpartyNotAllowedError extends ControlsError {
  static override code = "COUNTERPARTY_NOT_ALLOWED";
  static override suggestion = "Add the counterparty to the allowlist before requesting an authorization.";
}

export class EntityFrozenError extends ControlsError {
  static override code = "ENTITY_FROZEN";
  static override suggestion = "Release the emergency freeze before authorizing any money movement.";
}

export class SegregationOfDutiesError extends ControlsError {
  static override code = "SEGREGATION_OF_DUTIES";
  static override suggestion = "A requestor cannot approve their own authorization; use a distinct approver principal.";
}

export class InvalidAuthorizationTransitionError extends ControlsError {
  static override code = "INVALID_AUTHORIZATION_TRANSITION";
  static override suggestion = "Check the authorization status; only pending tokens can be approved/rejected and only approved tokens consumed.";
}

export class InvalidTokenError extends ControlsError {
  static override code = "INVALID_TOKEN";
  static override suggestion = "Present the exact single-use token issued at approval time.";
}

export class PermissionDeniedError extends ControlsError {
  static override code = "PERMISSION_DENIED";
  static override suggestion = "Use a credential with the required scope and entity/org access.";
  constructor(action: string, resource?: string) {
    super(`Permission denied for action '${action}'${resource ? ` on ${resource}` : ""}.`);
  }
}

export class NotFoundError extends ControlsError {
  static override code = "NOT_FOUND";
  static override suggestion = "Check the resource path and id.";
}

/** Map an error code to an HTTP status. */
export const ERROR_STATUS: Record<string, number> = {
  VALIDATION_ERROR: 400,
  INVALID_LIST_QUERY: 400,
  UNAUTHORIZED: 401,
  PERMISSION_DENIED: 403,
  ENTITY_FROZEN: 423,
  SEGREGATION_OF_DUTIES: 422,
  SPEND_CAP_EXCEEDED: 422,
  COUNTERPARTY_NOT_ALLOWED: 422,
  INVALID_AUTHORIZATION_TRANSITION: 422,
  INVALID_TOKEN: 422,
  POLICY_NOT_FOUND: 404,
  ALLOWLIST_ENTRY_NOT_FOUND: 404,
  APPROVAL_RULE_NOT_FOUND: 404,
  AUTHORIZATION_NOT_FOUND: 404,
  FREEZE_NOT_FOUND: 404,
  NOT_FOUND: 404,
};

export interface ErrorEnvelope {
  code: string;
  message: string;
  suggestion: string;
}

/** Normalize any thrown value to the shared { code, message, suggestion } envelope. */
export function toErrorEnvelope(error: unknown): ErrorEnvelope {
  if (error instanceof ControlsError) {
    return {
      code: error.code,
      message: error.message,
      suggestion: (error.constructor as typeof ControlsError).suggestion || "",
    };
  }
  if (error instanceof Error && "code" in error && typeof (error as { code?: unknown }).code === "string") {
    return { code: (error as { code: string }).code, message: error.message, suggestion: "" };
  }
  if (error instanceof Error) {
    return { code: "INTERNAL_ERROR", message: error.message, suggestion: "Check the error message and retry." };
  }
  return { code: "UNKNOWN_ERROR", message: String(error), suggestion: "An unexpected error occurred." };
}

export function statusForCode(code: string): number {
  return ERROR_STATUS[code] ?? 500;
}
