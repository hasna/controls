import type { Database } from "bun:sqlite";
import type { AuthorizationAction, AuthorizationContext } from "./authorization.js";
import type { Input } from "./common.js";
import * as policies from "./policies.js";
import * as allowlists from "./allowlists.js";
import * as approvalRules from "./approval-rules.js";
import * as authorizations from "./authorizations.js";
import * as freezes from "./freezes.js";
import * as audit from "./audit.js";

export type Profile = "minimal" | "standard" | "full";
export type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";

export interface OperationDef {
  /** Canonical operation name, e.g. "policy.create". */
  op: string;
  summary: string;
  /** Domain authorization action (maps to a scope on the serve/MCP tiers). */
  action: AuthorizationAction;
  mutates: boolean;
  handler: (db: Database, input: Input, ctx?: AuthorizationContext) => unknown;
  /** REST binding. `path` uses :params; `entity_id` always comes from the path. */
  rest: { method: HttpMethod; path: string };
  /** Names of :params to lift from the path into the op input. */
  pathParams: string[];
  /** MCP tool name (namespaced controls_* at registration time). */
  mcp: string;
  /** CLI namespace + command (friendly surface). */
  cli: { namespace: string; command: string };
  profiles: Profile[];
  /** Input field names, for CLI flag generation + OpenAPI docs. */
  fields: OperationField[];
}

export interface OperationField {
  name: string;
  type: "string" | "integer" | "boolean";
  required: boolean;
  description: string;
}

const ENTITY = { name: "entity_id", type: "string", required: true, description: "Entity UUID this record is anchored to." } as const;

export const OPERATIONS: OperationDef[] = [
  // ---- policies ----
  {
    op: "policy.create", summary: "Create a per-entity/per-agent spend cap.", action: "write", mutates: true,
    handler: policies.createPolicy, rest: { method: "POST", path: "/v1/entities/:entity_id/policies" }, pathParams: ["entity_id"],
    mcp: "policy_create", cli: { namespace: "policies", command: "create" }, profiles: ["minimal", "standard", "full"],
    fields: [ENTITY,
      { name: "agent_id", type: "string", required: false, description: "Scope the cap to a single agent identity (optional)." },
      { name: "window", type: "string", required: true, description: "Cap window: transaction|day|week|month." },
      { name: "amount_limit", type: "integer", required: true, description: "Cap amount in minor units (e.g. cents)." },
      { name: "currency", type: "string", required: true, description: "ISO-4217 currency code." },
      { name: "note", type: "string", required: false, description: "Free-text note." }],
  },
  {
    op: "policy.list", summary: "List spend caps for an entity.", action: "read", mutates: false,
    handler: policies.listPolicies, rest: { method: "GET", path: "/v1/entities/:entity_id/policies" }, pathParams: ["entity_id"],
    mcp: "policy_list", cli: { namespace: "policies", command: "list" }, profiles: ["minimal", "standard", "full"], fields: [ENTITY],
  },
  {
    op: "policy.get", summary: "Get a spend cap by id.", action: "read", mutates: false,
    handler: policies.getPolicy, rest: { method: "GET", path: "/v1/entities/:entity_id/policies/:id" }, pathParams: ["entity_id", "id"],
    mcp: "policy_get", cli: { namespace: "policies", command: "get" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Policy id." }],
  },
  {
    op: "policy.update", summary: "Update a spend cap (amount/active/note).", action: "write", mutates: true,
    handler: policies.updatePolicy, rest: { method: "PATCH", path: "/v1/entities/:entity_id/policies/:id" }, pathParams: ["entity_id", "id"],
    mcp: "policy_update", cli: { namespace: "policies", command: "update" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Policy id." },
      { name: "amount_limit", type: "integer", required: false, description: "New cap amount in minor units." },
      { name: "active", type: "boolean", required: false, description: "Enable/disable the cap." },
      { name: "note", type: "string", required: false, description: "Free-text note." }],
  },
  {
    op: "policy.delete", summary: "Delete a spend cap.", action: "admin", mutates: true,
    handler: policies.deletePolicy, rest: { method: "DELETE", path: "/v1/entities/:entity_id/policies/:id" }, pathParams: ["entity_id", "id"],
    mcp: "policy_delete", cli: { namespace: "policies", command: "delete" }, profiles: ["full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Policy id." }],
  },

  // ---- counterparty allowlists ----
  {
    op: "counterparty.allow", summary: "Add/allow a counterparty on the allowlist.", action: "write", mutates: true,
    handler: allowlists.allowCounterparty, rest: { method: "POST", path: "/v1/entities/:entity_id/allowlist" }, pathParams: ["entity_id"],
    mcp: "counterparty_allow", cli: { namespace: "allowlist", command: "allow" }, profiles: ["minimal", "standard", "full"],
    fields: [ENTITY, { name: "counterparty_id", type: "string", required: true, description: "Counterparty identifier." },
      { name: "counterparty_name", type: "string", required: false, description: "Display name." },
      { name: "note", type: "string", required: false, description: "Free-text note." }],
  },
  {
    op: "counterparty.block", summary: "Block a counterparty.", action: "write", mutates: true,
    handler: allowlists.blockCounterparty, rest: { method: "POST", path: "/v1/entities/:entity_id/allowlist/block" }, pathParams: ["entity_id"],
    mcp: "counterparty_block", cli: { namespace: "allowlist", command: "block" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "counterparty_id", type: "string", required: true, description: "Counterparty identifier." },
      { name: "counterparty_name", type: "string", required: false, description: "Display name." },
      { name: "note", type: "string", required: false, description: "Free-text note." }],
  },
  {
    op: "counterparty.list", summary: "List allowlist entries for an entity.", action: "read", mutates: false,
    handler: allowlists.listAllowlist, rest: { method: "GET", path: "/v1/entities/:entity_id/allowlist" }, pathParams: ["entity_id"],
    mcp: "counterparty_list", cli: { namespace: "allowlist", command: "list" }, profiles: ["minimal", "standard", "full"], fields: [ENTITY],
  },
  {
    op: "counterparty.get", summary: "Get an allowlist entry by id.", action: "read", mutates: false,
    handler: allowlists.getAllowlistEntry, rest: { method: "GET", path: "/v1/entities/:entity_id/allowlist/:id" }, pathParams: ["entity_id", "id"],
    mcp: "counterparty_get", cli: { namespace: "allowlist", command: "get" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Allowlist entry id." }],
  },
  {
    op: "counterparty.remove", summary: "Remove an allowlist entry.", action: "admin", mutates: true,
    handler: allowlists.removeAllowlistEntry, rest: { method: "DELETE", path: "/v1/entities/:entity_id/allowlist/:id" }, pathParams: ["entity_id", "id"],
    mcp: "counterparty_remove", cli: { namespace: "allowlist", command: "remove" }, profiles: ["full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Allowlist entry id." }],
  },

  // ---- approval rules ----
  {
    op: "approval_rule.create", summary: "Create a tiered approval threshold rule.", action: "admin", mutates: true,
    handler: approvalRules.createApprovalRule, rest: { method: "POST", path: "/v1/entities/:entity_id/approval-rules" }, pathParams: ["entity_id"],
    mcp: "approval_rule_create", cli: { namespace: "approval-rules", command: "create" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "tier", type: "string", required: true, description: "Tier label, e.g. 'high-value'." },
      { name: "threshold_amount", type: "integer", required: true, description: "Rule applies to amounts >= this (minor units)." },
      { name: "currency", type: "string", required: true, description: "ISO-4217 currency code." },
      { name: "required_approvals", type: "integer", required: false, description: "Number of distinct approvals required (default 1)." },
      { name: "approver_role", type: "string", required: false, description: "Role expected to approve (advisory)." }],
  },
  {
    op: "approval_rule.list", summary: "List approval rules for an entity.", action: "read", mutates: false,
    handler: approvalRules.listApprovalRules, rest: { method: "GET", path: "/v1/entities/:entity_id/approval-rules" }, pathParams: ["entity_id"],
    mcp: "approval_rule_list", cli: { namespace: "approval-rules", command: "list" }, profiles: ["standard", "full"], fields: [ENTITY],
  },
  {
    op: "approval_rule.get", summary: "Get an approval rule by id.", action: "read", mutates: false,
    handler: approvalRules.getApprovalRule, rest: { method: "GET", path: "/v1/entities/:entity_id/approval-rules/:id" }, pathParams: ["entity_id", "id"],
    mcp: "approval_rule_get", cli: { namespace: "approval-rules", command: "get" }, profiles: ["full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Approval rule id." }],
  },
  {
    op: "approval_rule.delete", summary: "Delete an approval rule.", action: "admin", mutates: true,
    handler: approvalRules.deleteApprovalRule, rest: { method: "DELETE", path: "/v1/entities/:entity_id/approval-rules/:id" }, pathParams: ["entity_id", "id"],
    mcp: "approval_rule_delete", cli: { namespace: "approval-rules", command: "delete" }, profiles: ["full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Approval rule id." }],
  },

  // ---- authorizations ----
  {
    op: "authorization.request", summary: "Request a single-use money authorization token.", action: "write", mutates: true,
    handler: authorizations.requestAuthorization, rest: { method: "POST", path: "/v1/entities/:entity_id/authorizations" }, pathParams: ["entity_id"],
    mcp: "authorization_request", cli: { namespace: "authorizations", command: "request" }, profiles: ["minimal", "standard", "full"],
    fields: [ENTITY, { name: "requestor_id", type: "string", required: true, description: "Identity requesting the spend." },
      { name: "amount", type: "integer", required: true, description: "Amount in minor units." },
      { name: "currency", type: "string", required: true, description: "ISO-4217 currency code." },
      { name: "counterparty_id", type: "string", required: true, description: "Counterparty to pay." },
      { name: "counterparty_name", type: "string", required: false, description: "Display name." },
      { name: "reason", type: "string", required: false, description: "Business justification." },
      { name: "ttl_seconds", type: "integer", required: false, description: "Token time-to-live in seconds (default 3600)." }],
  },
  {
    op: "authorization.list", summary: "List authorizations for an entity.", action: "read", mutates: false,
    handler: authorizations.listAuthorizations, rest: { method: "GET", path: "/v1/entities/:entity_id/authorizations" }, pathParams: ["entity_id"],
    mcp: "authorization_list", cli: { namespace: "authorizations", command: "list" }, profiles: ["minimal", "standard", "full"],
    fields: [ENTITY, { name: "status", type: "string", required: false, description: "Filter by status." }],
  },
  {
    op: "authorization.get", summary: "Get an authorization by id.", action: "read", mutates: false,
    handler: authorizations.getAuthorization, rest: { method: "GET", path: "/v1/entities/:entity_id/authorizations/:id" }, pathParams: ["entity_id", "id"],
    mcp: "authorization_get", cli: { namespace: "authorizations", command: "get" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Authorization id." }],
  },
  {
    op: "authorization.approve", summary: "Approve a pending authorization (SoD enforced).", action: "approve", mutates: true,
    handler: authorizations.approveAuthorization, rest: { method: "POST", path: "/v1/entities/:entity_id/authorizations/:id/approve" }, pathParams: ["entity_id", "id"],
    mcp: "authorization_approve", cli: { namespace: "authorizations", command: "approve" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Authorization id." },
      { name: "approver_id", type: "string", required: true, description: "Approver identity (must differ from requestor)." },
      { name: "reason", type: "string", required: false, description: "Approval note." }],
  },
  {
    op: "authorization.reject", summary: "Reject a pending authorization.", action: "approve", mutates: true,
    handler: authorizations.rejectAuthorization, rest: { method: "POST", path: "/v1/entities/:entity_id/authorizations/:id/reject" }, pathParams: ["entity_id", "id"],
    mcp: "authorization_reject", cli: { namespace: "authorizations", command: "reject" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Authorization id." },
      { name: "approver_id", type: "string", required: true, description: "Approver identity (must differ from requestor)." },
      { name: "reason", type: "string", required: false, description: "Rejection note." }],
  },
  {
    op: "authorization.consume", summary: "Consume a single-use approved token (mover call).", action: "write", mutates: true,
    handler: authorizations.consumeAuthorization, rest: { method: "POST", path: "/v1/entities/:entity_id/authorizations/:id/consume" }, pathParams: ["entity_id", "id"],
    mcp: "authorization_consume", cli: { namespace: "authorizations", command: "consume" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Authorization id." },
      { name: "token", type: "string", required: true, description: "The signed token issued at approval." }],
  },
  {
    op: "authorization.verify", summary: "Verify a token without consuming it (enforcement contract).", action: "read", mutates: false,
    handler: authorizations.verifyAuthorization, rest: { method: "POST", path: "/v1/entities/:entity_id/authorizations/:id/verify" }, pathParams: ["entity_id", "id"],
    mcp: "authorization_verify", cli: { namespace: "authorizations", command: "verify" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Authorization id." },
      { name: "token", type: "string", required: true, description: "The signed token to verify." }],
  },

  // ---- freezes ----
  {
    op: "freeze.create", summary: "Emergency-freeze an entity or a specific identity.", action: "freeze", mutates: true,
    handler: freezes.createFreeze, rest: { method: "POST", path: "/v1/entities/:entity_id/freezes" }, pathParams: ["entity_id"],
    mcp: "freeze_create", cli: { namespace: "freezes", command: "create" }, profiles: ["minimal", "standard", "full"],
    fields: [ENTITY, { name: "identity_id", type: "string", required: false, description: "Freeze a single identity (omit for whole entity)." },
      { name: "reason", type: "string", required: true, description: "Why the freeze was applied." }],
  },
  {
    op: "freeze.release", summary: "Release an active freeze.", action: "freeze", mutates: true,
    handler: freezes.releaseFreeze, rest: { method: "POST", path: "/v1/entities/:entity_id/freezes/:id/release" }, pathParams: ["entity_id", "id"],
    mcp: "freeze_release", cli: { namespace: "freezes", command: "release" }, profiles: ["standard", "full"],
    fields: [ENTITY, { name: "id", type: "string", required: true, description: "Freeze id." }],
  },
  {
    op: "freeze.list", summary: "List freezes for an entity.", action: "read", mutates: false,
    handler: freezes.listFreezes, rest: { method: "GET", path: "/v1/entities/:entity_id/freezes" }, pathParams: ["entity_id"],
    mcp: "freeze_list", cli: { namespace: "freezes", command: "list" }, profiles: ["standard", "full"], fields: [ENTITY],
  },
  {
    op: "freeze.status", summary: "Check whether an entity/identity is currently frozen.", action: "read", mutates: false,
    handler: freezes.freezeStatus, rest: { method: "GET", path: "/v1/entities/:entity_id/freezes/status" }, pathParams: ["entity_id"],
    mcp: "freeze_status", cli: { namespace: "freezes", command: "status" }, profiles: ["minimal", "standard", "full"],
    fields: [ENTITY, { name: "identity_id", type: "string", required: false, description: "Restrict the check to a single identity." }],
  },

  // ---- audit ----
  {
    op: "audit.list", summary: "Read the append-only money audit trail.", action: "read", mutates: false,
    handler: audit.listAudit, rest: { method: "GET", path: "/v1/entities/:entity_id/audit" }, pathParams: ["entity_id"],
    mcp: "audit_list", cli: { namespace: "audit", command: "list" }, profiles: ["standard", "full"], fields: [ENTITY],
  },
  {
    op: "audit.verify", summary: "Verify the tamper-evident audit hash chain.", action: "read", mutates: false,
    handler: audit.verifyAudit, rest: { method: "GET", path: "/v1/entities/:entity_id/audit/verify" }, pathParams: ["entity_id"],
    mcp: "audit_verify", cli: { namespace: "audit", command: "verify" }, profiles: ["standard", "full"], fields: [ENTITY],
  },
];

const BY_OP = new Map(OPERATIONS.map((o) => [o.op, o]));
const BY_MCP = new Map(OPERATIONS.map((o) => [o.mcp, o]));

export function getOperation(op: string): OperationDef | undefined {
  return BY_OP.get(op);
}

export function getOperationByMcp(name: string): OperationDef | undefined {
  return BY_MCP.get(name);
}

/** Execute an op by canonical name through the shared service layer. */
export function executeOperation(db: Database, op: string, input: Input, ctx?: AuthorizationContext): unknown {
  const def = BY_OP.get(op);
  if (!def) throw new Error(`Unknown operation: ${op}`);
  return def.handler(db, input, ctx);
}

/** Interface-parity manifest: { op, input(fields), surfaces } generated from the registry. */
export interface OperationManifestEntry {
  op: string;
  action: AuthorizationAction;
  mutates: boolean;
  input: OperationField[];
  surfaces: { cli: string; mcp: string; api: string };
}

export function operationManifest(): OperationManifestEntry[] {
  return OPERATIONS.map((o) => ({
    op: o.op,
    action: o.action,
    mutates: o.mutates,
    input: o.fields,
    surfaces: {
      cli: `controls ${o.cli.namespace} ${o.cli.command}`,
      mcp: `controls_${o.mcp}`,
      api: `${o.rest.method} ${o.rest.path}`,
    },
  }));
}
