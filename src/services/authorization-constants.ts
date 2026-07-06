/**
 * Per-app domain NAMES for the copy-verbatim authorization stack (BUILD-SPEC
 * §6.3 / §10.1). This is the ONLY file that differs between apps; `authorization.ts`
 * is byte-identical across the cohort and imports these four members. Controls
 * swaps in the money/SoD actions (approve/freeze) and its requestor/approver/
 * security roles. The three reserved roles system|owner|admin MUST be present
 * (SYSTEM_AUTHORIZATION_CONTEXT hardcodes roles:["system"]; roleAllows/scopesForRoles
 * index rolePermissions by role).
 */
export type AuthorizationAction = "read" | "write" | "approve" | "freeze" | "export" | "admin";

export type AuthorizationRole =
  | "system"
  | "owner"
  | "admin"
  | "requestor"
  | "approver"
  | "security"
  | "auditor"
  | "integration";

export const allActions: AuthorizationAction[] = ["read", "write", "approve", "freeze", "export", "admin"];

export const rolePermissions: Record<AuthorizationRole, Set<AuthorizationAction>> = {
  system: new Set(allActions),
  owner: new Set(allActions),
  admin: new Set(allActions),
  requestor: new Set<AuthorizationAction>(["read", "write"]),
  approver: new Set<AuthorizationAction>(["read", "approve"]),
  security: new Set<AuthorizationAction>(["read", "freeze"]),
  auditor: new Set<AuthorizationAction>(["read", "export"]),
  integration: new Set<AuthorizationAction>(["read", "write", "export"]),
};
