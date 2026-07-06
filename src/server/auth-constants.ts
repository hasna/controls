import type { AuthorizationRole } from "../services/authorization.js";

export const apiScopes = [
  "controls:read",
  "controls:write",
  "controls:approve",
  "controls:freeze",
  "controls:export",
  "controls:admin",
  "storage:admin",
] as const;
export type ApiScope = (typeof apiScopes)[number];

export interface AuthConstants {
  apiScopes: readonly ApiScope[];
  knownRoles: AuthorizationRole[];
  roleScopes: Record<AuthorizationRole, ApiScope[]>;
  actionScope: Record<string, ApiScope>;
  defaultAction: ApiScope;
  env: { apiKey: string[]; credentials: string[] };
  verifyToken?: (token: string) => {
    identity_id: string;
    jti: string;
    scopes: string[];
    entity_ids?: string[];
  };
}

const allScopes = [...apiScopes];
export const AUTH_CONSTANTS: AuthConstants = {
  apiScopes,
  knownRoles: ["system", "owner", "admin", "requestor", "approver", "security", "auditor", "integration"],
  roleScopes: {
    system: allScopes,
    owner: allScopes,
    admin: allScopes,
    requestor: ["controls:read", "controls:write"],
    approver: ["controls:read", "controls:approve"],
    security: ["controls:read", "controls:freeze"],
    auditor: ["controls:read", "controls:export"],
    integration: ["controls:read", "controls:write", "controls:export"],
  },
  actionScope: {
    read: "controls:read",
    write: "controls:write",
    approve: "controls:approve",
    freeze: "controls:freeze",
    export: "controls:export",
    admin: "controls:admin",
  },
  defaultAction: "controls:admin",
  env: {
    apiKey: ["HASNA_CONTROLS_API_KEY", "CONTROLS_API_KEY"],
    credentials: ["HASNA_CONTROLS_API_CREDENTIALS", "CONTROLS_API_CREDENTIALS"],
  },
};
