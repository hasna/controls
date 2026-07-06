import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import type { AuthorizationAction, AuthorizationContext, AuthorizationRole } from "../services/authorization.js";

/**
 * Serve/MCP credential + scope stack. Mechanism copied verbatim from the
 * reference security model (timing-safe bearer compare, ApiCredentialConfig with
 * scopes/roles/org scoping/expiry/revocation, role->scope map). Only the SCOPE
 * NAMES are parameterized to the controls domain. Deny-by-default (§6.3/§10.1).
 */
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
export type ApiCredentialType = "api_key" | "user" | "session";

export interface ApiCredentialConfig {
  id: string;
  token?: string;
  key?: string;
  type?: ApiCredentialType;
  actor_id?: string;
  roles?: AuthorizationRole[];
  scopes?: ApiScope[];
  org_id?: string;
  org_ids?: string[];
  entity_ids?: string[];
  expires_at?: string;
  revoked?: boolean;
}

export interface ApiPrincipal extends AuthorizationContext {
  credential_id: string;
  credential_type: ApiCredentialType;
  scopes: ApiScope[];
  entity_ids?: string[];
}

const allScopes = [...apiScopes];
const knownScopes = new Set<ApiScope>(allScopes);
const knownRoles = new Set<AuthorizationRole>([
  "system",
  "owner",
  "admin",
  "requestor",
  "approver",
  "security",
  "auditor",
  "integration",
]);

const roleScopes: Record<AuthorizationRole, ApiScope[]> = {
  system: allScopes,
  owner: allScopes,
  admin: allScopes,
  requestor: ["controls:read", "controls:write"],
  approver: ["controls:read", "controls:approve"],
  security: ["controls:read", "controls:freeze"],
  auditor: ["controls:read", "controls:export"],
  integration: ["controls:read", "controls:write", "controls:export"],
};

/** Map a domain action to the serve/MCP scope that guards it. */
export const ACTION_SCOPE: Record<AuthorizationAction, ApiScope> = {
  read: "controls:read",
  write: "controls:write",
  approve: "controls:approve",
  freeze: "controls:freeze",
  export: "controls:export",
  admin: "controls:admin",
};

export function scopesForRoles(roles: AuthorizationRole[]): ApiScope[] {
  return Array.from(new Set(roles.flatMap((role) => roleScopes[role] || [])));
}

export function getLegacyApiKey(): string {
  return process.env["HASNA_CONTROLS_API_KEY"] || process.env["CONTROLS_API_KEY"] || "";
}

export function isApiAuthConfigured(): boolean {
  return Boolean(getLegacyApiKey() || process.env["HASNA_CONTROLS_API_CREDENTIALS"] || process.env["CONTROLS_API_CREDENTIALS"]);
}

export function configuredApiCredentials(): ApiCredentialConfig[] {
  const raw = process.env["HASNA_CONTROLS_API_CREDENTIALS"] || process.env["CONTROLS_API_CREDENTIALS"];
  if (!raw) return [];
  let parsed: ApiCredentialConfig[] | ApiCredentialConfig;
  try {
    parsed = JSON.parse(raw) as ApiCredentialConfig[] | ApiCredentialConfig;
  } catch {
    return [];
  }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  return list.filter((cred) => Boolean((cred.token || cred.key) && cred.id));
}

/** Authenticate a bearer token to a principal, or null. */
export function authenticateToken(token: string | null | undefined): ApiPrincipal | null {
  if (!token) return null;

  const legacyKey = getLegacyApiKey();
  if (legacyKey && safeEqual(token, legacyKey)) {
    return {
      actor_id: "legacy-api-key",
      credential_id: "legacy-api-key",
      credential_type: "api_key",
      roles: ["owner"],
      scopes: allScopes,
    };
  }

  for (const credential of configuredApiCredentials()) {
    const secret = credential.token || credential.key || "";
    if (!safeEqual(token, secret) || credential.revoked || isExpired(credential.expires_at)) continue;
    const roles = normalizeRoles(credential.roles);
    const scopes = normalizeScopes(credential.scopes) || scopesForRoles(roles);
    const orgIds = mergeOrgIds(credential);
    return {
      actor_id: credential.actor_id || `${credential.type || "api_key"}:${credential.id}`,
      credential_id: credential.id,
      credential_type: credential.type || "api_key",
      roles,
      scopes,
      org_id: credential.org_id,
      org_ids: orgIds,
      entity_ids: credential.entity_ids,
    };
  }

  return null;
}

export function bearerFromHeader(header: string | null | undefined): string {
  const auth = header || "";
  if (!auth) return "";
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : auth.trim();
}

export interface AuthzResult {
  allowed: boolean;
  status?: number;
  code?: "UNAUTHORIZED" | "PERMISSION_DENIED";
  message?: string;
  required_scope?: ApiScope;
}

/**
 * Enforce a required scope + entity/org access for an authenticated principal.
 * Deny-by-default; knowing an entity_id grants nothing without matching access.
 */
export function authorizeScopeAndEntity(principal: ApiPrincipal, requiredScope: ApiScope, entityId?: string): AuthzResult {
  if (!principal.scopes.includes(requiredScope)) {
    return { allowed: false, status: 403, code: "PERMISSION_DENIED", message: `Credential lacks required scope: ${requiredScope}.`, required_scope: requiredScope };
  }
  if (entityId && !hasEntityAccess(principal, entityId)) {
    return { allowed: false, status: 403, code: "PERMISSION_DENIED", message: "Credential is not scoped to this entity." };
  }
  return { allowed: true };
}

export function hasEntityAccess(principal: ApiPrincipal, entityId: string): boolean {
  if (principal.bypass) return true;
  if (principal.org_id && principal.org_id === entityId) return true;
  if (principal.org_ids && principal.org_ids.includes(entityId)) return true;
  if (principal.entity_ids && principal.entity_ids.includes(entityId)) return true;
  // STRICT deny-by-default (§1c): knowing an entity_id grants nothing. An
  // authenticated (non-bypass) principal with NO explicit entity/org set reaches
  // NO entity — never a wildcard. Only the SYSTEM bypass is entity-unrestricted.
  return false;
}

/** Build the AuthorizationContext the service layer consumes (entity scoping via org_ids). */
export function toAuthorizationContext(principal: ApiPrincipal): AuthorizationContext {
  const orgIds = mergePrincipalScopeIds(principal);
  return {
    actor_id: principal.actor_id,
    roles: principal.roles,
    ...(principal.org_id ? { org_id: principal.org_id } : {}),
    ...(orgIds.length > 0 ? { org_ids: orgIds } : {}),
  };
}

function mergePrincipalScopeIds(principal: ApiPrincipal): string[] {
  return Array.from(new Set([...(principal.org_ids ?? []), ...(principal.entity_ids ?? [])]));
}

function mergeOrgIds(credential: ApiCredentialConfig): string[] | undefined {
  const ids = Array.from(new Set([...(credential.org_ids ?? []), ...(credential.entity_ids ?? [])]));
  return ids.length > 0 ? ids : undefined;
}

function normalizeRoles(roles: AuthorizationRole[] = ["integration"]): AuthorizationRole[] {
  const normalized = roles.filter((role) => knownRoles.has(role));
  return normalized.length > 0 ? Array.from(new Set(normalized)) : ["integration"];
}

function normalizeScopes(scopes?: ApiScope[]): ApiScope[] | null {
  if (!scopes) return null;
  return Array.from(new Set(scopes.filter((scope) => knownScopes.has(scope))));
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function isExpired(expiresAt?: string): boolean {
  return Boolean(expiresAt && Date.parse(expiresAt) <= Date.now());
}
