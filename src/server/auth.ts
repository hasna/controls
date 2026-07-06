import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import type { AuthorizationContext, AuthorizationRole } from "../services/authorization.js";
import { hasEntityAccess } from "../services/authorization.js";
import { AUTH_CONSTANTS, apiScopes } from "./auth-constants.js";
import type { ApiScope } from "./auth-constants.js";

/**
 * CANONICAL transport credential module — identical across all 9 Hasna internal
 * apps. The MECHANISM (timing-safe bearer compare, expiry, revocation, STRICT
 * deny-by-default entity scoping, and the rule that a network credential can
 * NEVER escalate to a SYSTEM bypass) is NOT a per-app design choice.
 *
 * The ONLY per-app difference is the imported `./auth-constants.js`, which
 * carries the domain scope/role NAMES (apiScopes, knownRoles, roleScopes,
 * actionScope), the env-var names, and an OPTIONAL `verifyToken` hook (provided
 * only by the token-issuer app). This file is otherwise byte-identical.
 *
 * ONE shared authenticate path (`authenticateToken` / `authenticateApiRequest`)
 * is the SOLE credential resolver for BOTH the /v1 serve tier AND the MCP HTTP
 * transport, so the identical credential set is honored on both surfaces. It
 * resolves, in order: the single static legacy API key (a trusted bootstrap
 * principal, `owner` ROLE but NEVER a bypass), an env-configured serve
 * credential, then — if the app is a token issuer — a signed bearer token whose
 * OWN scopes/entity_ids are its sole authority (it carries no roles).
 */

export type { ApiScope };
export { apiScopes };

export type ApiCredentialType = "api_key" | "user" | "session" | "service";

export interface ApiCredentialConfig {
  id: string;
  token?: string;
  key?: string;
  type?: ApiCredentialType;
  actor_id?: string;
  roles?: AuthorizationRole[];
  scopes?: ApiScope[];
  /** CANONICAL entity dimension. */
  entity_id?: string;
  entity_ids?: string[];
  /**
   * DEPRECATED org-dimension aliases, still accepted and folded into the
   * principal's `entity_ids` for drop-in compatibility with older credential
   * blobs. New credentials should use entity_id/entity_ids only.
   */
  org_id?: string;
  org_ids?: string[];
  expires_at?: string;
  revoked?: boolean;
}

/**
 * CANONICAL principal shape. Extends the shared AuthorizationContext (actor_id,
 * roles, entity_id/entity_ids, bypass) and adds the credential identity + the
 * resolved API scopes. Entity dimension only — the org_* aliases are collapsed
 * into `entity_ids` at authentication time.
 */
export interface ApiPrincipal extends AuthorizationContext {
  credential_id: string;
  credential_type: ApiCredentialType;
  scopes: ApiScope[];
  /**
   * SYSTEM bypass — grants unrestricted entity access, mirroring the CLI's
   * local-owner context. It is set ONLY by the in-process `localOwnerPrincipal`
   * (stdio / auth-off loopback dev); it is NEVER derived from a caller-supplied
   * credential (`authenticateToken` never sets it), so a bearer token can never
   * escalate to a bypass.
   */
  bypass?: boolean;
}

export interface ApiAuthResult {
  allowed: boolean;
  status?: number;
  code?: "UNAUTHORIZED" | "PERMISSION_DENIED";
  message?: string;
  /** Single required scope (principal-level `authorizeScopeAndEntity`). */
  required_scope?: ApiScope;
  /** Required scope set (request-level `authorizeApiRequest`). */
  required_scopes?: ApiScope[];
  principal?: ApiPrincipal;
}

const allScopes = [...AUTH_CONSTANTS.apiScopes];
const knownScopes = new Set<ApiScope>(allScopes);
const knownRoles = new Set<AuthorizationRole>(AUTH_CONSTANTS.knownRoles);
const roleScopes = AUTH_CONSTANTS.roleScopes;

/** Map an authorization action to its required API scope (deny-by-default fallback). */
export const actionScope: Record<string, ApiScope> = AUTH_CONSTANTS.actionScope;
/** Back-compat UPPER_SNAKE alias (controls). */
export const ACTION_SCOPE = actionScope;

export function requiredScopeForAction(action: string): ApiScope {
  return actionScope[action] ?? AUTH_CONSTANTS.defaultAction;
}
/** Back-compat alias (workforce). */
export const scopeForAction = requiredScopeForAction;

/** Roles → API scopes (union). Names are per-app; the mechanism is shared. */
export function scopesForRoles(roles: AuthorizationRole[]): ApiScope[] {
  return Array.from(new Set(roles.flatMap((role) => roleScopes[role] || [])));
}
/** Back-compat alias (entities). */
export const apiScopesForRoles = scopesForRoles;

/** First non-empty configured legacy API key across the app's env-var names. */
export function legacyApiKey(): string | undefined {
  for (const name of AUTH_CONSTANTS.env.apiKey) {
    const value = process.env[name]?.trim();
    if (value) return value;
  }
  return undefined;
}
/** Back-compat alias (access). */
export const getApiKey = legacyApiKey;

function credentialsRaw(): string | undefined {
  for (const name of AUTH_CONSTANTS.env.credentials) {
    const value = process.env[name];
    if (value) return value;
  }
  return undefined;
}

export function isApiAuthConfigured(): boolean {
  return Boolean(legacyApiKey() || credentialsRaw());
}

export function configuredApiCredentials(): ApiCredentialConfig[] {
  const raw = credentialsRaw();
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

/**
 * Extract a bearer token from an Authorization header value OR a Request. Accepts
 * both shapes so it is drop-in for `bearerToken(header)` and `bearerToken(req)`.
 */
export function bearerToken(input: string | null | undefined | Request): string {
  const header =
    typeof input === "object" && input !== null && "headers" in input
      ? input.headers.get("Authorization")
      : (input as string | null | undefined);
  const auth = (header || "").trim();
  if (!auth) return "";
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : auth;
}
/** Back-compat alias (controls, billing). */
export const bearerFromHeader = bearerToken;

/** Collapse a credential's entity/org dimensions into a single entity_ids set. */
function credentialEntityIds(credential: ApiCredentialConfig): string[] | undefined {
  const ids = new Set<string>();
  if (credential.entity_id) ids.add(credential.entity_id);
  for (const id of credential.entity_ids ?? []) ids.add(id);
  if (credential.org_id) ids.add(credential.org_id);
  for (const id of credential.org_ids ?? []) ids.add(id);
  return ids.size > 0 ? [...ids] : undefined;
}

/**
 * Authenticate a raw bearer token to a principal, honoring expiry + revocation.
 * NEVER sets `bypass` — a network-presented credential cannot escalate to the
 * entity-unrestricted SYSTEM context.
 */
export function authenticateToken(token: string): ApiPrincipal | null {
  if (!token) return null;

  const legacy = legacyApiKey();
  if (legacy && safeEqual(token, legacy)) {
    // The single static operator key maps to the `owner` ROLE (full ACTION set),
    // but it is NEVER a SYSTEM bypass: the strict deny-by-default entity gate
    // still applies. Scope it via <APP>_API_CREDENTIALS/entity_ids for
    // cross-entity operator reach.
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
    const entity_ids = credentialEntityIds(credential);
    return {
      actor_id: credential.actor_id || `${credential.type || "api_key"}:${credential.id}`,
      credential_id: credential.id,
      credential_type: credential.type || "api_key",
      roles,
      scopes,
      ...(entity_ids ? { entity_ids } : {}),
    };
  }

  // Token-issuer apps (e.g. access) verify their own signed bearer tokens
  // (header.payload.signature). The SAME credential is honored on the MCP
  // transport, unifying both surfaces on one authenticate path. The token
  // carries NO roles: its own scopes + entity_ids are the sole authority. Only
  // token-shaped strings touch the token store, so opaque serve keys never do.
  const verify = AUTH_CONSTANTS.verifyToken;
  if (verify && token.split(".").length === 3) {
    try {
      const verified = verify(token);
      return {
        actor_id: verified.identity_id,
        credential_id: verified.jti,
        credential_type: "session",
        roles: [],
        scopes: normalizeScopes(verified.scopes as ApiScope[]) ?? [],
        ...(verified.entity_ids ? { entity_ids: verified.entity_ids } : {}),
      };
    } catch {
      return null;
    }
  }

  return null;
}
/** Back-compat alias (entities, holdings). */
export const authenticateBearer = authenticateToken;

export function authenticateApiRequest(req: Request): ApiPrincipal | null {
  return authenticateToken(bearerToken(req.headers.get("Authorization")));
}
/** Back-compat alias (consolidations, entities). */
export const authenticateRequest = authenticateApiRequest;

/**
 * The in-process local-owner principal (CLI / stdio / auth-off loopback dev).
 * This is the ONLY principal that carries `bypass: true`; it is never produced
 * from a network credential.
 */
export function localOwnerPrincipal(): ApiPrincipal {
  return {
    actor_id: "local-owner",
    credential_id: "local-owner",
    credential_type: "api_key",
    roles: ["owner"],
    scopes: allScopes,
    bypass: true,
  };
}

export function principalHasScope(principal: ApiPrincipal, scope: ApiScope): boolean {
  return principal.scopes.includes(scope);
}

/**
 * Bridge an authenticated principal to the shared authorization context. Threads
 * the principal's scopes so the service layer honors scope-based grants (for a
 * token/serve credential that carries scopes but no roles) identically on the
 * /v1 and MCP paths. `bypass` is propagated ONLY when already set by
 * `localOwnerPrincipal` — a network principal always carries `bypass: false`.
 */
export function toAuthorizationContext(
  principal: ApiPrincipal,
): AuthorizationContext & { scopes?: ApiScope[] } {
  return {
    actor_id: principal.actor_id,
    roles: principal.roles,
    scopes: principal.scopes,
    ...(principal.entity_ids ? { entity_ids: principal.entity_ids } : {}),
    ...(principal.bypass ? { bypass: true } : {}),
  };
}
/** Back-compat aliases (access: principalToContext, entities: principalContext). */
export const principalToContext = toAuthorizationContext;
export const principalContext = toAuthorizationContext;

/**
 * Request-level gate: authenticate + require a scope set + (optional) entity.
 * Deny-by-default. Used by apps that gate at the HTTP layer (access).
 */
export function authorizeApiRequest(
  req: Request,
  requirement: { public?: boolean; scopes: ApiScope[]; entity_id?: string },
): ApiAuthResult {
  if (requirement.public) return { allowed: true };
  if (!isApiAuthConfigured()) {
    // Permitted ONLY when bound strictly to loopback in local mode; app.ts
    // enforces the fail-closed non-loopback / cloud guard at startup.
    return { allowed: true };
  }

  const principal = authenticateApiRequest(req);
  if (!principal) {
    return { allowed: false, status: 401, code: "UNAUTHORIZED", message: "Invalid or missing API credential." };
  }
  // STRICT deny-by-default entity gate — reuses the canonical primitive so it
  // cannot drift. A non-bypass principal with no entity set reaches NO entity.
  if (requirement.entity_id && !hasEntityAccess(principal, requirement.entity_id)) {
    return { allowed: false, status: 403, code: "PERMISSION_DENIED", message: "Credential is not scoped to this entity." };
  }
  const missing = requirement.scopes.filter((scope) => !principal.scopes.includes(scope));
  if (missing.length > 0) {
    return {
      allowed: false,
      status: 403,
      code: "PERMISSION_DENIED",
      message: `Credential lacks required scope: ${missing.join(", ")}.`,
      required_scopes: requirement.scopes,
    };
  }
  return { allowed: true, principal };
}

/**
 * Principal-level gate: require a single scope + (optional) entity access for an
 * already-authenticated principal. Deny-by-default; knowing an entity_id grants
 * nothing without matching access.
 */
export function authorizeScopeAndEntity(
  principal: ApiPrincipal,
  requiredScope: ApiScope,
  entityId?: string,
): ApiAuthResult {
  if (!principal.scopes.includes(requiredScope)) {
    return {
      allowed: false,
      status: 403,
      code: "PERMISSION_DENIED",
      message: `Credential lacks required scope: ${requiredScope}.`,
      required_scope: requiredScope,
    };
  }
  if (entityId && !hasEntityAccess(principal, entityId)) {
    return { allowed: false, status: 403, code: "PERMISSION_DENIED", message: "Credential is not scoped to this entity." };
  }
  return { allowed: true, principal };
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
