import { PermissionDeniedError } from "../types/index.js";
import {
  allActions,
  rolePermissions,
  type AuthorizationAction,
  type AuthorizationRole,
} from "./authorization-constants.js";

/**
 * COPY-VERBATIM security stack (BUILD-SPEC §6.3 / §10.1). This file is byte-for-byte
 * IDENTICAL across all 9 apps — the ONLY per-app difference is the import above,
 * which resolves to that app's `authorization-constants.ts` (domain ACTION/ROLE
 * *names* only). The MECHANISM — deny-by-default authorize(), role→action map, and
 * STRICT entity-dimension scoping — is NOT a per-app design choice.
 *
 * STRICT deny-by-default entity scoping (§1c): an `entity_id` is an authorized
 * *reference*, never a bearer capability. Resolving or guessing an id grants
 * NOTHING. Only a `bypass` principal (the trusted internal SYSTEM context used for
 * bootstrap/migration/tests) is entity-unrestricted. A non-bypass principal with
 * NO entity/org set resolves to the EMPTY allowed set and gets NO access — we NEVER
 * return `true` (or `null`) for an unscoped principal. Admin/owner ROLES widen the
 * ACTION dimension only; they never grant cross-entity reach without an explicit
 * entity set. MCP/HTTP callers thread their OWN principal here, never SYSTEM bypass.
 */

// Re-export the domain names so downstream code imports everything from
// `./authorization.js` regardless of which app it is compiled into.
export type { AuthorizationAction, AuthorizationRole };
export { allActions, rolePermissions };

export interface AuthorizationContext {
  actor_id: string;
  roles: AuthorizationRole[];
  /** Single allowed entity id (legacy single-tenant credential). */
  entity_id?: string;
  /** The allowed entity id set — the principal's tenant boundary. */
  entity_ids?: string[];
  /** Org-style credential aliases, accepted as entity-scope ids for compatibility. */
  org_id?: string;
  org_ids?: string[];
  /**
   * SYSTEM bypass. Set ONLY by trusted internal callers (bootstrap, migration,
   * seed, unit tests) — NEVER the dispatch context of an authenticated MCP or HTTP
   * caller. A bypass principal skips entity scoping and every action gate.
   */
  bypass?: boolean;
}

export interface AuthorizationResource {
  /** The single entity the operation touches. */
  entity_id?: string;
  /** A group of entities (e.g. a consolidation run) — ALL must be allowed. */
  entity_ids?: string[];
  resource?: string;
}

/**
 * SYSTEM bypass context. Trusted internal use ONLY (migrations, seed, tests) — it
 * is NEVER the context for an authenticated transport caller, which would defeat
 * tenant isolation (BUILD-SPEC failure class 1).
 */
export const SYSTEM_AUTHORIZATION_CONTEXT: AuthorizationContext = {
  actor_id: "system",
  roles: ["system"],
  bypass: true,
};

/**
 * The principal's EXPLICIT entity allowlist (union of entity_id + entity_ids and
 * the org_id/org_ids aliases). Never widened by role. An unscoped principal yields
 * an empty set — deny-by-default.
 */
function allowedEntitySet(context: AuthorizationContext): Set<string> {
  const ids = new Set<string>();
  if (context.entity_id) ids.add(context.entity_id);
  for (const id of context.entity_ids ?? []) ids.add(id);
  if (context.org_id) ids.add(context.org_id);
  for (const id of context.org_ids ?? []) ids.add(id);
  return ids;
}

/**
 * Deny-by-default single-entity check. `bypass` is unrestricted; a resource with
 * no entity to check is not blocked by scoping; every other case requires the id
 * to be in the principal's explicit allowlist. An unscoped non-bypass principal
 * (empty allowlist) can reach NO entity.
 */
export function hasEntityAccess(context: AuthorizationContext, entityId?: string): boolean {
  if (context.bypass) return true;
  if (!entityId) return true;
  return allowedEntitySet(context).has(entityId);
}

/** Group form: the principal must be scoped to EVERY entity in the set. */
export function hasAllEntityAccess(context: AuthorizationContext, entityIds: string[]): boolean {
  return entityIds.every((id) => hasEntityAccess(context, id));
}

export function roleAllows(role: AuthorizationRole, action: AuthorizationAction): boolean {
  return rolePermissions[role].has(action);
}

/**
 * The principal's allowed entity set, or `null` when UNCONSTRAINED. ONLY the
 * bypass/SYSTEM context is unconstrained; EVERY authenticated principal is
 * constrained to its explicit allowlist. An unscoped non-bypass principal
 * therefore resolves to the EMPTY array (sees nothing) — never wildcard. This is
 * the single source of truth for entity isolation on list ops.
 */
export function allowedEntityIds(context?: AuthorizationContext): string[] | null {
  const principal = context ?? SYSTEM_AUTHORIZATION_CONTEXT;
  if (principal.bypass) return null;
  return [...allowedEntitySet(principal)];
}

/** Post-filter form: whether a principal may see a specific entity's rows. */
export function principalCanSeeEntity(entityId: string, context?: AuthorizationContext): boolean {
  const allowed = allowedEntityIds(context);
  return allowed === null || allowed.includes(entityId);
}

/**
 * SQL predicate that constrains a list query to the principal's allowed entity
 * set, so cross-entity rows are isolated BY CONSTRUCTION — not merely because a
 * caller supplied an `entity_id` filter. `null` when the principal is unconstrained.
 * A principal constrained to an empty set yields an always-false predicate so no
 * rows leak (deny-by-default).
 */
export function entityScopeFilter(
  context?: AuthorizationContext,
  column = "entity_id",
): { clause: string; params: string[] } | null {
  const allowed = allowedEntityIds(context);
  if (allowed === null) return null;
  if (allowed.length === 0) return { clause: "1 = 0", params: [] };
  return { clause: `${column} IN (${allowed.map(() => "?").join(", ")})`, params: [...allowed] };
}

/** In-memory form of entityScopeFilter for already-materialized rows. */
export function scopeToEntities<T extends { entity_id: string }>(
  rows: T[],
  context?: AuthorizationContext,
): T[] {
  const allowed = allowedEntityIds(context);
  if (allowed === null) return rows;
  const set = new Set(allowed);
  return rows.filter((row) => set.has(row.entity_id));
}

/**
 * Deny by default: BOTH the entity scope AND the action scope must pass. Throws
 * PermissionDeniedError otherwise. The SAME context flows through the /v1 serve
 * tier AND the MCP tools — MCP tools thread the CALLER principal, never a SYSTEM
 * bypass (BUILD-SPEC failure class 1).
 */
export function authorize(
  action: AuthorizationAction,
  context?: AuthorizationContext,
  resource: AuthorizationResource = {},
): void {
  const principal = context ?? SYSTEM_AUTHORIZATION_CONTEXT;
  if (!hasEntityAccess(principal, resource.entity_id)) {
    throw new PermissionDeniedError(action, resource.resource || resource.entity_id);
  }
  if (resource.entity_ids && !hasAllEntityAccess(principal, resource.entity_ids)) {
    throw new PermissionDeniedError(action, resource.resource || "entity-group");
  }
  if (principal.bypass || principal.roles.some((role) => roleAllows(role, action))) {
    return;
  }
  throw new PermissionDeniedError(action, resource.resource);
}

export function authorizeAll(
  actions: AuthorizationAction[],
  context?: AuthorizationContext,
  resource: AuthorizationResource = {},
): void {
  for (const action of actions) authorize(action, context, resource);
}

/** Union of actions the given roles grant (used to advertise a credential's scope). */
export function scopesForRoles(roles: AuthorizationRole[]): AuthorizationAction[] {
  const set = new Set<AuthorizationAction>();
  for (const role of roles) {
    for (const action of rolePermissions[role]) set.add(action);
  }
  return [...set];
}
