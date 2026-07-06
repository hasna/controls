import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z, type ZodRawShape, type ZodTypeAny } from "zod";
import { ok, fail } from "../compact.js";
import { getDatabase } from "../../db/database.js";
import { OPERATIONS, type OperationDef, type OperationField } from "../../services/registry.js";
import { SYSTEM_AUTHORIZATION_CONTEXT, type AuthorizationContext } from "../../services/authorization.js";
import { requiredScopeForAction, authorizeScopeAndEntity, toAuthorizationContext, type ApiPrincipal } from "../../server/auth.js";
import { PermissionDeniedError } from "../../types/index.js";

function fieldSchema(field: OperationField): ZodTypeAny {
  let base: ZodTypeAny;
  if (field.type === "integer") base = z.number().int();
  else if (field.type === "boolean") base = z.boolean();
  else base = z.string();
  base = base.describe(field.description);
  return field.required ? base : base.optional();
}

function shapeFor(def: OperationDef): ZodRawShape {
  const shape: ZodRawShape = {};
  for (const field of def.fields) shape[field.name] = fieldSchema(field);
  return shape;
}

/**
 * Register the controls domain tools from the shared operation registry so the
 * MCP surface stays in lockstep with CLI + /v1 (interface parity, §7).
 *
 * §5.1a: MCP domain tools MUST enforce the SAME scope + entity/org authorization
 * as the /v1 routes (app.ts). The shared service layer only checks ROLES, so a
 * scope-limited credential (e.g. role defaults to `integration` but scopes are
 * `controls:read` only) would be allowed to write via MCP while /v1 denies it.
 * When a principal is present we run `authorizeScopeAndEntity` (identical to the
 * serve tier) BEFORE dispatching to the handler. Callers with no principal
 * (stdio single-user / SYSTEM) keep the bypass — parity harness drives this path.
 */
export function registerDomainTools(
  server: McpServer,
  principal: ApiPrincipal | undefined,
  shouldRegister: (name: string) => boolean,
): void {
  const ctx: AuthorizationContext = principal ? toAuthorizationContext(principal) : SYSTEM_AUTHORIZATION_CONTEXT;

  for (const def of OPERATIONS) {
    const toolName = `controls_${def.mcp}`;
    if (!shouldRegister(def.mcp)) continue;
    server.tool(toolName, def.summary, shapeFor(def), async (args: Record<string, unknown>) => {
      try {
        if (principal) {
          const entityId = typeof args["entity_id"] === "string" ? (args["entity_id"] as string) : undefined;
          const requiredScope = requiredScopeForAction(def.action);
          const authz = authorizeScopeAndEntity(principal, requiredScope, entityId);
          if (!authz.allowed) {
            return fail(new PermissionDeniedError(requiredScope, entityId));
          }
        }
        const db = getDatabase();
        const result = def.handler(db, args, ctx);
        return ok(result);
      } catch (error) {
        return fail(error);
      }
    });
  }
}
