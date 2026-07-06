import { Hono } from "hono";
import type { Context } from "hono";
import { getDatabase } from "../db/database.js";
import { statusForCode, toErrorEnvelope } from "../types/index.js";
import { OPERATIONS, type OperationDef } from "../services/registry.js";
import { listQueryResponse } from "./list-query.js";
import {
  requiredScopeForAction,
  authenticateToken,
  authorizeScopeAndEntity,
  bearerFromHeader,
  isApiAuthConfigured,
  toAuthorizationContext,
  type ApiPrincipal,
} from "./auth.js";
import { healthPayload, readyPayload } from "./health.js";
import { authRequired, corsOrigins, rateLimitMax } from "./runtime.js";

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW = 60_000;

function checkRateLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const max = rateLimitMax();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return { allowed: true, remaining: max - 1 };
  }
  entry.count++;
  const remaining = max - entry.count;
  if (remaining < 0) return { allowed: false, remaining: 0 };
  return { allowed: true, remaining };
}

/**
 * Derive a rate-limit key from a TRUSTED source, not the raw client-supplied
 * X-Forwarded-For (which an attacker can rotate to mint a fresh bucket per
 * request, or omit to collapse into one shared bucket).
 *  1. The real socket peer address (Bun.serve exposes `server.requestIP`) — fully
 *     trusted and not client-controllable.
 *  2. Else the LAST (rightmost) XFF hop, appended by the nearest trusted proxy;
 *     the leftmost entries are client-supplied and spoofable, so never key on them.
 */
function clientKey(c: Context): string {
  const server = c.env as { requestIP?: (req: Request) => { address?: string } | null } | undefined;
  const socketAddr = server?.requestIP?.(c.req.raw)?.address;
  if (socketAddr) return socketAddr;
  const xff = c.req.header("x-forwarded-for");
  if (xff) {
    const hops = xff.split(",").map((s) => s.trim()).filter(Boolean);
    const last = hops[hops.length - 1];
    if (last) return last;
  }
  return "local";
}

function applyCors(c: Context): void {
  const origin = c.req.header("Origin");
  const allowed = corsOrigins();
  if (origin && allowed.includes(origin)) {
    c.header("Access-Control-Allow-Origin", origin);
    c.header("Vary", "Origin");
    c.header("Access-Control-Allow-Credentials", "true");
  }
  // Deny by default: never emit `*` while accepting credentials/authorization.
}

function honoPath(restPath: string): string {
  return restPath; // Hono uses :param syntax, identical to our registry paths.
}

async function buildInput(c: Context, def: OperationDef): Promise<Record<string, unknown>> {
  const input: Record<string, unknown> = {};
  for (const p of def.pathParams) input[p] = c.req.param(p);
  if (def.rest.method === "GET" || def.rest.method === "DELETE") {
    const url = new URL(c.req.url);
    for (const [k, v] of url.searchParams.entries()) {
      if (!(k in input)) input[k] = v;
    }
  } else {
    let body: unknown = {};
    try {
      body = await c.req.json();
    } catch {
      body = {};
    }
    if (body && typeof body === "object") Object.assign(input, body);
  }
  return input;
}

function errorJson(c: Context, error: unknown) {
  const env = toErrorEnvelope(error);
  return c.json(env, statusForCode(env.code) as never);
}

function authenticate(c: Context): { principal: ApiPrincipal | null; unauthorizedOpen: boolean } {
  const configured = isApiAuthConfigured();
  const token = bearerFromHeader(c.req.header("Authorization"));
  const principal = authenticateToken(token);
  // Unauthenticated open access is allowed only when auth is not required and not configured.
  const unauthorizedOpen = !authRequired() && !configured;
  return { principal, unauthorizedOpen };
}

export function createApp(): Hono {
  const app = new Hono();

  app.options("/*", (c) => {
    applyCors(c);
    const allowed = corsOrigins();
    const origin = c.req.header("Origin");
    if (origin && allowed.includes(origin)) {
      c.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
      c.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
      c.header("Access-Control-Max-Age", "86400");
    }
    return c.body(null, 204);
  });

  // Rate limit + CORS for every request.
  app.use("/*", async (c, next) => {
    applyCors(c);
    const ip = clientKey(c);
    const rl = checkRateLimit(ip);
    if (!rl.allowed) return c.json({ code: "RATE_LIMITED", message: "Too many requests", suggestion: "Slow down and retry." }, 429);
    await next();
    c.header("X-RateLimit-Remaining", String(rl.remaining));
  });

  // System endpoints (§6.2) — unauthenticated, minimal.
  app.get("/health", (c) => c.json(healthPayload()));
  app.get("/version", (c) => c.json(healthPayload()));
  app.get("/ready", (c) => {
    const { ready, body } = readyPayload();
    return c.json(body, ready ? 200 : 503);
  });

  // Generate one /v1 route per registry operation (guarantees interface parity).
  for (const def of OPERATIONS) {
    const method = def.rest.method.toLowerCase() as "get" | "post" | "patch" | "delete";
    app[method](honoPath(def.rest.path), async (c) => {
      try {
        const { principal, unauthorizedOpen } = authenticate(c);
        if (!principal && !unauthorizedOpen) {
          return c.json({ code: "UNAUTHORIZED", message: "Invalid or missing API credential.", suggestion: "Send Authorization: Bearer <token>." }, 401);
        }
        const entityId = c.req.param("entity_id");
        if (principal) {
          const authz = authorizeScopeAndEntity(principal, requiredScopeForAction(def.action), entityId);
          if (!authz.allowed) {
            return c.json({ code: authz.code, message: authz.message, suggestion: "Use a credential with the required scope + entity access." }, authz.status as never);
          }
        }
        const input = await buildInput(c, def);
        const ctx = principal ? toAuthorizationContext(principal) : undefined;
        const db = getDatabase();
        const result = def.handler(db, input, ctx);
        if (!def.mutates && Array.isArray(result)) {
          const url = new URL(c.req.url);
          return c.json(listQueryResponse(url, result as object[], { default_sort: "created_at", allowed_sorts: ["created_at", "id"] }) as never);
        }
        return c.json(result as never);
      } catch (error) {
        return errorJson(c, error);
      }
    });
  }

  app.notFound((c) => c.json({ code: "NOT_FOUND", message: `No route: ${c.req.method} ${new URL(c.req.url).pathname}`, suggestion: "Check the API path." }, 404));

  return app;
}
