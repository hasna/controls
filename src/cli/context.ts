import { Command } from "commander";
import { SYSTEM_AUTHORIZATION_CONTEXT, type AuthorizationContext } from "../services/authorization.js";
import { authenticateToken, toAuthorizationContext } from "../server/auth.js";
import { APP_VERSION } from "../version.js";
import { ControlsError, toErrorEnvelope } from "../types/index.js";

export const program = new Command();

export function configureProgram(): void {
  program
    .name("controls")
    .description("Spend-authorization/approval control plane: caps, allowlists, tiered approvals, SoD, freeze, immutable money audit.")
    .version(APP_VERSION)
    .enablePositionalOptions()
    .option("--json", "Emit machine-readable JSON");
}

export function jsonMode(): boolean {
  return Boolean(program.opts().json);
}

/**
 * The local CLI runs with a trusted system context (single-user local machine)
 * by DEFAULT. When a caller token is supplied (`HASNA_CONTROLS_API_TOKEN` /
 * `CONTROLS_API_TOKEN`) the CLI instead acts as that authenticated, entity-scoped
 * principal — resolved through the SAME credential stack as the serve/MCP tiers —
 * so a scoped credential is subject to identical deny-by-default scope + entity
 * authorization on the CLI surface too. A token that fails authentication is a
 * hard, fail-closed error: the CLI NEVER silently falls back to the trusted
 * system context when a (wrong/expired/revoked) token was explicitly provided,
 * which would be a privilege escalation.
 */
export function cliContext(): AuthorizationContext {
  const token = (process.env["HASNA_CONTROLS_API_TOKEN"] || process.env["CONTROLS_API_TOKEN"] || "").trim();
  if (!token) return SYSTEM_AUTHORIZATION_CONTEXT;
  const principal = authenticateToken(token);
  if (!principal) {
    const err = new ControlsError("Invalid, expired, or revoked CLI API token; refusing to fall back to the system context.");
    err.code = "UNAUTHORIZED";
    throw err;
  }
  return toAuthorizationContext(principal);
}

export function emit(value: unknown): void {
  if (jsonMode()) {
    console.log(JSON.stringify(value, null, 2));
    return;
  }
  if (typeof value === "string") {
    console.log(value);
  } else {
    console.log(JSON.stringify(value, null, 2));
  }
}

export function handleError(error: unknown): never {
  const env = toErrorEnvelope(error);
  if (jsonMode()) {
    console.log(JSON.stringify(env));
  } else {
    console.error(`${env.code}: ${env.message}${env.suggestion ? ` (${env.suggestion})` : ""}`);
  }
  process.exit(1);
}

export function snakeToCamel(name: string): string {
  return name.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}

export function snakeToKebab(name: string): string {
  return name.replace(/_/g, "-");
}
