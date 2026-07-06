import { resolveStorageMode } from "../config.js";

export function getPort(): number {
  const raw = process.env["HASNA_CONTROLS_PORT"] || process.env["CONTROLS_PORT"];
  const n = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 3482;
}

export function getBindHost(): string {
  return process.env["HASNA_CONTROLS_BIND_HOST"] || process.env["CONTROLS_BIND_HOST"] || "127.0.0.1";
}

export function isLoopbackBind(host = getBindHost()): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

export function corsOrigins(): string[] {
  const raw = process.env["HASNA_CONTROLS_CORS_ORIGINS"] || process.env["CONTROLS_CORS_ORIGINS"] || "";
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

export function rateLimitMax(): number {
  const raw = process.env["HASNA_CONTROLS_RATE_LIMIT"] || process.env["CONTROLS_RATE_LIMIT"];
  const n = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 120;
}

/**
 * Auth is decoupled from storage mode (§6.3). Unauthenticated /v1 is permitted
 * ONLY when bound strictly to loopback AND mode is local. Any non-loopback bind
 * or cloud mode requires auth (fail-closed).
 */
export function authRequired(): boolean {
  if (!isLoopbackBind()) return true;
  return resolveStorageMode() === "cloud";
}

/** Fail-closed startup guard: non-loopback / cloud with no credentials configured. */
export function assertServeSafe(authConfigured: boolean): void {
  if (authRequired() && !authConfigured) {
    throw new Error(
      "Refusing to start: serve is bound to a non-loopback interface or cloud mode without API credentials. " +
        "Set HASNA_CONTROLS_API_CREDENTIALS (or HASNA_CONTROLS_API_KEY) before serving /v1.",
    );
  }
}
