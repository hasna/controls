import { createHmac, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";
import { resolveStorageMode } from "../config.js";
import type { Authorization } from "../types/index.js";

/**
 * Single-use money-authorization token signing. The token is an HMAC-SHA256 over
 * the immutable, money-relevant fields of an authorization, so a mover
 * (wallets/payments) can verify the token is bound to a specific
 * amount/currency/counterparty/entity and was issued by controls.
 */
const LOCAL_DEV_SECRET = "controls-local-dev-signing-secret";

function secret(): string {
  const configured = process.env["HASNA_CONTROLS_TOKEN_SECRET"] || process.env["CONTROLS_TOKEN_SECRET"];
  if (configured) return configured;
  // Fail-closed: never sign real money-authorization tokens with a source-visible
  // default secret outside local dev. In cloud mode a real secret is REQUIRED —
  // otherwise anyone who knows the open-source default plus an authorization's
  // non-secret fields could forge a valid single-use token.
  if (resolveStorageMode() === "cloud") {
    throw new Error(
      "controls: HASNA_CONTROLS_TOKEN_SECRET (or CONTROLS_TOKEN_SECRET) must be set in cloud mode. " +
        "Refusing to sign money-authorization tokens with the built-in local-dev default secret.",
    );
  }
  return LOCAL_DEV_SECRET;
}

function payload(auth: Pick<Authorization, "id" | "entity_id" | "amount" | "currency" | "counterparty_id" | "requestor_id">): string {
  return [auth.id, auth.entity_id, String(auth.amount), auth.currency, auth.counterparty_id, auth.requestor_id].join("|");
}

export function signAuthorizationToken(
  auth: Pick<Authorization, "id" | "entity_id" | "amount" | "currency" | "counterparty_id" | "requestor_id">,
): string {
  return createHmac("sha256", secret()).update(payload(auth)).digest("hex");
}

export function verifyAuthorizationToken(
  auth: Pick<Authorization, "id" | "entity_id" | "amount" | "currency" | "counterparty_id" | "requestor_id">,
  token: string,
): boolean {
  const expected = signAuthorizationToken(auth);
  const a = Buffer.from(expected);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}
