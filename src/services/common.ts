import { ValidationError } from "../types/index.js";
import type { AuthorizationContext } from "./authorization.js";

export type Input = Record<string, unknown>;

export function requireString(input: Input, key: string): string {
  const value = input[key];
  if (typeof value !== "string" || value.trim() === "") {
    throw new ValidationError(`Field '${key}' is required and must be a non-empty string.`);
  }
  return value.trim();
}

export function optionalString(input: Input, key: string): string | null {
  const value = input[key];
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") throw new ValidationError(`Field '${key}' must be a string.`);
  return value.trim();
}

export function requireInt(input: Input, key: string): number {
  const value = input[key];
  const n = typeof value === "string" ? Number(value) : value;
  if (typeof n !== "number" || !Number.isInteger(n)) {
    throw new ValidationError(`Field '${key}' must be an integer.`);
  }
  return n;
}

export function requirePositiveInt(input: Input, key: string): number {
  const n = requireInt(input, key);
  if (n <= 0) throw new ValidationError(`Field '${key}' must be a positive integer.`);
  return n;
}

export function optionalInt(input: Input, key: string, fallback: number): number {
  if (input[key] === undefined || input[key] === null || input[key] === "") return fallback;
  return requireInt(input, key);
}

export function requireEnum<T extends string>(input: Input, key: string, allowed: readonly T[]): T {
  const value = requireString(input, key);
  if (!(allowed as readonly string[]).includes(value)) {
    throw new ValidationError(`Field '${key}' must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

export function requireCurrency(input: Input, key = "currency"): string {
  const value = requireString(input, key).toUpperCase();
  if (!/^[A-Z]{3}$/.test(value)) throw new ValidationError(`Field '${key}' must be a 3-letter ISO currency code.`);
  return value;
}

export function optionalBool(input: Input, key: string): boolean | undefined {
  const value = input[key];
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "boolean") return value;
  if (value === "true" || value === "1") return true;
  if (value === "false" || value === "0") return false;
  throw new ValidationError(`Field '${key}' must be a boolean.`);
}

export function sqliteBool(value: boolean): number {
  return value ? 1 : 0;
}

/** Every entity-scoped op resolves + authorizes the principal against the entity (§1c). */
export function entityResource(entityId: string, resource: string): { entity_id: string; resource: string } {
  return { entity_id: entityId, resource };
}

export function actorId(ctx?: AuthorizationContext): string | null {
  return ctx?.actor_id ?? null;
}
