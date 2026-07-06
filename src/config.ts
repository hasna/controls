import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Canonical Hasna Service Contract v1 storage config for @hasna/controls.
 *
 * Runtime storage modes are `local | cloud` ONLY (Amendment A1, PURE REMOTE):
 *   - local: SQLite at ~/.hasna/controls/controls.db is authoritative.
 *   - cloud: reads AND writes go directly to the app-owned cloud Postgres.
 *
 * The legacy words `remote`, `hybrid`, and `self_hosted` are accepted only as
 * deprecated aliases that normalize to `cloud`.
 *
 * The app NEVER reads a secret VALUE to choose a mode — only the *presence* of
 * a DATABASE_URL / secret-ref. See §2.3/§2.4 of the build spec.
 */
export const APP_NAME = "controls";
export const ENV_TOKEN = "CONTROLS";

export type StorageMode = "local" | "cloud";

const DEPRECATED_CLOUD_ALIASES = new Set(["remote", "hybrid", "self_hosted"]);

const MODE_KEYS = [`HASNA_${ENV_TOKEN}_STORAGE_MODE`, `${ENV_TOKEN}_STORAGE_MODE`] as const;
const DB_URL_KEYS = [`HASNA_${ENV_TOKEN}_DATABASE_URL`, `${ENV_TOKEN}_DATABASE_URL`] as const;
const DB_URL_FILE_KEYS = [`HASNA_${ENV_TOKEN}_DATABASE_URL_FILE`] as const;
const DB_PATH_KEYS = [`HASNA_${ENV_TOKEN}_DB_PATH`, `${ENV_TOKEN}_DB_PATH`] as const;

export const DATABASE_URL_SECRET_REF = `hasna/oss/${APP_NAME}/database-url`;

type Env = Record<string, string | undefined>;

function firstEnv(env: Env, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return value;
  }
  return undefined;
}

/** Resolve the storage mode from the environment; defaults to `local`. */
export function resolveStorageMode(env: Env = process.env): StorageMode {
  const raw = firstEnv(env, MODE_KEYS);
  const mode = normalizeMode(raw);
  // Fail-closed misconfig guard (§2.3): a DATABASE_URL present while mode
  // resolves to `local` is almost certainly a mis-deploy that would silently
  // write to SQLite while a cloud DB is configured. Treat it as a hard error.
  if (mode === "local" && databaseUrlPresent(env)) {
    throw new Error(
      `Storage misconfiguration: a ${ENV_TOKEN} DATABASE_URL is present but mode resolved to 'local'. ` +
        `Set HASNA_${ENV_TOKEN}_STORAGE_MODE=cloud, or unset the DATABASE_URL for local mode.`,
    );
  }
  return mode;
}

function normalizeMode(raw: string | undefined): StorageMode {
  if (!raw) return "local";
  const normalized = raw.toLowerCase().replace(/-/g, "_");
  if (normalized === "local") return "local";
  if (normalized === "cloud" || DEPRECATED_CLOUD_ALIASES.has(normalized)) {
    if (DEPRECATED_CLOUD_ALIASES.has(normalized)) {
      console.warn(`[controls] storage mode '${raw}' is a deprecated alias; normalizing to 'cloud'.`);
    }
    return "cloud";
  }
  throw new Error(`Unknown storage mode: ${raw}. Use local or cloud.`);
}

/**
 * Whether a cloud database URL is present (presence only — the value is never
 * inspected to choose a mode). Presence is signalled by a `*_DATABASE_URL_FILE`
 * path, an inline `*_DATABASE_URL` env var, or a reachable secret-ref mount.
 */
export function databaseUrlPresent(env: Env = process.env): boolean {
  if (firstEnv(env, DB_URL_FILE_KEYS) !== undefined) return true;
  if (firstEnv(env, DB_URL_KEYS) !== undefined) return true;
  return false;
}

/**
 * Resolve the cloud DSN at startup (§2.4). Order:
 *   1. `HASNA_CONTROLS_DATABASE_URL_FILE` (a 0400 path),
 *   2. inline `HASNA_CONTROLS_DATABASE_URL` (local/dev only),
 * The secret-ref (`hasna/oss/controls/database-url`) is fetched by the runtime
 * task role out-of-band and surfaced as the FILE path in production.
 */
export function resolveDatabaseUrl(env: Env = process.env): string | undefined {
  const filePath = firstEnv(env, DB_URL_FILE_KEYS);
  if (filePath && existsSync(filePath)) {
    return readFileSync(filePath, "utf-8").trim();
  }
  return firstEnv(env, DB_URL_KEYS);
}

/**
 * Scrub the inline DSN from process.env after the store has connected so that
 * child processes and later introspection (`/proc/<pid>/environ`) cannot read
 * it. The FILE path is a 0400 mount and is left intact.
 */
export function scrubDatabaseUrl(env: Env = process.env): void {
  for (const key of DB_URL_KEYS) {
    if (env[key] !== undefined) delete env[key];
  }
}

/** Canonical local SQLite path: ~/.hasna/controls/controls.db */
export function defaultSqlitePath(): string {
  return join(homedir(), ".hasna", APP_NAME, `${APP_NAME}.db`);
}

/** Resolve the SQLite path, honoring the HASNA_CONTROLS_DB_PATH override (tests). */
export function resolveDbPath(env: Env = process.env): string {
  return firstEnv(env, DB_PATH_KEYS) ?? defaultSqlitePath();
}
