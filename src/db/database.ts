import { Database } from "bun:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { resolveDatabaseUrl, resolveDbPath, resolveStorageMode, scrubDatabaseUrl } from "../config.js";
import { ensureControlsAppHome } from "../core/app-home.js";
import { applySchema } from "./schema.js";
import { currentMigrationId, MIGRATION_PLAN } from "./migration-plan.js";
import { backupDatabaseBeforeMigration } from "./backup.js";

export { backupDatabaseBeforeMigration, listDatabaseBackups } from "./backup.js";

let _db: Database | null = null;

function ensureDir(filePath: string): void {
  const dir = dirname(resolve(filePath));
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/**
 * Open (and cache) the app database.
 *
 * - local: bun:sqlite at the resolved path (or ":memory:" for tests), with
 *   WAL + foreign_keys ON, idempotent schema, and the schema_migrations ledger.
 * - cloud: PURE REMOTE — reads/writes go to cloud Postgres via the vendored
 *   storage-kit (dynamically imported so the SQLite bundle never links pg). The
 *   DSN is fetched then scrubbed from the environment (§2.4).
 *
 * `getDatabase()` returns the local SQLite handle used by the domain services.
 * Cloud connectivity is provisioned by `provisionCloudStore()` but is not the
 * synchronous handle path — services run against SQLite in local mode.
 */
export function getDatabase(path?: string): Database {
  if (_db && path === undefined) return _db;

  const mode = resolveStorageMode();

  // Fail-closed (§2.4 / DoD §9). The cloud Postgres domain path is not yet wired
  // through the (synchronous) service layer, so cloud mode must NOT silently fall
  // back to an ephemeral in-memory SQLite: doing so would store money
  // authorizations/caps/freezes/audit in per-instance volatile memory — lost on
  // restart and not shared across Fargate/LWA instances. Refuse instead of
  // degrading. `provisionCloudStore()` is the connection primitive the future
  // async wiring will build on. An explicit `path` (tests/migration tooling) may
  // still open a concrete store.
  if (mode === "cloud" && path === undefined) {
    throw new Error(
      "controls: cloud storage mode is not yet wired for domain data. Refusing to serve reads/writes " +
        "from ephemeral in-memory SQLite (fail-closed). Use HASNA_CONTROLS_STORAGE_MODE=local for the " +
        "SQLite store, or wire the cloud Postgres path (provisionCloudStore()) before deploying in cloud mode.",
    );
  }

  const dbPath = path ?? defaultResolvedPath();

  if (dbPath !== ":memory:") {
    ensureDir(dbPath);
    if (existsSync(dbPath)) backupIfMigrationPending(dbPath);
  }

  const db = new Database(dbPath);
  db.run("PRAGMA journal_mode = WAL;");
  db.run("PRAGMA busy_timeout = 5000;");
  db.run("PRAGMA foreign_keys = ON;");
  applySchema(db);
  recordMigrationLedger(db);

  if (path === undefined) _db = db;
  return db;
}

function defaultResolvedPath(): string {
  ensureControlsAppHome();
  return resolveDbPath();
}

function backupIfMigrationPending(dbPath: string): void {
  // Back up before a shape change: applied ledger id behind the current plan.
  const probe = new Database(dbPath, { readonly: true });
  try {
    const row = probe.query("SELECT MAX(id) AS m FROM schema_migrations").get() as { m: number | null } | null;
    const applied = row?.m ?? 0;
    if (applied > 0 && applied < currentMigrationId()) {
      backupDatabaseBeforeMigration(dbPath);
    }
  } catch {
    // fresh db without ledger yet — no backup needed
  } finally {
    probe.close();
  }
}

function recordMigrationLedger(db: Database): void {
  for (const step of MIGRATION_PLAN) {
    db.run("INSERT OR IGNORE INTO schema_migrations (id) VALUES (?)", [step.id]);
  }
}

export function closeDatabase(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}

export function resetDatabaseCache(): void {
  _db = null;
}

export function migrationsApplied(db: Database): number {
  const row = db.query("SELECT COUNT(*) AS c FROM schema_migrations").get() as { c: number };
  return row.c;
}

export function now(): string {
  return new Date().toISOString();
}

/** Unguessable UUIDv4 for entity-anchored ids (§1c). */
export function uuid(): string {
  return crypto.randomUUID();
}

/**
 * Provision a cloud Postgres store (PURE REMOTE). Dynamically imports the
 * vendored storage-kit so the local SQLite path never bundles `pg`. Returns the
 * typed query client; callers must have resolved mode === "cloud".
 */
export async function provisionCloudStore(): Promise<unknown> {
  const dsn = resolveDatabaseUrl();
  if (!dsn) {
    throw new Error(
      "cloud mode needs HASNA_CONTROLS_DATABASE_URL (or _FILE); PURE REMOTE reads/writes go to cloud Postgres.",
    );
  }
  const { createPgPool } = await import("../generated/storage-kit/pool.js");
  const { createQueryClient } = await import("../generated/storage-kit/query.js");
  // sslmode=verify-full is enforced by the vendored tls.ts against the DSN.
  const pool = createPgPool({ connectionString: dsn, applicationName: "controls" });
  const client = createQueryClient(pool);
  // Scrub the inline DSN so child processes / introspection cannot read it.
  scrubDatabaseUrl();
  return client;
}
