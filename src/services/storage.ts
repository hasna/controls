import type { Database } from "bun:sqlite";
import { recordAuditEvent } from "../db/audit.js";
import { AUDIT_TABLES, SYNCABLE_TABLES } from "../db/schema.js";
import { getDatabase, migrationsApplied } from "../db/database.js";
import { databaseUrlPresent, resolveDbPath, resolveStorageMode } from "../config.js";
import { PermissionDeniedError } from "../types/index.js";

export interface StorageStatus {
  mode: "local" | "cloud";
  dsn_present: boolean;
  sqlite_path: string | null;
  migrations_applied: number;
  remote_reachable: boolean;
}

/**
 * Redacted storage status (§4.6) — never includes a DSN or secret value.
 *
 * Resolves its own handle: in `local` it counts the SQLite migration ledger; in
 * `cloud` the domain path is fail-closed/pending (see db/database.ts), so it does
 * NOT open a domain DB and reports `migrations_applied: 0`. `remote_reachable`
 * reflects whether a live cloud connection is actually established — it never is
 * today (no live pool is opened), so it is honestly `false`, not a fabricated
 * "reachable".
 */
export function storageStatus(): StorageStatus {
  const mode = resolveStorageMode();
  return {
    mode,
    dsn_present: databaseUrlPresent(),
    sqlite_path: mode === "local" ? resolveDbPath() : null,
    migrations_applied: mode === "local" ? migrationsApplied(getDatabase()) : 0,
    // No live remote connection is opened from here; report unreachable rather
    // than fabricate reachability. A real probe lands with the cloud wiring.
    remote_reachable: false,
  };
}

export interface StorageAdmin {
  has_storage_admin: boolean;
  actor_id: string | null;
}

export interface StorageSyncResult {
  direction: "push" | "pull";
  tables: string[];
  excluded_audit_tables: string[];
  performed: boolean;
  note: string;
}

/**
 * Push/pull between local SQLite and cloud Postgres. Gated on storage:admin,
 * audited, and NEVER touches append-only audit tables (§4.6/§4.7).
 *
 * Real local<->cloud row movement requires the cloud Postgres domain path, which
 * is fail-closed/pending (see db/database.ts getDatabase). Until that is wired,
 * this records an audited plan but performs NO remote I/O and reports
 * `performed: false` — it never falsely claims a push/pull "executed".
 */
export function storageSync(
  db: Database,
  direction: "push" | "pull",
  tables: string[] | undefined,
  admin: StorageAdmin,
): StorageSyncResult {
  if (!admin.has_storage_admin) throw new PermissionDeniedError("storage:admin", "storage");
  const requested = tables && tables.length > 0 ? tables : [...SYNCABLE_TABLES];
  const excluded = requested.filter((t) => (AUDIT_TABLES as readonly string[]).includes(t));
  const effective = requested.filter((t) => (SYNCABLE_TABLES as readonly string[]).includes(t));
  recordAuditEvent(db, {
    entity_id: null,
    actor_id: admin.actor_id ?? "system",
    action: direction === "push" ? "storage.push" : "storage.pull",
    resource_type: "storage",
    resource_id: null,
    detail: { direction, tables: effective, excluded_audit_tables: excluded },
  });
  return {
    direction,
    tables: effective,
    excluded_audit_tables: excluded,
    performed: false,
    note: "audited plan only — remote row movement is not yet implemented (cloud Postgres domain path pending).",
  };
}
