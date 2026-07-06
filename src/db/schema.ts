import type { Database } from "bun:sqlite";

/**
 * Idempotent DDL for @hasna/controls. Every statement is `CREATE ... IF NOT
 * EXISTS`; applied at startup for local (SQLite) and mirrored as ordered
 * migrations for cloud (Postgres) via migration-plan.ts.
 *
 * The `controls_audit` table is APPEND-ONLY and TAMPER-EVIDENT (§4.7):
 *   - SQLite triggers RAISE(ABORT) on UPDATE/DELETE.
 *   - Each row hash-chains to the previous via prev_hash / row_hash.
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  id INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO schema_migrations (id) VALUES (1);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  agent_id TEXT,
  window TEXT NOT NULL,
  amount_limit INTEGER NOT NULL,
  currency TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_policies_entity ON policies(entity_id);

CREATE TABLE IF NOT EXISTS counterparty_allowlists (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  counterparty_id TEXT NOT NULL,
  counterparty_name TEXT,
  status TEXT NOT NULL DEFAULT 'allowed',
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(entity_id, counterparty_id)
);
CREATE INDEX IF NOT EXISTS idx_allowlists_entity ON counterparty_allowlists(entity_id);

CREATE TABLE IF NOT EXISTS approval_rules (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  tier TEXT NOT NULL,
  threshold_amount INTEGER NOT NULL,
  currency TEXT NOT NULL,
  required_approvals INTEGER NOT NULL DEFAULT 1,
  approver_role TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approval_rules_entity ON approval_rules(entity_id);

CREATE TABLE IF NOT EXISTS authorizations (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  requestor_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  currency TEXT NOT NULL,
  counterparty_id TEXT NOT NULL,
  counterparty_name TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  required_approvals INTEGER NOT NULL DEFAULT 0,
  approvals TEXT NOT NULL DEFAULT '[]',
  token TEXT,
  reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  approved_at TEXT,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_authorizations_entity ON authorizations(entity_id);
CREATE INDEX IF NOT EXISTS idx_authorizations_status ON authorizations(entity_id, status);

CREATE TABLE IF NOT EXISTS freezes (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  identity_id TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  released_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_freezes_entity ON freezes(entity_id, active);

CREATE TABLE IF NOT EXISTS controls_audit (
  id TEXT PRIMARY KEY,
  entity_id TEXT,
  actor_id TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  amount INTEGER,
  currency TEXT,
  detail TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL,
  row_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_controls_audit_entity ON controls_audit(entity_id, created_at);

CREATE TRIGGER IF NOT EXISTS controls_audit_no_update
BEFORE UPDATE ON controls_audit
BEGIN
  SELECT RAISE(ABORT, 'controls_audit is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS controls_audit_no_delete
BEFORE DELETE ON controls_audit
BEGIN
  SELECT RAISE(ABORT, 'controls_audit is append-only: DELETE is forbidden');
END;
`;

/** Tables excluded from storage push/pull/sync — audit is never overwritten. */
export const AUDIT_TABLES = ["controls_audit"] as const;

/** Domain tables eligible for storage push/pull/sync (audit excluded). */
export const SYNCABLE_TABLES = [
  "policies",
  "counterparty_allowlists",
  "approval_rules",
  "authorizations",
  "freezes",
] as const;

export function applySchema(db: Database): void {
  db.run(SCHEMA_SQL);
}
