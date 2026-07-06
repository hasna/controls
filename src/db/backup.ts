import { copyFileSync, existsSync, mkdirSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { basename, join } from "node:path";
import { getDefaultControlsBackupDir } from "../core/app-home.js";

const RETAIN = 10;

export interface BackupResult {
  path: string | null;
  skipped: boolean;
  reason?: string;
}

/**
 * Snapshot the current SQLite DB before a shape-changing migration (§4.4).
 * - Writes to ~/.hasna/controls/backups/controls-<ISO>-pre-migration.db, 0600.
 * - Retains the last N=10 snapshots; prunes older ones.
 * - Refuses (throws) if the backup directory cannot be created.
 */
export function backupDatabaseBeforeMigration(dbPath: string): BackupResult {
  if (dbPath === ":memory:" || !existsSync(dbPath)) {
    return { path: null, skipped: true, reason: "no on-disk database to back up" };
  }
  const dir = getDefaultControlsBackupDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const iso = new Date().toISOString().replace(/[:.]/g, "-");
  const target = join(dir, `controls-${iso}-pre-migration.db`);
  copyFileSync(dbPath, target);
  try {
    // Restrict the plaintext money snapshot to the owner.
    // (chmod via fs is imported lazily to keep this file dependency-light.)
    const { chmodSync } = require("node:fs") as typeof import("node:fs");
    chmodSync(target, 0o600);
  } catch {
    // best-effort on platforms without POSIX perms
  }
  pruneOldBackups(dir);
  return { path: target, skipped: false };
}

export function listDatabaseBackups(dir = getDefaultControlsBackupDir()): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith("-pre-migration.db"))
    .map((f) => join(dir, f))
    .sort();
}

function pruneOldBackups(dir: string): void {
  const backups = listDatabaseBackups(dir)
    .map((p) => ({ p, mtime: statSync(p).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  for (const stale of backups.slice(RETAIN)) {
    try {
      unlinkSync(stale.p);
    } catch {
      // ignore
    }
  }
}

export function backupBasename(path: string): string {
  return basename(path);
}
