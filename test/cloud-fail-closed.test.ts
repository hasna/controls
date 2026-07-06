import { afterEach, describe, expect, it } from "bun:test";
import { getDatabase, resetDatabaseCache } from "../src/db/database.js";

/**
 * Cloud mode must be FAIL-CLOSED (§2.4 / DoD §9). The cloud Postgres domain path
 * is not yet wired through the synchronous service layer, so cloud mode must
 * NEVER silently degrade to an ephemeral in-memory SQLite — that would store
 * money authorizations/caps/freezes/audit in per-instance volatile memory, lost
 * on restart and not shared across instances. getDatabase() throws instead.
 */
function reset(): void {
  delete process.env["HASNA_CONTROLS_STORAGE_MODE"];
  delete process.env["HASNA_CONTROLS_DATABASE_URL"];
  delete process.env["HASNA_CONTROLS_DB_PATH"];
  resetDatabaseCache();
}

afterEach(reset);

describe("cloud mode is fail-closed", () => {
  it("getDatabase throws in cloud mode instead of using in-memory SQLite", () => {
    reset();
    process.env["HASNA_CONTROLS_STORAGE_MODE"] = "cloud";
    process.env["HASNA_CONTROLS_DATABASE_URL"] = "postgres://x/y";
    expect(() => getDatabase()).toThrow(/cloud storage mode is not yet wired/i);
  });

  it("never returns a volatile :memory: fallback handle when a DSN is set", () => {
    reset();
    process.env["HASNA_CONTROLS_STORAGE_MODE"] = "cloud";
    process.env["HASNA_CONTROLS_DATABASE_URL"] = "postgres://x/y";
    let handle: unknown;
    try {
      handle = getDatabase();
    } catch {
      handle = undefined;
    }
    expect(handle).toBeUndefined();
  });

  it("still opens a real SQLite handle in local mode", () => {
    reset();
    process.env["HASNA_CONTROLS_DB_PATH"] = ":memory:";
    const db = getDatabase();
    expect(db).toBeDefined();
    const row = db.query("SELECT COUNT(*) AS c FROM schema_migrations").get() as { c: number };
    expect(row.c).toBeGreaterThan(0);
  });
});
