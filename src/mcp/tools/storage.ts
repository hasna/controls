import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ok, fail } from "../compact.js";
import { getDatabase } from "../../db/database.js";
import { storageStatus, storageSync, type StorageAdmin } from "../../services/storage.js";
import type { ApiPrincipal } from "../../server/auth.js";

/**
 * Standard storage MCP tools (§4.6). `status` is REDACTED (never emits a DSN or
 * the full storage config). `push`/`pull`/`sync` require the elevated
 * `storage:admin` scope, write an audit entry, and NEVER touch append-only audit
 * tables.
 */
export function registerStorageTools(server: McpServer, principal: ApiPrincipal | undefined): void {
  const admin: StorageAdmin = {
    // stdio local single-user callers have no principal and are trusted (system).
    has_storage_admin: !principal || principal.scopes.includes("storage:admin"),
    actor_id: principal?.actor_id ?? null,
  };

  server.tool(
    "controls_storage_status",
    "Redacted storage status: mode, whether a DSN is present, sqlite path, migrations applied, remote reachability. Never returns secret values.",
    {},
    async () => {
      try {
        return ok(storageStatus());
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "controls_storage_push",
    "Push local rows to cloud Postgres (elevated storage:admin scope; audited; append-only audit tables excluded).",
    { tables: z.array(z.string()).optional().describe("Optional table filter (audit tables always excluded).") },
    async ({ tables }) => {
      try {
        return ok(storageSync(getDatabase(), "push", tables, admin));
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "controls_storage_pull",
    "Pull cloud rows into local SQLite (elevated storage:admin scope; audited; append-only audit tables excluded).",
    { tables: z.array(z.string()).optional().describe("Optional table filter (audit tables always excluded).") },
    async ({ tables }) => {
      try {
        return ok(storageSync(getDatabase(), "pull", tables, admin));
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "controls_storage_sync",
    "Push then pull (elevated storage:admin scope; audited; append-only audit tables excluded).",
    { tables: z.array(z.string()).optional().describe("Optional table filter (audit tables always excluded).") },
    async ({ tables }) => {
      try {
        const db = getDatabase();
        storageSync(db, "push", tables, admin);
        return ok(storageSync(db, "pull", tables, admin));
      } catch (error) {
        return fail(error);
      }
    },
  );
}
