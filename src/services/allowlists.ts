import type { Database } from "bun:sqlite";
import { now, uuid } from "../db/database.js";
import { recordAuditEvent } from "../db/audit.js";
import { AllowlistEntryNotFoundError, type AllowlistStatus, type CounterpartyAllowlistEntry } from "../types/index.js";
import { authorize, type AuthorizationContext } from "./authorization.js";
import { actorId, entityResource, optionalString, requireString, type Input } from "./common.js";

interface AllowlistRow {
  id: string;
  entity_id: string;
  counterparty_id: string;
  counterparty_name: string | null;
  status: string;
  note: string | null;
  created_at: string;
  updated_at: string;
}

function mapRow(row: AllowlistRow): CounterpartyAllowlistEntry {
  return { ...row, status: row.status as AllowlistStatus };
}

function upsert(db: Database, input: Input, status: AllowlistStatus, ctx?: AuthorizationContext): CounterpartyAllowlistEntry {
  const entity_id = requireString(input, "entity_id");
  const counterparty_id = requireString(input, "counterparty_id");
  authorize("write", ctx, entityResource(entity_id, "counterparty_allowlist"));
  const ts = now();
  const existing = db
    .query("SELECT * FROM counterparty_allowlists WHERE entity_id = ? AND counterparty_id = ?")
    .get(entity_id, counterparty_id) as AllowlistRow | null;
  const name = optionalString(input, "counterparty_name");
  const note = optionalString(input, "note");
  let id: string;
  if (existing) {
    id = existing.id;
    db.run(
      "UPDATE counterparty_allowlists SET counterparty_name = ?, status = ?, note = ?, updated_at = ? WHERE id = ?",
      [name ?? existing.counterparty_name, status, note ?? existing.note, ts, id],
    );
  } else {
    id = uuid();
    db.run(
      `INSERT INTO counterparty_allowlists (id, entity_id, counterparty_id, counterparty_name, status, note, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, entity_id, counterparty_id, name, status, note, ts, ts],
    );
  }
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx),
    action: "allowlist.upsert",
    resource_type: "counterparty_allowlist",
    resource_id: id,
    detail: { counterparty_id, status },
  });
  const row = db.query("SELECT * FROM counterparty_allowlists WHERE id = ?").get(id) as AllowlistRow;
  return mapRow(row);
}

export function allowCounterparty(db: Database, input: Input, ctx?: AuthorizationContext): CounterpartyAllowlistEntry {
  return upsert(db, input, "allowed", ctx);
}

export function blockCounterparty(db: Database, input: Input, ctx?: AuthorizationContext): CounterpartyAllowlistEntry {
  return upsert(db, input, "blocked", ctx);
}

export function getAllowlistEntry(db: Database, input: Input, ctx?: AuthorizationContext): CounterpartyAllowlistEntry {
  const entity_id = requireString(input, "entity_id");
  const id = requireString(input, "id");
  authorize("read", ctx, entityResource(entity_id, "counterparty_allowlist"));
  const row = db.query("SELECT * FROM counterparty_allowlists WHERE id = ? AND entity_id = ?").get(id, entity_id) as AllowlistRow | null;
  if (!row) throw new AllowlistEntryNotFoundError(`Allowlist entry ${id} not found for entity ${entity_id}.`);
  return mapRow(row);
}

export function listAllowlist(db: Database, input: Input, ctx?: AuthorizationContext): CounterpartyAllowlistEntry[] {
  const entity_id = requireString(input, "entity_id");
  authorize("read", ctx, entityResource(entity_id, "counterparty_allowlist"));
  const rows = db.query("SELECT * FROM counterparty_allowlists WHERE entity_id = ? ORDER BY created_at, id").all(entity_id) as AllowlistRow[];
  return rows.map(mapRow);
}

export function removeAllowlistEntry(db: Database, input: Input, ctx?: AuthorizationContext): { id: string; deleted: true } {
  const existing = getAllowlistEntry(db, input, ctx);
  authorize("admin", ctx, entityResource(existing.entity_id, "counterparty_allowlist"));
  db.run("DELETE FROM counterparty_allowlists WHERE id = ?", [existing.id]);
  recordAuditEvent(db, {
    entity_id: existing.entity_id,
    actor_id: actorId(ctx),
    action: "allowlist.remove",
    resource_type: "counterparty_allowlist",
    resource_id: existing.id,
    detail: { counterparty_id: existing.counterparty_id },
  });
  return { id: existing.id, deleted: true };
}

/** Is a counterparty permitted for the entity? Blocked or absent => not allowed. */
export function isCounterpartyAllowed(db: Database, entity_id: string, counterparty_id: string): boolean {
  const row = db
    .query("SELECT status FROM counterparty_allowlists WHERE entity_id = ? AND counterparty_id = ?")
    .get(entity_id, counterparty_id) as { status: string } | null;
  return row?.status === "allowed";
}
