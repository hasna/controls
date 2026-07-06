import type { Database } from "bun:sqlite";
import { now, uuid } from "../db/database.js";
import { recordAuditEvent } from "../db/audit.js";
import { FreezeNotFoundError, type Freeze } from "../types/index.js";
import { authorize, type AuthorizationContext } from "./authorization.js";
import { actorId, entityResource, optionalString, requireString, sqliteBool, type Input } from "./common.js";

interface FreezeRow {
  id: string;
  entity_id: string;
  identity_id: string | null;
  active: number;
  reason: string;
  created_at: string;
  released_at: string | null;
}

function mapRow(row: FreezeRow): Freeze {
  return { ...row, active: row.active === 1 };
}

export function createFreeze(db: Database, input: Input, ctx?: AuthorizationContext): Freeze {
  const entity_id = requireString(input, "entity_id");
  authorize("freeze", ctx, entityResource(entity_id, "freeze"));
  const freeze: Freeze = {
    id: uuid(),
    entity_id,
    identity_id: optionalString(input, "identity_id"),
    active: true,
    reason: requireString(input, "reason"),
    created_at: now(),
    released_at: null,
  };
  db.run(
    "INSERT INTO freezes (id, entity_id, identity_id, active, reason, created_at, released_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [freeze.id, freeze.entity_id, freeze.identity_id, sqliteBool(freeze.active), freeze.reason, freeze.created_at, freeze.released_at],
  );
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx),
    action: "freeze.create",
    resource_type: "freeze",
    resource_id: freeze.id,
    detail: { identity_id: freeze.identity_id, reason: freeze.reason },
  });
  return freeze;
}

export function releaseFreeze(db: Database, input: Input, ctx?: AuthorizationContext): Freeze {
  const entity_id = requireString(input, "entity_id");
  const id = requireString(input, "id");
  authorize("freeze", ctx, entityResource(entity_id, "freeze"));
  const row = db.query("SELECT * FROM freezes WHERE id = ? AND entity_id = ?").get(id, entity_id) as FreezeRow | null;
  if (!row) throw new FreezeNotFoundError(`Freeze ${id} not found for entity ${entity_id}.`);
  const ts = now();
  db.run("UPDATE freezes SET active = 0, released_at = ? WHERE id = ?", [ts, id]);
  recordAuditEvent(db, {
    entity_id,
    actor_id: actorId(ctx),
    action: "freeze.release",
    resource_type: "freeze",
    resource_id: id,
    detail: {},
  });
  return mapRow({ ...row, active: 0, released_at: ts });
}

export function listFreezes(db: Database, input: Input, ctx?: AuthorizationContext): Freeze[] {
  const entity_id = requireString(input, "entity_id");
  authorize("read", ctx, entityResource(entity_id, "freeze"));
  const rows = db.query("SELECT * FROM freezes WHERE entity_id = ? ORDER BY created_at, id").all(entity_id) as FreezeRow[];
  return rows.map(mapRow);
}

export interface FreezeStatus {
  entity_id: string;
  identity_id: string | null;
  frozen: boolean;
  freezes: Freeze[];
}

export function freezeStatus(db: Database, input: Input, ctx?: AuthorizationContext): FreezeStatus {
  const entity_id = requireString(input, "entity_id");
  const identity_id = optionalString(input, "identity_id");
  authorize("read", ctx, entityResource(entity_id, "freeze"));
  const active = activeFreezes(db, entity_id, identity_id);
  return { entity_id, identity_id, frozen: active.length > 0, freezes: active };
}

/** Active freezes that apply to the entity (whole-entity) or a specific identity. */
export function activeFreezes(db: Database, entity_id: string, identity_id: string | null): Freeze[] {
  const rows = db
    .query("SELECT * FROM freezes WHERE entity_id = ? AND active = 1 ORDER BY created_at, id")
    .all(entity_id) as FreezeRow[];
  return rows
    .filter((r) => r.identity_id === null || r.identity_id === identity_id)
    .map(mapRow);
}

export function isFrozen(db: Database, entity_id: string, identity_id: string | null): boolean {
  return activeFreezes(db, entity_id, identity_id).length > 0;
}
