import type { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { now, uuid } from "./database.js";
import type { AuditAction, AuditEvent, AuditIntegrityIssue, AuditIntegrityResult } from "../types/index.js";

const HASH_ALGO = "sha256";

export interface RecordAuditInput {
  entity_id: string | null;
  actor_id: string | null;
  action: AuditAction;
  resource_type: string;
  resource_id?: string | null;
  amount?: number | null;
  currency?: string | null;
  detail?: Record<string, unknown>;
}

interface AuditRow {
  id: string;
  entity_id: string | null;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  amount: number | null;
  currency: string | null;
  detail: string;
  prev_hash: string;
  row_hash: string;
  created_at: string;
}

function mapRow(row: AuditRow): AuditEvent {
  return {
    ...row,
    action: row.action as AuditAction,
    detail: JSON.parse(row.detail || "{}") as Record<string, unknown>,
  };
}

/** Append a tamper-evident, hash-chained audit event (§4.7). Insert-only. */
export function recordAuditEvent(db: Database, input: RecordAuditInput): AuditEvent {
  const id = uuid();
  const createdAt = now();
  const prevHash = latestHash(db, input.entity_id);
  const detail = input.detail ?? {};
  const rowHash = computeRowHash(
    {
      id,
      entity_id: input.entity_id,
      actor_id: input.actor_id,
      action: input.action,
      resource_type: input.resource_type,
      resource_id: input.resource_id ?? null,
      amount: input.amount ?? null,
      currency: input.currency ?? null,
      detail,
      created_at: createdAt,
    },
    prevHash,
  );

  db.run(
    `INSERT INTO controls_audit
       (id, entity_id, actor_id, action, resource_type, resource_id, amount, currency, detail, prev_hash, row_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      input.entity_id,
      input.actor_id,
      input.action,
      input.resource_type,
      input.resource_id ?? null,
      input.amount ?? null,
      input.currency ?? null,
      JSON.stringify(detail),
      prevHash,
      rowHash,
      createdAt,
    ],
  );

  const row = db.query("SELECT * FROM controls_audit WHERE id = ?").get(id) as AuditRow | null;
  if (!row) throw new Error(`Audit event not found after insert: ${id}`);
  return mapRow(row);
}

export function listAuditEvents(db: Database, entityId: string | null): AuditEvent[] {
  const rows = (
    entityId === null
      ? db.query("SELECT * FROM controls_audit ORDER BY rowid").all()
      : db.query("SELECT * FROM controls_audit WHERE entity_id = ? ORDER BY rowid").all(entityId)
  ) as AuditRow[];
  return rows.map(mapRow);
}

export function verifyAuditIntegrity(db: Database, entityId: string | null): AuditIntegrityResult {
  const events = listAuditEvents(db, entityId);
  const issues: AuditIntegrityIssue[] = [];
  let prevHash = "";

  events.forEach((event, index) => {
    if (event.prev_hash !== prevHash) {
      issues.push({
        index,
        event_id: event.id,
        code: "previous_hash_mismatch",
        message: `Expected prev_hash ${prevHash || "<genesis>"} but found ${event.prev_hash || "<missing>"}.`,
      });
    }
    const expected = computeRowHash(
      {
        id: event.id,
        entity_id: event.entity_id,
        actor_id: event.actor_id,
        action: event.action,
        resource_type: event.resource_type,
        resource_id: event.resource_id,
        amount: event.amount,
        currency: event.currency,
        detail: event.detail,
        created_at: event.created_at,
      },
      event.prev_hash,
    );
    if (event.row_hash !== expected) {
      issues.push({
        index,
        event_id: event.id,
        code: "hash_mismatch",
        message: "Row hash does not match the stored event contents (tamper detected).",
      });
    }
    prevHash = event.row_hash;
  });

  return {
    entity_id: entityId,
    valid: issues.length === 0,
    event_count: events.length,
    head_hash: events.length > 0 ? events[events.length - 1]!.row_hash : null,
    checked_at: now(),
    issues,
  };
}

function latestHash(db: Database, entityId: string | null): string {
  const row = (
    entityId === null
      ? db.query("SELECT row_hash FROM controls_audit WHERE entity_id IS NULL ORDER BY rowid DESC LIMIT 1").get()
      : db.query("SELECT row_hash FROM controls_audit WHERE entity_id = ? ORDER BY rowid DESC LIMIT 1").get(entityId)
  ) as { row_hash: string } | null;
  return row?.row_hash ?? "";
}

interface HashPayload {
  id: string;
  entity_id: string | null;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  amount: number | null;
  currency: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

function computeRowHash(payload: HashPayload, prevHash: string): string {
  const canonical = stableStringify({ ...payload, prev_hash: prevHash });
  return createHash(HASH_ALGO).update(canonical).digest("hex");
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
    .join(",")}}`;
}
