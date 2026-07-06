import type { Database } from "bun:sqlite";
import { listAuditEvents, verifyAuditIntegrity } from "../db/audit.js";
import type { AuditEvent, AuditIntegrityResult } from "../types/index.js";
import { authorize, type AuthorizationContext } from "./authorization.js";
import { entityResource, requireString, type Input } from "./common.js";

/** Read the append-only money audit trail for an entity (§4.7). */
export function listAudit(db: Database, input: Input, ctx?: AuthorizationContext): AuditEvent[] {
  const entity_id = requireString(input, "entity_id");
  authorize("read", ctx, entityResource(entity_id, "controls_audit"));
  return listAuditEvents(db, entity_id);
}

/** Verify the tamper-evident hash chain for an entity's audit trail. */
export function verifyAudit(db: Database, input: Input, ctx?: AuthorizationContext): AuditIntegrityResult {
  const entity_id = requireString(input, "entity_id");
  authorize("read", ctx, entityResource(entity_id, "controls_audit"));
  return verifyAuditIntegrity(db, entity_id);
}
