import { SCHEMA_SQL } from "./schema.js";

export interface MigrationStep {
  id: number;
  name: string;
  sql: string;
}

/**
 * Ordered, forward-only migration steps. The initial step is the idempotent
 * baseline schema; new shape changes append a new step with the next id and are
 * applied at most once (recorded in the schema_migrations ledger). Never rewrite
 * an applied migration — add a new one.
 */
export const MIGRATION_PLAN: MigrationStep[] = [
  { id: 1, name: "baseline", sql: SCHEMA_SQL },
];

export function currentMigrationId(): number {
  return MIGRATION_PLAN[MIGRATION_PLAN.length - 1]?.id ?? 1;
}
