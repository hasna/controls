import { Command } from "commander";
import { writeFileSync, readFileSync } from "node:fs";
import { getDatabase } from "../db/database.js";
import { resolveDbPath, resolveStorageMode } from "../config.js";
import { OPERATIONS, executeOperation, operationManifest, type OperationDef } from "../services/registry.js";
import { storageStatus, storageSync } from "../services/storage.js";
import { openApiDocument } from "../api/index.js";
import { healthPayload } from "../server/health.js";
import { cliContext, emit, handleError, program, snakeToCamel, snakeToKebab } from "./context.js";
import type { Input } from "../services/common.js";

function collectInput(def: OperationDef, opts: Record<string, unknown>): Input {
  const input: Input = {};
  for (const field of def.fields) {
    const key = snakeToCamel(field.name);
    const value = opts[key];
    if (value !== undefined) input[field.name] = value;
  }
  return input;
}

function runOp(def: OperationDef, opts: Record<string, unknown>): void {
  try {
    const db = getDatabase();
    const result = executeOperation(db, def.op, collectInput(def, opts), cliContext());
    emit(result);
  } catch (error) {
    handleError(error);
  }
}

/** Build one commander namespace per domain resource, generated from the registry. */
export function registerDomainCommands(): void {
  const namespaces = new Map<string, Command>();
  for (const def of OPERATIONS) {
    let ns = namespaces.get(def.cli.namespace);
    if (!ns) {
      ns = program.command(def.cli.namespace).description(`Manage ${def.cli.namespace}`);
      namespaces.set(def.cli.namespace, ns);
    }
    const cmd = ns.command(def.cli.command).description(def.summary);
    for (const field of def.fields) {
      const flag = `--${snakeToKebab(field.name)} <value>`;
      cmd.option(flag, `${field.description}${field.required ? " (required)" : ""}`);
    }
    cmd.action((opts: Record<string, unknown>) => runOp(def, opts));
  }
}

/** Generic dispatch used by power users and the interface-parity harness. */
export function registerCallCommand(): void {
  program
    .command("call")
    .description("Execute a controls operation by its canonical name with a JSON input body.")
    .argument("<op>", "Operation name, e.g. policy.create")
    .option("--input <json>", "JSON input object", "{}")
    .action((op: string, opts: { input: string }) => {
      try {
        let input: Input;
        try {
          input = JSON.parse(opts.input) as Input;
        } catch {
          throw new Error("--input must be valid JSON.");
        }
        const db = getDatabase();
        emit(executeOperation(db, op, input, cliContext()));
      } catch (error) {
        handleError(error);
      }
    });
}

export function registerStorageCommands(): void {
  const storage = program.command("storage").description("Storage status and local<->cloud sync (audited, audit tables excluded)");
  storage
    .command("status")
    .description("Show redacted storage status (no secrets).")
    .action(() => {
      try {
        emit(storageStatus());
      } catch (error) {
        handleError(error);
      }
    });
  for (const direction of ["push", "pull", "sync"] as const) {
    storage
      .command(direction)
      .description(`${direction} local<->cloud (storage:admin; audited).`)
      .option("--tables <list>", "Comma-separated table filter")
      .action((opts: { tables?: string }) => {
        try {
          const tables = opts.tables ? opts.tables.split(",").map((t) => t.trim()).filter(Boolean) : undefined;
          const db = getDatabase();
          const admin = { has_storage_admin: true, actor_id: "cli" };
          if (direction === "sync") {
            storageSync(db, "push", tables, admin);
            emit(storageSync(db, "pull", tables, admin));
          } else {
            emit(storageSync(db, direction, tables, admin));
          }
        } catch (error) {
          handleError(error);
        }
      });
  }
}

export function registerOpenApiCommands(): void {
  const openapi = program.command("openapi").description("OpenAPI document tooling");
  openapi
    .command("generate")
    .description("Generate the OpenAPI document.")
    .option("--out <path>", "Output path", "openapi.json")
    .option("--minify", "Minify JSON")
    .action((opts: { out: string; minify?: boolean }) => {
      const doc = openApiDocument();
      const text = opts.minify ? JSON.stringify(doc) : JSON.stringify(doc, null, 2);
      writeFileSync(opts.out, text + "\n");
      emit({ generated: true, out: opts.out, paths: Object.keys((doc as { paths: object }).paths).length });
    });
  openapi
    .command("check")
    .description("Check that the checked-in OpenAPI document matches the generated one.")
    .option("--path <path>", "OpenAPI path", "openapi.json")
    .action((opts: { path: string }) => {
      try {
        const onDisk = JSON.parse(readFileSync(opts.path, "utf-8")) as unknown;
        const generated = openApiDocument();
        const match = JSON.stringify(onDisk) === JSON.stringify(generated);
        if (!match) throw new Error(`OpenAPI document at ${opts.path} is stale; run 'controls openapi generate'.`);
        emit({ ok: true, path: opts.path });
      } catch (error) {
        handleError(error);
      }
    });
}

export function registerSystemCommands(): void {
  program
    .command("doctor")
    .description("Show storage mode, database path, health, and the operation manifest size.")
    .action(() => {
      emit({
        app: "controls",
        mode: resolveStorageMode(),
        db_path: resolveDbPath(),
        health: healthPayload(),
        operations: operationManifest().length,
      });
    });
  program
    .command("operations")
    .description("Print the interface-parity operation manifest (op, input, surfaces).")
    .action(() => emit(operationManifest()));
}
