#!/usr/bin/env bun
import { configureProgram, program } from "./context.js";
import {
  registerCallCommand,
  registerDomainCommands,
  registerOpenApiCommands,
  registerStorageCommands,
  registerSystemCommands,
} from "./namespaces.js";

configureProgram();
registerDomainCommands();
registerCallCommand();
registerStorageCommands();
registerOpenApiCommands();
registerSystemCommands();

async function main(): Promise<void> {
  await program.parseAsync(process.argv);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
