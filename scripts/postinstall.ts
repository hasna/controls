import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Provision ~/.hasna/controls/{config,data,exports,backups,logs,tmp} mode 0700.
const root = process.env["HASNA_CONTROLS_HOME"] || join(homedir(), ".hasna", "controls");
const subdirs = ["config", "data", "exports", "backups", "logs", "tmp"];
try {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  for (const dir of subdirs) mkdirSync(join(root, dir), { recursive: true, mode: 0o700 });
} catch {
  // best-effort; the app also creates these lazily on first open.
}
