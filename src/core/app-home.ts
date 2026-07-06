import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { APP_NAME } from "../config.js";

/** Subdirectories of ~/.hasna/controls, all created mode 0700. */
export const CONTROLS_APP_SUBDIRS = ["config", "data", "exports", "backups", "logs", "tmp"] as const;
export type ControlsAppSubdir = (typeof CONTROLS_APP_SUBDIRS)[number];

function homeDir(): string {
  return process.env["HOME"] || process.env["USERPROFILE"] || homedir();
}

/** ~/.hasna/controls (overridable via HASNA_CONTROLS_HOME for tests). */
export function getControlsAppHome(): string {
  return resolve(
    process.env["HASNA_CONTROLS_HOME"] ??
      process.env["CONTROLS_HOME"] ??
      join(homeDir(), ".hasna", APP_NAME),
  );
}

export function getControlsAppDir(name: ControlsAppSubdir): string {
  return join(getControlsAppHome(), name);
}

/** Create the app-home tree with directory mode 0700 (hardened, §4.4). */
export function ensureControlsAppHome(): Record<ControlsAppSubdir | "root", string> {
  const root = getControlsAppHome();
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const dirs = { root } as Record<ControlsAppSubdir | "root", string>;
  for (const name of CONTROLS_APP_SUBDIRS) {
    const dir = getControlsAppDir(name);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    dirs[name] = dir;
  }
  return dirs;
}

export function getDefaultControlsBackupDir(): string {
  return getControlsAppDir("backups");
}
