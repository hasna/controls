import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const MAX_PRODUCTION_LOC = 700;
const SKIPPED_DIRS = new Set([".git", "coverage", "dist", "node_modules", "test"]);
const GENERATED_FILES = new Set(["bun.lock"]);

function collectProductionFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (SKIPPED_DIRS.has(entry)) continue;
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      files.push(...collectProductionFiles(path));
    } else if (stat.isFile()) {
      const projectPath = relative(process.cwd(), path);
      if (!GENERATED_FILES.has(projectPath)) files.push(path);
    }
  }
  return files;
}

function lineCount(path: string): number {
  const content = readFileSync(path, "utf8");
  if (content.length === 0) return 0;
  return content.split(/\r?\n/).length;
}

describe("production file size", () => {
  it("keeps non-test files under 700 lines", () => {
    const oversized = collectProductionFiles(process.cwd())
      .map((path) => ({ path: relative(process.cwd(), path), lines: lineCount(path) }))
      .filter((file) => file.lines > MAX_PRODUCTION_LOC);

    expect(oversized).toEqual([]);
  });
});
