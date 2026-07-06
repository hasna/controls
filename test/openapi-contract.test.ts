import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { openApiDocument } from "../src/api/index.js";
import { OPERATIONS } from "../src/services/registry.js";

describe("openapi contract", () => {
  it("checked-in openapi.json matches the generated document (freshness)", () => {
    const onDisk = JSON.parse(readFileSync(join(process.cwd(), "openapi.json"), "utf-8")) as unknown;
    const generated = openApiDocument();
    expect(JSON.stringify(onDisk)).toBe(JSON.stringify(generated));
  });

  it("documents every registry operation as a path+method", () => {
    const doc = openApiDocument() as { paths: Record<string, Record<string, unknown>> };
    for (const op of OPERATIONS) {
      const path = op.rest.path.replace(/:([a-zA-Z_]+)/g, "{$1}");
      expect(doc.paths[path]).toBeDefined();
      expect(doc.paths[path]![op.rest.method.toLowerCase()]).toBeDefined();
    }
  });

  it("declares bearer security", () => {
    const doc = openApiDocument() as { components: { securitySchemes: Record<string, unknown> } };
    expect(doc.components.securitySchemes).toHaveProperty("bearerAuth");
  });
});
