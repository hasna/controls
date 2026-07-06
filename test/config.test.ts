import { describe, expect, it } from "bun:test";
import { resolveStorageMode, databaseUrlPresent } from "../src/config.js";

describe("config: storage mode resolution", () => {
  it("defaults to local", () => {
    expect(resolveStorageMode({})).toBe("local");
  });

  it("resolves cloud", () => {
    expect(resolveStorageMode({ HASNA_CONTROLS_STORAGE_MODE: "cloud" })).toBe("cloud");
  });

  it("normalizes deprecated aliases to cloud", () => {
    expect(resolveStorageMode({ HASNA_CONTROLS_STORAGE_MODE: "self_hosted" })).toBe("cloud");
    expect(resolveStorageMode({ HASNA_CONTROLS_STORAGE_MODE: "remote" })).toBe("cloud");
    expect(resolveStorageMode({ HASNA_CONTROLS_STORAGE_MODE: "hybrid" })).toBe("cloud");
  });

  it("honors the alias env prefix", () => {
    expect(resolveStorageMode({ CONTROLS_STORAGE_MODE: "cloud" })).toBe("cloud");
  });

  it("rejects unknown modes", () => {
    expect(() => resolveStorageMode({ HASNA_CONTROLS_STORAGE_MODE: "hybrid-cache" })).toThrow();
  });

  it("fail-closed: DSN present but mode local is a hard error", () => {
    expect(() =>
      resolveStorageMode({ HASNA_CONTROLS_DATABASE_URL: "postgres://x/y" }),
    ).toThrow(/DATABASE_URL is present but mode resolved to 'local'/);
  });

  it("cloud + DSN present is fine", () => {
    expect(
      resolveStorageMode({ HASNA_CONTROLS_STORAGE_MODE: "cloud", HASNA_CONTROLS_DATABASE_URL: "postgres://x/y" }),
    ).toBe("cloud");
  });

  it("detects DSN presence without reading the value", () => {
    expect(databaseUrlPresent({})).toBe(false);
    expect(databaseUrlPresent({ HASNA_CONTROLS_DATABASE_URL: "postgres://secret:pw@host/db" })).toBe(true);
  });
});
