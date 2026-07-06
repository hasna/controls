import { describe, expect, it } from "bun:test";
import { runSmoke } from "../src/release/package-smoke.js";

describe("package smoke script", () => {
  it("runs the full request->approve->consume flow with a valid audit chain", () => {
    const result = runSmoke();
    expect(result.ok).toBe(true);
    expect(result.audit_valid).toBe(true);
    expect(result.steps).toContain("authorization.consume");
    expect(result.audit_events).toBeGreaterThan(0);
  });
});
