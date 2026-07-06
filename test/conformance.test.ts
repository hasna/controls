import { describe, expect, it } from "bun:test";

describe("repo conformance (Hasna Service Contract v1)", () => {
  it("passes all 6 conformance checks", async () => {
    const contracts = (await import("@hasna/contracts")) as {
      runRepoConformance?: (root: string) => { ok: boolean; checks: { id: string; status: string; detail: string }[] };
    };
    expect(typeof contracts.runRepoConformance).toBe("function");
    const report = contracts.runRepoConformance!(process.cwd());
    const failing = report.checks.filter((c) => c.status === "fail");
    if (failing.length > 0) console.error(failing);
    expect(failing).toEqual([]);
    expect(report.ok).toBe(true);
    const ids = report.checks.map((c) => c.id);
    for (const check of ["manifest_valid", "bins_allowlisted", "bins_match_package", "mode_enum_compliance", "health_shape", "no_cloud_guard"]) {
      expect(ids).toContain(check);
    }
  });
});
