// Prove this repo satisfies the Hasna Service Contract v1 using its own
// hasna.contract.json. Requires @hasna/contracts >= 0.4.0 (dev-dependency).
import * as contracts from "@hasna/contracts";

const runRepoConformance = (
  contracts as {
    runRepoConformance?: (root: string) => {
      ok: boolean;
      name: string | null;
      class: string | null;
      checks: { id: string; status: string; detail: string }[];
    };
  }
).runRepoConformance;

if (typeof runRepoConformance !== "function") {
  console.error("Install @hasna/contracts >= 0.4.0 (runRepoConformance not found).");
  process.exit(1);
}

const report = runRepoConformance(process.cwd());
console.log(`${report.ok ? "ok" : "fail"} hasna.service_contract.v1 ${report.name ?? "?"} (${report.class ?? "?"})`);
for (const check of report.checks) {
  console.log(`  ${check.status}\t${check.id}: ${check.detail}`);
}
if (!report.ok) process.exit(1);
