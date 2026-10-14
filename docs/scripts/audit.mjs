import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// See ../README.md for scope and rationale. Remove these when patches are released.
const exceptions = {
  "https://github.com/advisories/GHSA-vfj7-8cjw-p6xm": {
    package: "braces",
    version: "3.0.3",
    expires: "2026-11-03",
  },
};

export function checkAudit(report, lock, today = new Date().toISOString().slice(0, 10)) {
  if (report.error || report.auditReportVersion !== 2 || !report.vulnerabilities) {
    throw new Error("npm audit did not return a valid version 2 report");
  }

  // npm can report cycles between parents. Visit every cause, requiring each
  // finding to reach a reviewed advisory even when its dependency path cycles.
  function checkFinding(name, visited = new Set()) {
    if (visited.has(name)) return false;
    visited.add(name);
    const finding = report.vulnerabilities[name];
    if (!Array.isArray(finding?.via) || finding.via.length === 0) {
      throw new Error(`Missing advisory causes for ${name}`);
    }
    let hasAdvisory = false;
    for (const cause of finding.via) {
      if (typeof cause === "string") {
        hasAdvisory = checkFinding(cause, visited) || hasAdvisory;
        continue;
      }
      const exception = exceptions[cause.url];
      if (!exception || name !== exception.package || cause.name !== name ||
          cause.severity !== "high" || today >= exception.expires ||
          finding.fixAvailable !== false || !finding.nodes?.length ||
          !finding.nodes.every((node) => lock.packages?.[node]?.version === exception.version)) {
        throw new Error(`Unaccepted advisory for ${name}: ${cause.url}. Check locked versions, patches, and exception expiry.`);
      }
      hasAdvisory = true;
    }
    return hasAdvisory;
  }
  const names = Object.keys(report.vulnerabilities);
  for (const name of names) {
    if (!checkFinding(name)) throw new Error(`No advisory found for ${name}`);
  }
  return names.length;
}

function main() {
  const docs = fileURLToPath(new URL("../", import.meta.url));
  const result = spawnSync("npm", ["audit", "--json"], {
    cwd: docs,
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.signal || ![0, 1].includes(result.status)) {
    throw new Error(`npm audit failed: ${result.error || result.stderr || result.signal || result.status}`);
  }
  // Keep the complete findings visible even when a temporary exception applies.
  process.stdout.write(result.stdout);
  const report = JSON.parse(result.stdout);
  const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  const count = checkAudit(report, lock);
  console.log(`Docs audit passed with ${count} findings covered by the braces exception, expiring 2026-11-03.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
