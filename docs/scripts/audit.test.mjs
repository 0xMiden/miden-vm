import assert from "node:assert/strict";
import test from "node:test";
import { checkAudit } from "./audit.mjs";

function fixture(name = "braces", version = "3.0.3", id = "GHSA-vfj7-8cjw-p6xm") {
  const vulnerabilities = {
    [name]: {
      via: [{ name, url: `https://github.com/advisories/${id}`, severity: "high" }],
      nodes: [`node_modules/${name}`],
      fixAvailable: false,
    },
    parent: { via: [name] },
    grandparent: { via: ["parent"] },
  };
  const packages = { [`node_modules/${name}`]: { version } };
  return [{ auditReportVersion: 2, vulnerabilities }, { packages }];
}

const today = "2026-10-03";

test("accepts only reviewed advisories and their transitive findings", () => {
  const [report, lock] = fixture();
  // Exercise dependency resolution when parents appear before causes.
  report.vulnerabilities = Object.fromEntries(Object.entries(report.vulnerabilities).reverse());
  assert.equal(checkAudit(report, lock, today), 3);
  assert.equal(checkAudit({ auditReportVersion: 2, vulnerabilities: {} }, lock, today), 0);
});

test("rejects a new advisory on an excepted package", () => {
  const [report, lock] = fixture();
  report.vulnerabilities.braces.via.push({ name: "braces", url: "https://github.com/advisories/GHSA-new" });
  assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
});

test("accepts parent cycles only when every advisory is reviewed", () => {
  const [report, lock] = fixture();
  report.vulnerabilities.parent.via.push("grandparent");
  assert.equal(checkAudit(report, lock, today), 3);
  report.vulnerabilities.grandparent.via.push({ name: "grandparent", url: "https://github.com/advisories/GHSA-new" });
  assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
});

test("rejects unknown findings, missing causes, and cycles", () => {
  for (const via of [[{ name: "other", url: "https://github.com/advisories/GHSA-new" }], ["missing"], ["other"], []]) {
    const [report, lock] = fixture();
    report.vulnerabilities.other = { via };
    assert.throws(() => checkAudit(report, lock, today));
  }
});

test("rejects the removed http-cache-semantics exception", () => {
  const [report, lock] = fixture();
  report.vulnerabilities["http-cache-semantics"] = {
    via: [{
      name: "http-cache-semantics",
      url: "https://github.com/advisories/GHSA-ch52-4w7c-c8xp",
      severity: "high",
    }],
    nodes: ["node_modules/http-cache-semantics"],
    fixAvailable: false,
  };
  lock.packages["node_modules/http-cache-semantics"] = { version: "4.2.0" };
  assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
});

test("rejects changed and missing locked versions, including nested copies", () => {
  for (const version of ["3.0.2", undefined]) {
    const [report, lock] = fixture();
    report.vulnerabilities.braces.nodes.push("node_modules/parent/node_modules/braces");
    lock.packages["node_modules/parent/node_modules/braces"] = { version };
    assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
  }
});

test("rejects expired exceptions, available fixes, and increased severity", () => {
  const [report, lock] = fixture();
  assert.throws(() => checkAudit(report, lock, "2026-11-03"), /Unaccepted/);
  assert.throws(() => checkAudit(report, lock, "2026-11-04"), /Unaccepted/);
  report.vulnerabilities.braces.fixAvailable = true;
  assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
  report.vulnerabilities.braces.fixAvailable = false;
  report.vulnerabilities.braces.via[0].severity = "critical";
  assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
});

test("rejects npm errors and unexpected report formats", () => {
  const [, lock] = fixture();
  for (const report of [{ error: { code: "E503" } }, {}, { auditReportVersion: 1, vulnerabilities: {} }]) {
    assert.throws(() => checkAudit(report, lock, today), /valid version 2 report/);
  }
});

test("picomatch exception requires the reviewed version and an unexpired date", () => {
  const [report, lock] = fixture("picomatch", "2.3.2", "GHSA-fc5q-39xc-vjpf");
  report.vulnerabilities.picomatch.via[0].range = "<=4.0.7";
  const reviewDate = "2026-11-17";
  assert.equal(checkAudit(report, lock, reviewDate, "4.0.7"), 3);
  assert.throws(() => checkAudit(report, lock, "2026-11-24", "4.0.7"), /Unaccepted/);

  lock.packages["node_modules/picomatch"].version = "4.0.7";
  assert.throws(() => checkAudit(report, lock, reviewDate, "4.0.7"), /Unaccepted/);
  lock.packages["node_modules/picomatch"].version = "2.3.2";
  report.vulnerabilities.picomatch.fixAvailable = true;
  assert.throws(() => checkAudit(report, lock, reviewDate, "4.0.7"), /Unaccepted/);
});

test("accepts only the reviewed inapplicable picomatch downgrade", () => {
  const [report, lock] = fixture("picomatch", "2.3.2", "GHSA-fc5q-39xc-vjpf");
  const finding = report.vulnerabilities.picomatch;
  finding.via[0].range = "<=4.0.7";
  finding.fixAvailable = {
    name: "@cmfcmf/docusaurus-search-local",
    version: "0.11.0",
    isSemVerMajor: true,
  };
  assert.equal(checkAudit(report, lock, "2026-11-17", "4.0.7"), 3);

  for (const fix of [
    true,
    { name: "picomatch", version: "4.0.8", isSemVerMajor: true },
    { name: "@cmfcmf/docusaurus-search-local", version: "0.11.1", isSemVerMajor: true },
    { name: "@cmfcmf/docusaurus-search-local", version: "0.11.0", isSemVerMajor: false },
  ]) {
    finding.fixAvailable = fix;
    assert.throws(() => checkAudit(report, lock, "2026-11-17", "4.0.7"), /Unaccepted/);
  }
});

test("rejects changed or unverified picomatch registry data", () => {
  const [report, lock] = fixture("picomatch", "2.3.2", "GHSA-fc5q-39xc-vjpf");
  report.vulnerabilities.picomatch.via[0].range = "<=4.0.7";
  for (const latest of ["4.0.8", "2.3.3", undefined, null]) {
    assert.throws(() => checkAudit(report, lock, "2026-11-17", latest), /Unaccepted/);
  }
  report.vulnerabilities.picomatch.via[0].range = "<2.3.2";
  assert.throws(() => checkAudit(report, lock, "2026-11-17", "4.0.7"), /Unaccepted/);
});
