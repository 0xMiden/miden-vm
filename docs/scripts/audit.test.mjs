import assert from "node:assert/strict";
import test from "node:test";
import { checkAudit } from "./audit.mjs";

function fixture() {
  const vulnerabilities = {};
  const packages = {};
  for (const [name, version, id] of [
    ["minimatch", "3.1.5", "GHSA-g3hv-75wg-m249"],
  ]) {
    vulnerabilities[name] = {
      via: [{ name, url: `https://github.com/advisories/${id}`, severity: "moderate" }],
      nodes: [`node_modules/${name}`],
      fixAvailable: false,
    };
    packages[`node_modules/${name}`] = { version };
  }
  vulnerabilities.parent = { via: ["minimatch"] };
  vulnerabilities.grandparent = { via: ["parent"] };
  return [{ auditReportVersion: 2, vulnerabilities }, { packages }];
}

const today = "2026-11-03";

test("accepts only reviewed advisories and their transitive findings", () => {
  const [report, lock] = fixture();
  // Exercise dependency resolution when parents appear before causes.
  report.vulnerabilities = Object.fromEntries(Object.entries(report.vulnerabilities).reverse());
  assert.equal(checkAudit(report, lock, today), 3);
  assert.equal(checkAudit({ auditReportVersion: 2, vulnerabilities: {} }, lock, today), 0);
});

test("rejects a new advisory on an excepted package", () => {
  const [report, lock] = fixture();
  report.vulnerabilities.minimatch.via.push({ name: "minimatch", url: "https://github.com/advisories/GHSA-new" });
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
  for (const version of ["3.1.4", undefined]) {
    const [report, lock] = fixture();
    report.vulnerabilities.minimatch.nodes.push("node_modules/parent/node_modules/minimatch");
    lock.packages["node_modules/parent/node_modules/minimatch"] = { version };
    assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
  }
});

test("rejects expired exceptions, available fixes, and increased severity", () => {
  const [report, lock] = fixture();
  assert.throws(() => checkAudit(report, lock, "2026-12-03"), /Unaccepted/);
  assert.throws(() => checkAudit(report, lock, "2026-12-04"), /Unaccepted/);
  report.vulnerabilities.minimatch.fixAvailable = true;
  assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
  report.vulnerabilities.minimatch.fixAvailable = false;
  report.vulnerabilities.minimatch.via[0].severity = "high";
  assert.throws(() => checkAudit(report, lock, today), /Unaccepted/);
});

test("rejects npm errors and unexpected report formats", () => {
  const [, lock] = fixture();
  for (const report of [{ error: { code: "E503" } }, {}, { auditReportVersion: 1, vulnerabilities: {} }]) {
    assert.throws(() => checkAudit(report, lock, today), /valid version 2 report/);
  }
});

test("rejects the withdrawn braces exception", () => {
  const report = {
    auditReportVersion: 2,
    vulnerabilities: {
      braces: {
        via: [{ name: "braces", url: "https://github.com/advisories/GHSA-vfj7-8cjw-p6xm", severity: "high" }],
        nodes: ["node_modules/braces"],
        fixAvailable: false,
      },
    },
  };
  const lock = { packages: { "node_modules/braces": { version: "3.0.3" } } };
  assert.throws(() => checkAudit(report, lock, "2026-10-03"), /Unaccepted/);
});
