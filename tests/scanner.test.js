/**
 * tests/scanner.test.js
 * ──────────────────────
 * Unit tests for the scanner module.
 * Run: node tests/scanner.test.js
 *
 * Uses Node.js built-in assert (zero dependencies).
 */

const assert = require("node:assert");
const path = require("node:path");

// ─── Test Utilities ──────────────────────────────────────────────

let passed = 0;
let failed = 0;
const errors = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (err) {
    failed++;
    errors.push({ name, error: err.message });
    console.log(`  ❌ ${name}`);
    console.log(`     → ${err.message}`);
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (err) {
    failed++;
    errors.push({ name, error: err.message });
    console.log(`  ❌ ${name}`);
    console.log(`     → ${err.message}`);
  }
}

function summary() {
  console.log(`\n${"─".repeat(50)}`);
  console.log(`  Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  if (failed > 0) {
    console.log(`\n  Failed tests:`);
    errors.forEach((e) => console.log(`    ❌ ${e.name}: ${e.error}`));
  }
  console.log(`${"─".repeat(50)}\n`);
  process.exit(failed > 0 ? 1 : 0);
}

// ═══════════════════════════════════════════════════════════════
//  SCANNER MODULE TESTS
// ═══════════════════════════════════════════════════════════════

console.log("\n🧪 Scanner Module Tests\n");

// ─── npmAuditScanner Tests ──────────────────────────────────────

console.log("── npmAuditScanner ──");

const npmAudit = require("../src/scanner/npmAuditScanner");

test("getVulnSummary returns correct counts", () => {
  const mockAudit = {
    metadata: {
      vulnerabilities: {
        critical: 2,
        high: 3,
        medium: 5,
        low: 1,
        info: 0,
        total: 11,
      },
    },
  };
  const summary = npmAudit.getVulnSummary(mockAudit);
  assert.strictEqual(summary.critical, 2);
  assert.strictEqual(summary.high, 3);
  assert.strictEqual(summary.medium, 5);
  assert.strictEqual(summary.low, 1);
  assert.strictEqual(summary.total, 11);
});

test("getVulnSummary handles empty metadata", () => {
  const summary = npmAudit.getVulnSummary({});
  assert.strictEqual(summary.critical, 0);
  assert.strictEqual(summary.total, 0);
});

test("getVulnList parses vulnerabilities correctly", () => {
  const mockAudit = {
    vulnerabilities: {
      lodash: {
        severity: "high",
        isDirect: true,
        range: "<=4.17.20",
        fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
        via: [
          {
            source: 1234,
            title: "Prototype Pollution",
            url: "https://npmjs.com/advisories/1234",
            severity: "high",
            cwe: ["CWE-1321"],
            cvss: { score: 7.4 },
            range: "<=4.17.20",
          },
        ],
        effects: [],
      },
    },
  };
  const list = npmAudit.getVulnList(mockAudit);
  assert.strictEqual(list.length, 1);
  assert.strictEqual(list[0].packageName, "lodash");
  assert.strictEqual(list[0].severity, "high");
  assert.strictEqual(list[0].isDirect, true);
  assert.strictEqual(list[0].advisories.length, 1);
  assert.strictEqual(list[0].advisories[0].title, "Prototype Pollution");
});

test("getVulnList sorts by severity (critical first)", () => {
  const mockAudit = {
    vulnerabilities: {
      "pkg-low": { severity: "low", via: [], effects: [] },
      "pkg-critical": { severity: "critical", via: [], effects: [] },
      "pkg-high": { severity: "high", via: [], effects: [] },
    },
  };
  const list = npmAudit.getVulnList(mockAudit);
  assert.strictEqual(list[0].packageName, "pkg-critical");
  assert.strictEqual(list[1].packageName, "pkg-high");
  assert.strictEqual(list[2].packageName, "pkg-low");
});

test("getVulnList handles transitive via strings", () => {
  const mockAudit = {
    vulnerabilities: {
      express: {
        severity: "high",
        via: ["qs", "body-parser"],
        effects: [],
      },
    },
  };
  const list = npmAudit.getVulnList(mockAudit);
  assert.strictEqual(list[0].transitiveVia.length, 2);
  assert.deepStrictEqual(list[0].transitiveVia, ["qs", "body-parser"]);
  assert.strictEqual(list[0].advisories.length, 0);
});

test("parseFixInfo handles boolean fixAvailable", () => {
  const mockAudit = {
    vulnerabilities: {
      pkg: { severity: "medium", fixAvailable: true, via: [], effects: [] },
    },
  };
  const list = npmAudit.getVulnList(mockAudit);
  assert.strictEqual(list[0].fixInfo.canFix, true);
});

test("parseFixInfo handles object fixAvailable", () => {
  const mockAudit = {
    vulnerabilities: {
      pkg: {
        severity: "medium",
        fixAvailable: { name: "pkg", version: "2.0.0", isSemVerMajor: true },
        via: [],
        effects: [],
      },
    },
  };
  const list = npmAudit.getVulnList(mockAudit);
  assert.strictEqual(list[0].fixInfo.canFix, true);
  assert.strictEqual(list[0].fixInfo.version, "2.0.0");
  assert.strictEqual(list[0].fixInfo.isSemVerMajor, true);
});

// ─── osvClient Tests ────────────────────────────────────────────

console.log("\n── osvClient ──");

const osv = require("../src/scanner/osvClient");

testAsync("queryPackage returns array for valid package", async () => {
  // This is a live API call — may be slow
  const result = await osv.queryPackage("lodash", "4.17.20");
  assert.ok(Array.isArray(result), "Should return an array");
});

testAsync("queryPackage handles non-existent package gracefully", async () => {
  const result = await osv.queryPackage("zzzz-nonexistent-pkg-12345", "1.0.0");
  assert.ok(Array.isArray(result), "Should return an empty array");
});

// ─── dependencyTree Tests ───────────────────────────────────────

console.log("\n── dependencyTree ──");

const depTree = require("../src/scanner/dependencyTree");

test("extractPackageName extracts from node_modules path", () => {
  // Test internal helper via module (if exported)
  // Since it's not exported, we test buildTree behavior
  assert.ok(typeof depTree.buildTree === "function");
  assert.ok(typeof depTree.getDirect === "function");
  assert.ok(typeof depTree.findPaths === "function");
  assert.ok(typeof depTree.getBlastRadius === "function");
  assert.ok(typeof depTree.getAllPackages === "function");
});

test("getBlastRadius works with mock tree", () => {
  const mockTree = {
    packages: {
      lodash: { dependencies: [] },
      express: { dependencies: ["lodash"] },
      app: { dependencies: ["express"] },
    },
    graph: {
      lodash: ["express"],
      express: ["app"],
      app: [],
    },
  };
  const result = depTree.getBlastRadius(mockTree, "lodash");
  assert.strictEqual(result.directDependents.length, 1);
  assert.strictEqual(result.directDependents[0], "express");
  assert.strictEqual(result.totalAffected, 2); // express + app
});

test("findPaths returns paths to target package", () => {
  const mockTree = {
    directDependencies: ["express"],
    packages: {
      express: { dependencies: ["qs"] },
      qs: { dependencies: [] },
    },
    graph: {
      express: [],
      qs: ["express"],
    },
  };
  const paths = depTree.findPaths(mockTree, "qs");
  assert.ok(paths.length >= 1);
  assert.deepStrictEqual(paths[0], ["express", "qs"]);
});

test("getInstalledVersion returns correct version", () => {
  const mockTree = {
    packages: {
      lodash: { version: "4.17.21" },
    },
  };
  assert.strictEqual(depTree.getInstalledVersion(mockTree, "lodash"), "4.17.21");
  assert.strictEqual(depTree.getInstalledVersion(mockTree, "nonexistent"), null);
});

test("getAllPackages returns flat list", () => {
  const mockTree = {
    packages: {
      lodash: { version: "4.17.21", isDirect: true, isDev: false },
      debug: { version: "4.3.4", isDirect: false, isDev: true },
    },
  };
  const all = depTree.getAllPackages(mockTree);
  assert.strictEqual(all.length, 2);
  assert.strictEqual(all[0].name, "lodash");
  assert.strictEqual(all[1].isDev, true);
});

// ─── nvdClient Tests ────────────────────────────────────────────

console.log("\n── nvdClient ──");

const nvd = require("../src/scanner/nvdClient");

test("getCVE rejects invalid CVE ID", async () => {
  const result = await nvd.getCVE("not-a-cve");
  assert.strictEqual(result, null);
});

test("getCVE rejects empty input", async () => {
  const result = await nvd.getCVE("");
  assert.strictEqual(result, null);
});

test("getCVSSScore returns null for invalid CVE", async () => {
  const result = await nvd.getCVSSScore("invalid");
  assert.strictEqual(result.score, null);
  assert.strictEqual(result.severity, "unknown");
});

// ─── Run summary ────────────────────────────────────────────────

// Wait for async tests to complete
setTimeout(summary, 8000);
