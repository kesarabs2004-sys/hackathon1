/**
 * tests/analyzer.test.js
 * ───────────────────────
 * Unit tests for the analyzer module.
 * Run: node tests/analyzer.test.js
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
//  ANALYZER MODULE TESTS
// ═══════════════════════════════════════════════════════════════

console.log("\n🧪 Analyzer Module Tests\n");

// ─── riskClassifier Tests ───────────────────────────────────────

console.log("── riskClassifier ──");

const riskClassifier = require("../src/analyzer/riskClassifier");

test("classifyRisk computes composite score", () => {
  const vuln = {
    packageName: "lodash",
    severity: "high",
    blastRadius: 10,
    nvd: { cvssScore: 7.5 },
    reachability: { isReachable: true },
    advisories: [],
  };
  const result = riskClassifier.classifyRisk(vuln);
  assert.ok(result.risk, "Should have .risk field");
  assert.ok(result.risk.score > 0, "Score should be > 0");
  assert.ok(result.risk.score <= 10, "Score should be <= 10");
  assert.ok(result.risk.label, "Should have severity label");
  assert.ok(result.risk.recommendation, "Should have recommendation");
});

test("classifyRisk marks phantom vulns correctly", () => {
  const vuln = {
    packageName: "qs",
    severity: "medium",
    blastRadius: 2,
    nvd: { cvssScore: 5.0 },
    reachability: { isReachable: false },
    advisories: [],
  };
  const result = riskClassifier.classifyRisk(vuln);
  assert.strictEqual(result.risk.isPhantom, true);
  assert.ok(result.risk.recommendation.includes("PHANTOM"));
});

test("classifyRisk falls back to severity when no CVSS", () => {
  const vuln = {
    packageName: "test-pkg",
    severity: "critical",
    blastRadius: 0,
    advisories: [],
  };
  const result = riskClassifier.classifyRisk(vuln);
  assert.ok(result.risk.score > 0, "Should compute score from severity string");
});

test("classifyAll sorts by risk score descending", () => {
  const vulns = [
    { packageName: "low-risk", severity: "low", blastRadius: 0, advisories: [] },
    { packageName: "high-risk", severity: "critical", blastRadius: 50, nvd: { cvssScore: 10 }, reachability: { isReachable: true }, advisories: [] },
    { packageName: "mid-risk", severity: "medium", blastRadius: 5, advisories: [] },
  ];
  const result = riskClassifier.classifyAll(vulns);
  assert.strictEqual(result[0].packageName, "high-risk");
  assert.ok(result[0].risk.score >= result[1].risk.score);
  assert.ok(result[1].risk.score >= result[2].risk.score);
});

test("getSeverityLabel returns correct labels", () => {
  assert.strictEqual(riskClassifier.getSeverityLabel(9.5), "critical");
  assert.strictEqual(riskClassifier.getSeverityLabel(7.5), "high");
  assert.strictEqual(riskClassifier.getSeverityLabel(5.0), "medium");
  assert.strictEqual(riskClassifier.getSeverityLabel(2.0), "low");
  assert.strictEqual(riskClassifier.getSeverityLabel(0), "info");
});

test("generateRiskMatrix builds correct summary", () => {
  const classified = [
    { packageName: "a", risk: { score: 9.5, label: "critical", isPhantom: false, isExploitable: true, breakdown: { reachability: { value: 1.0 } } } },
    { packageName: "b", risk: { score: 5.0, label: "medium", isPhantom: true, isExploitable: false, breakdown: { reachability: { value: 0.0 } } } },
  ];
  const matrix = riskClassifier.generateRiskMatrix(classified);
  assert.strictEqual(matrix.total, 2);
  assert.strictEqual(matrix.bySeverity.critical, 1);
  assert.strictEqual(matrix.bySeverity.medium, 1);
  assert.strictEqual(matrix.byReachability.phantom, 1);
  assert.strictEqual(matrix.byExploitability.exploitable, 1);
  assert.strictEqual(matrix.topRisks.length, 2);
});

test("WEIGHTS sum to 1.0", () => {
  const total = Object.values(riskClassifier.WEIGHTS).reduce((a, b) => a + b, 0);
  assert.ok(Math.abs(total - 1.0) < 0.001, `Weights sum to ${total}, expected 1.0`);
});

// ─── typosquatDetector Tests ────────────────────────────────────

console.log("\n── typosquatDetector ──");

const typosquat = require("../src/analyzer/typosquatDetector");

test("levenshtein distance is correct", () => {
  assert.strictEqual(typosquat.levenshtein("kitten", "sitting"), 3);
  assert.strictEqual(typosquat.levenshtein("abc", "abc"), 0);
  assert.strictEqual(typosquat.levenshtein("", "abc"), 3);
  assert.strictEqual(typosquat.levenshtein("abc", ""), 3);
});

test("getSimilarityScore returns normalized value", () => {
  const score = typosquat.getSimilarityScore("lodash", "lodash");
  assert.strictEqual(score, 1);

  const diff = typosquat.getSimilarityScore("abc", "xyz");
  assert.ok(diff < 0.5, "Very different strings should have low score");
});

test("checkPackage detects single-char-edit typosquatting", () => {
  const result = typosquat.checkPackage("lodasb");  // 1 edit from "lodash"
  assert.ok(result.riskScore > 0.5, `Score ${result.riskScore} should be high`);
  assert.strictEqual(result.similarTo, "lodash");
});

test("checkPackage detects character swap", () => {
  const result = typosquat.checkPackage("loadsh");  // swap a↔d in lodash
  assert.ok(result.isSuspicious, "Should be flagged as suspicious");
  assert.ok(result.attackType === "character-swap" || result.attackType === "single-char-edit");
});

test("checkPackage returns safe for known popular package", () => {
  const result = typosquat.checkPackage("lodash");
  assert.strictEqual(result.isSuspicious, false);
  assert.strictEqual(result.riskScore, 0);
});

test("checkPackage detects suffix manipulation", () => {
  const result = typosquat.checkPackage("express-js");
  assert.ok(result.riskScore > 0.5, "Should detect suffix addition");
  assert.strictEqual(result.similarTo, "express");
});

test("checkPackage handles homoglyph (l→1)", () => {
  const result = typosquat.checkPackage("1odash");  // l replaced with 1
  assert.ok(result.riskScore > 0.5, "Homoglyph attack should score high");
});

test("checkAll batch processes correctly", () => {
  const results = typosquat.checkAll(["lodash", "loadsh", "totally-unique-pkg-999"]);
  assert.strictEqual(results.length, 3);
  assert.strictEqual(results[0].isSuspicious, false); // lodash is legit
  assert.strictEqual(results[1].isSuspicious, true);  // loadsh is suspicious
});

test("enrichWithTyposquatting adds .typosquat field", () => {
  const pkgs = [{ name: "lodash" }, { name: "loadsh" }];
  const enriched = typosquat.enrichWithTyposquatting(pkgs);
  assert.ok(enriched[0].typosquat, "Should have .typosquat field");
  assert.strictEqual(enriched[0].typosquat.isSuspicious, false);
  assert.strictEqual(enriched[1].typosquat.isSuspicious, true);
});

// ─── healthScorer Tests ─────────────────────────────────────────

console.log("\n── healthScorer ──");

const healthScorer = require("../src/analyzer/healthScorer");

test("scorePackage computes score for healthy package", () => {
  const score = healthScorer.scorePackage("express", "4.18.2", {
    cveCount: 0,
    lastPublishDate: new Date().toISOString(),
    weeklyDownloads: 1000000,
    prevWeekDownloads: 900000,
    license: "MIT",
    directDepCount: 3,
    typosquatScore: 0,
  });
  assert.ok(score.healthScore >= 80, `Healthy pkg should score high, got ${score.healthScore}`);
  assert.ok(score.grade === "A+" || score.grade === "A", `Grade should be A+/A, got ${score.grade}`);
  assert.strictEqual(score.flags.length, 0);
});

test("scorePackage computes low score for risky package", () => {
  const score = healthScorer.scorePackage("bad-pkg", "1.0.0", {
    cveCount: 6,
    lastPublishDate: "2020-01-01",
    weeklyDownloads: 10,
    prevWeekDownloads: 1000,
    license: "UNKNOWN",
    directDepCount: 60,
    typosquatScore: 0.8,
  });
  assert.ok(score.healthScore < 30, `Risky pkg should score low, got ${score.healthScore}`);
  assert.ok(score.grade === "F" || score.grade === "D", `Grade should be D/F, got ${score.grade}`);
  assert.ok(score.flags.length >= 3, "Should have multiple flags");
});

test("getGrade returns correct grades", () => {
  assert.strictEqual(healthScorer.getGrade(95), "A+");
  assert.strictEqual(healthScorer.getGrade(85), "A");
  assert.strictEqual(healthScorer.getGrade(70), "B");
  assert.strictEqual(healthScorer.getGrade(55), "C");
  assert.strictEqual(healthScorer.getGrade(40), "D");
  assert.strictEqual(healthScorer.getGrade(20), "F");
});

test("WEIGHTS sum to 1.0", () => {
  const total = Object.values(healthScorer.WEIGHTS).reduce((a, b) => a + b, 0);
  assert.ok(Math.abs(total - 1.0) < 0.001, `Weights sum to ${total}, expected 1.0`);
});

test("generateHealthReport computes averages", () => {
  const scored = [
    { healthScore: 90, grade: "A+", packageName: "a" },
    { healthScore: 40, grade: "D", packageName: "b" },
    { healthScore: 60, grade: "B", packageName: "c" },
  ];
  const report = healthScorer.generateHealthReport(scored);
  assert.strictEqual(report.totalPackages, 3);
  assert.strictEqual(report.averageHealthScore, 63);
  assert.strictEqual(report.overallGrade, "B");
  assert.strictEqual(report.gradeDistribution["A+"], 1);
  assert.strictEqual(report.gradeDistribution.D, 1);
});

test("generateHealthReport identifies risky packages", () => {
  const scored = [
    { healthScore: 90, grade: "A+", packageName: "safe", flags: [] },
    { healthScore: 25, grade: "F", packageName: "danger", flags: ["🔴 Bad"] },
  ];
  const report = healthScorer.generateHealthReport(scored);
  assert.strictEqual(report.riskyPackages.length, 1);
  assert.strictEqual(report.riskyPackages[0].name, "danger");
});

// ─── reachabilityAnalyzer Tests ─────────────────────────────────

console.log("\n── reachabilityAnalyzer ──");

const reachability = require("../src/analyzer/reachabilityAnalyzer");

test("getSourceFiles finds JS files", () => {
  const projectRoot = path.resolve(__dirname, "..");
  const files = reachability.getSourceFiles(projectRoot);
  assert.ok(files.length > 0, "Should find source files in project");
  assert.ok(files.every((f) => /\.(js|mjs|cjs|ts|jsx|tsx)$/.test(f)), "Should only find JS/TS files");
});

test("getSourceFiles skips node_modules", () => {
  const projectRoot = path.resolve(__dirname, "..");
  const files = reachability.getSourceFiles(projectRoot);
  assert.ok(
    files.every((f) => !f.includes("node_modules")),
    "Should not include node_modules files"
  );
});

test("findImportsInFile detects require statements", () => {
  // Create a temp file for testing
  const fs = require("node:fs");
  const tmpFile = path.join(__dirname, "_test_imports_temp.js");
  fs.writeFileSync(tmpFile, `
const lodash = require("lodash");
const { merge, clone } = require("lodash");
const express = require("express");
`);

  try {
    const imports = reachability.findImportsInFile(tmpFile, "lodash");
    assert.strictEqual(imports.length, 2, `Expected 2 lodash imports, got ${imports.length}`);
    assert.strictEqual(imports[0].variable, "lodash");
    assert.strictEqual(imports[1].isDestructured, true);
    assert.ok(imports[1].destructuredNames.includes("merge"));
    assert.ok(imports[1].destructuredNames.includes("clone"));
  } finally {
    fs.unlinkSync(tmpFile);
  }
});

test("findImportsInFile detects ES import statements", () => {
  const fs = require("node:fs");
  const tmpFile = path.join(__dirname, "_test_esm_temp.js");
  fs.writeFileSync(tmpFile, `
import axios from "axios";
import { get, post } from "axios";
`);

  try {
    const imports = reachability.findImportsInFile(tmpFile, "axios");
    assert.strictEqual(imports.length, 2);
    assert.strictEqual(imports[0].type, "import");
    assert.strictEqual(imports[1].isDestructured, true);
  } finally {
    fs.unlinkSync(tmpFile);
  }
});

test("analyzeReachability reports not-reachable for unused package", () => {
  const fs = require("node:fs");
  const tmpDir = path.join(__dirname, "_test_project_temp");
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.writeFileSync(path.join(tmpDir, "index.js"), `
const express = require("express");
const app = express();
`);

  try {
    const result = reachability.analyzeReachability(tmpDir, "lodash", []);
    assert.strictEqual(result.isReachable, false);
    assert.strictEqual(result.confidence, "high");
  } finally {
    fs.rmSync(tmpDir, { recursive: true });
  }
});

test("analyzeReachability detects reachable package", () => {
  const fs = require("node:fs");
  const tmpDir = path.join(__dirname, "_test_reachable_temp");
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.writeFileSync(path.join(tmpDir, "app.js"), `
const _ = require("lodash");
const result = _.merge({}, { a: 1 });
`);

  try {
    const result = reachability.analyzeReachability(tmpDir, "lodash", ["merge"]);
    assert.strictEqual(result.isReachable, true);
    assert.ok(result.functionCalls.length > 0, "Should detect merge() call");
  } finally {
    fs.rmSync(tmpDir, { recursive: true });
  }
});

test("KNOWN_VULN_FUNCTIONS has expected categories", () => {
  assert.ok(reachability.KNOWN_VULN_FUNCTIONS["prototype-pollution"]);
  assert.ok(reachability.KNOWN_VULN_FUNCTIONS["command-injection"]);
  assert.ok(reachability.KNOWN_VULN_FUNCTIONS["xss"]);
  assert.ok(reachability.KNOWN_VULN_FUNCTIONS["sql-injection"]);
});

// ─── Run summary ────────────────────────────────────────────────

setTimeout(summary, 3000);
