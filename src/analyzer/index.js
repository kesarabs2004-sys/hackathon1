/**
 * analyzer/index.js
 * ──────────────────
 * Barrel export for the analyzer module.
 * Orchestrates: reachability analysis → risk classification → health scoring → typosquat detection.
 *
 * Usage:
 *   const analyzer = require("./src/analyzer");
 *   const results = await analyzer.analyze(projectPath, scanResults);
 */

const riskClassifier = require("./riskClassifier");
const reachabilityAnalyzer = require("./reachabilityAnalyzer");
const healthScorer = require("./healthScorer");
const typosquatDetector = require("./typosquatDetector");

/**
 * Run the full analysis pipeline on scan results.
 *
 * Pipeline:
 *   1. Reachability analysis  → mark phantom vs reachable vulns
 *   2. Risk classification    → composite CARP scoring
 *   3. Typosquat detection    → flag suspicious package names
 *   4. Health scoring         → grade every dependency A+ to F
 *
 * @param {string} projectPath   - Absolute path to the project root
 * @param {object} scanResults   - Output from scanner.scan()
 * @param {object} options       - { skipHealth: bool, skipTyposquat: bool }
 * @returns {Promise<object>}    Complete analysis results
 */
async function analyze(projectPath, scanResults, options = {}) {
  const startTime = Date.now();
  console.log(`\n${"═".repeat(60)}`);
  console.log(`  🔬 ShieldBot Analyzer — Full Analysis Pipeline`);
  console.log(`${"═".repeat(60)}\n`);

  let vulnList = scanResults.vulnerabilities || [];

  // ── Step 1: Reachability Analysis ──
  console.log("[1/4] Running reachability analysis (AST scan)...");
  vulnList = reachabilityAnalyzer.enrichWithReachability(projectPath, vulnList);

  // ── Step 2: Risk Classification (CARP) ──
  console.log("\n[2/4] Computing composite risk scores (CARP)...");
  vulnList = riskClassifier.classifyAll(vulnList);

  // ── Step 3: Typosquat Detection ──
  let typosquatResults = [];
  if (!options.skipTyposquat) {
    console.log("\n[3/4] Checking for typosquatting attacks...");
    const allPkgNames = (scanResults.allPackages || []).map((p) => p.name);
    typosquatResults = typosquatDetector.checkAll(allPkgNames);
  } else {
    console.log("\n[3/4] Skipping typosquat detection");
  }

  // ── Step 4: Health Scoring ──
  let healthResults = [];
  if (!options.skipHealth) {
    console.log("\n[4/4] Computing dependency health scores...");
    const directPkgs = (scanResults.allPackages || []).filter((p) => p.isDirect);

    // Pass CVE counts and typosquat scores as extra data
    const extraData = {};
    for (const vuln of vulnList) {
      const name = vuln.packageName;
      if (!extraData[name]) extraData[name] = { cveCount: 0, typosquatScore: 0 };
      extraData[name].cveCount++;
    }
    for (const ts of typosquatResults) {
      if (ts.isSuspicious) {
        if (!extraData[ts.packageName]) extraData[ts.packageName] = { cveCount: 0 };
        extraData[ts.packageName].typosquatScore = ts.riskScore;
      }
    }

    healthResults = await healthScorer.scoreAll(directPkgs, extraData);
  } else {
    console.log("\n[4/4] Skipping health scoring");
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  // ── Build Results ──
  const riskMatrix = riskClassifier.generateRiskMatrix(vulnList);
  const healthReport = healthResults.length > 0
    ? healthScorer.generateHealthReport(healthResults)
    : null;

  const suspiciousPkgs = typosquatResults.filter((t) => t.isSuspicious);

  // ── Summary ──
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  Analysis Complete in ${duration}s`);
  console.log(`  📊 Risk Matrix:`);
  console.log(`     🔴 Critical: ${riskMatrix.bySeverity.critical}`);
  console.log(`     🟠 High:     ${riskMatrix.bySeverity.high}`);
  console.log(`     🟡 Medium:   ${riskMatrix.bySeverity.medium}`);
  console.log(`     🟢 Low:      ${riskMatrix.bySeverity.low}`);
  console.log(`     ⚪ Phantom:  ${riskMatrix.byReachability.phantom}`);
  console.log(`     💀 Exploitable: ${riskMatrix.byExploitability.exploitable}`);
  if (suspiciousPkgs.length > 0) {
    console.log(`  🎭 Typosquat Alerts: ${suspiciousPkgs.length}`);
  }
  if (healthReport) {
    console.log(`  💚 Avg Health Score: ${healthReport.averageHealthScore}% (${healthReport.overallGrade})`);
  }
  console.log(`${"─".repeat(60)}\n`);

  return {
    vulnerabilities: vulnList,
    riskMatrix,
    typosquatAlerts: suspiciousPkgs,
    healthScores: healthResults,
    healthReport,
    analysisDuration: duration,
    timestamp: new Date().toISOString(),
  };
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  analyze,
  // Re-export sub-modules
  riskClassifier,
  reachabilityAnalyzer,
  healthScorer,
  typosquatDetector,
};
