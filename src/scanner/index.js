/**
 * scanner/index.js
 * ────────────────
 * Barrel export for the scanner module.
 * Orchestrates npm audit → OSV enrichment → NVD enrichment → dependency tree.
 *
 * Usage:
 *   const scanner = require("./src/scanner");
 *   const results = await scanner.scan("/path/to/project");
 */

const npmAudit = require("./npmAuditScanner");
const osv = require("./osvClient");
const nvd = require("./nvdClient");
const depTree = require("./dependencyTree");

/**
 * Run the full scanning pipeline on a Node.js project.
 *
 * Pipeline:
 *   1. npm audit           → raw vulnerability list
 *   2. Dependency tree      → blast radius + transitive paths
 *   3. OSV.dev enrichment   → CVE IDs, detailed advisories
 *   4. NVD enrichment       → accurate CVSS scores
 *
 * @param {string} projectPath - Absolute path to the Node.js project root
 * @param {object} options     - { skipOSV: bool, skipNVD: bool }
 * @returns {Promise<object>}  Complete scan results
 */
async function scan(projectPath, options = {}) {
  const startTime = Date.now();
  console.log(`\n${"═".repeat(60)}`);
  console.log(`  🛡️  ShieldBot Scanner — Full Pipeline`);
  console.log(`  Target: ${projectPath}`);
  console.log(`${"═".repeat(60)}\n`);

  // ── Step 1: npm audit ──
  console.log("[1/4] Running npm audit...");
  const auditResult = await npmAudit.fullScan(projectPath);

  if (auditResult.summary.total === 0) {
    console.log("\n✅ No vulnerabilities found! Project is clean.\n");
    return {
      summary: auditResult.summary,
      vulnerabilities: [],
      dependencyTree: null,
      scanDuration: ((Date.now() - startTime) / 1000).toFixed(2),
    };
  }

  // ── Step 2: Build dependency tree ──
  console.log("\n[2/4] Building dependency tree...");
  const tree = depTree.buildTree(projectPath);

  // Add blast radius and dependency paths to each vulnerability
  let enrichedVulns = auditResult.vulnerabilities.map((vuln) => {
    const blastRadius = depTree.getBlastRadius(tree, vuln.packageName);
    const paths = depTree.findPaths(tree, vuln.packageName);
    const installedVersion = depTree.getInstalledVersion(tree, vuln.packageName);

    return {
      ...vuln,
      installedVersion,
      blastRadius: blastRadius.totalAffected,
      dependencyPaths: paths.slice(0, 5), // Top 5 paths
      isDirect: tree.packages[vuln.packageName]?.isDirect || false,
    };
  });

  // ── Step 3: OSV.dev enrichment (CVE IDs, advisories) ──
  if (!options.skipOSV) {
    console.log("\n[3/4] Enriching with OSV.dev data...");
    enrichedVulns = await osv.enrichWithOSV(enrichedVulns);
  } else {
    console.log("\n[3/4] Skipping OSV enrichment (--skipOSV)");
  }

  // ── Step 4: NVD enrichment (CVSS scores) ──
  if (!options.skipNVD) {
    console.log("\n[4/4] Enriching with NVD CVSS scores...");
    enrichedVulns = await nvd.enrichWithNVD(enrichedVulns);
  } else {
    console.log("\n[4/4] Skipping NVD enrichment (--skipNVD)");
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  // ── Summary ──
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  Scan Complete in ${duration}s`);
  console.log(`  Total Vulnerabilities: ${auditResult.summary.total}`);
  console.log(`  🔴 Critical: ${auditResult.summary.critical}`);
  console.log(`  🟠 High:     ${auditResult.summary.high}`);
  console.log(`  🟡 Medium:   ${auditResult.summary.medium}`);
  console.log(`  🟢 Low:      ${auditResult.summary.low}`);
  console.log(`  📦 Packages Scanned: ${tree.totalPackages}`);
  console.log(`${"─".repeat(60)}\n`);

  return {
    summary: auditResult.summary,
    vulnerabilities: enrichedVulns,
    dependencyTree: {
      totalPackages: tree.totalPackages,
      directDependencies: tree.directDependencies,
      devDependencies: tree.devDependencies,
    },
    allPackages: depTree.getAllPackages(tree),
    scanDuration: duration,
    timestamp: new Date().toISOString(),
  };
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  scan,
  // Re-export individual modules for granular use
  npmAudit,
  osv,
  nvd,
  depTree,
};
