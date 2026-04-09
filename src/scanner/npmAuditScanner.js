/**
 * npmAuditScanner.js
 * ──────────────────
 * Runs `npm audit --json` on a target Node.js project and parses
 * the output into a structured vulnerability list.
 *
 * Exports:
 *   - runAudit(projectPath)   → full parsed audit result
 *   - getVulnSummary(audit)   → { critical, high, medium, low, total }
 *   - getVulnList(audit)      → [{ name, severity, via, range, fixAvailable, ... }]
 */

const { execSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

// ─── Run npm audit ───────────────────────────────────────────────

/**
 * Execute `npm audit --json` in the target project directory.
 * @param {string} projectPath - Absolute path to the Node.js project root
 * @returns {object} Raw parsed JSON output from npm audit
 */
function runAudit(projectPath) {
  // Validate the project path
  const pkgPath = path.join(projectPath, "package.json");
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`No package.json found at ${pkgPath}`);
  }

  const lockPath = path.join(projectPath, "package-lock.json");
  if (!fs.existsSync(lockPath)) {
    console.warn(
      "[ShieldBot] WARNING: No package-lock.json found. Running npm install first..."
    );
    try {
      execSync("npm install --package-lock-only", {
        cwd: projectPath,
        stdio: "pipe",
        timeout: 120_000,
      });
    } catch (err) {
      throw new Error(`Failed to generate package-lock.json: ${err.message}`);
    }
  }

  let rawOutput;
  try {
    // npm audit exits with non-zero code when vulnerabilities are found,
    // so we catch that and still parse the JSON output
    rawOutput = execSync("npm audit --json", {
      cwd: projectPath,
      stdio: "pipe",
      timeout: 60_000,
      encoding: "utf-8",
    });
  } catch (err) {
    // npm audit exits code 1 when vulns exist — that's expected
    if (err.stdout) {
      rawOutput = err.stdout;
    } else {
      throw new Error(`npm audit failed: ${err.message}`);
    }
  }

  try {
    return JSON.parse(rawOutput);
  } catch {
    throw new Error("Failed to parse npm audit JSON output");
  }
}

// ─── Extract Vulnerability Summary ──────────────────────────────

/**
 * Pull the severity counts from the raw audit output.
 * @param {object} auditResult - Parsed JSON from runAudit()
 * @returns {{ critical: number, high: number, medium: number, low: number, info: number, total: number }}
 */
function getVulnSummary(auditResult) {
  const meta = auditResult.metadata?.vulnerabilities || {};
  return {
    critical: meta.critical || 0,
    high: meta.high || 0,
    medium: meta.medium || 0,
    low: meta.low || 0,
    info: meta.info || 0,
    total: meta.total || 0,
  };
}

// ─── Extract Structured Vulnerability List ──────────────────────

/**
 * Convert the raw audit advisories into a clean array of vulnerability objects.
 * @param {object} auditResult - Parsed JSON from runAudit()
 * @returns {Array<object>} List of vulnerability entries
 */
function getVulnList(auditResult) {
  const vulnerabilities = auditResult.vulnerabilities || {};
  const results = [];

  for (const [pkgName, entry] of Object.entries(vulnerabilities)) {
    // Each 'via' can be an advisory object or a string (transitive reference)
    const advisories = (entry.via || []).filter(
      (v) => typeof v === "object"
    );
    const transitiveVia = (entry.via || []).filter(
      (v) => typeof v === "string"
    );

    const vuln = {
      packageName: pkgName,
      severity: entry.severity || "unknown",
      isDirect: entry.isDirect || false,
      range: entry.range || "*",
      fixAvailable: entry.fixAvailable || false,
      effects: entry.effects || [],

      // Advisory details (CVE, URL, title)
      advisories: advisories.map((adv) => ({
        id: adv.source || null,
        title: adv.title || "Unknown",
        url: adv.url || null,
        severity: adv.severity || entry.severity,
        cwe: adv.cwe || [],
        cvss: adv.cvss?.score || null,
        range: adv.range || "*",
      })),

      // Packages that pull this in transitively
      transitiveVia,

      // Fix info
      fixInfo: parseFixInfo(entry.fixAvailable),
    };

    results.push(vuln);
  }

  // Sort: critical first, then high, medium, low
  const severityOrder = { critical: 0, high: 1, moderate: 2, medium: 2, low: 3, info: 4 };
  results.sort(
    (a, b) =>
      (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  return results;
}

// ─── Helpers ────────────────────────────────────────────────────

/**
 * Parse the fixAvailable field which can be boolean or an object.
 */
function parseFixInfo(fixAvailable) {
  if (typeof fixAvailable === "boolean") {
    return { canFix: fixAvailable, name: null, version: null, isSemVerMajor: false };
  }
  if (typeof fixAvailable === "object" && fixAvailable !== null) {
    return {
      canFix: true,
      name: fixAvailable.name || null,
      version: fixAvailable.version || null,
      isSemVerMajor: fixAvailable.isSemVerMajor || false,
    };
  }
  return { canFix: false, name: null, version: null, isSemVerMajor: false };
}

// ─── Convenience: Full Scan ─────────────────────────────────────

/**
 * Run a complete scan and return both summary and detailed vulnerability list.
 * @param {string} projectPath - Path to the Node.js project
 * @returns {{ summary: object, vulnerabilities: Array<object>, raw: object }}
 */
async function fullScan(projectPath) {
  console.log(`[ShieldBot:Scanner] Scanning project at: ${projectPath}`);
  const startTime = Date.now();

  const auditResult = runAudit(projectPath);
  const summary = getVulnSummary(auditResult);
  const vulnerabilities = getVulnList(auditResult);

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(
    `[ShieldBot:Scanner] Scan complete in ${elapsed}s — Found ${summary.total} vulnerabilities ` +
    `(🔴 ${summary.critical} critical, 🟠 ${summary.high} high, 🟡 ${summary.medium} medium, 🟢 ${summary.low} low)`
  );

  return { summary, vulnerabilities, raw: auditResult };
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  runAudit,
  getVulnSummary,
  getVulnList,
  fullScan,
};
