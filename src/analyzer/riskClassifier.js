/**
 * riskClassifier.js
 * ──────────────────
 * Context-Aware Risk Prioritization (CARP) engine.
 *
 * Instead of blindly trusting raw CVSS scores, this module computes a
 * composite risk score that factors in:
 *   - CVSS severity           (40%)
 *   - Reachability            (30%)  — is the vuln function actually called?
 *   - Blast radius            (20%)  — how many packages break if this breaks?
 *   - Exploit maturity        (10%)  — is there a public exploit available?
 *
 * Exports:
 *   - classifyRisk(vuln)            → single vuln with computed risk score
 *   - classifyAll(vulnList)         → sorted list, highest risk first
 *   - getSeverityLabel(score)       → "critical" | "high" | "medium" | "low"
 *   - generateRiskMatrix(vulnList)  → summary matrix for dashboard
 */

// ─── Weight Configuration ───────────────────────────────────────

const WEIGHTS = {
  cvss: 0.40,
  reachability: 0.30,
  blastRadius: 0.20,
  exploitMaturity: 0.10,
};

// ─── Classify a Single Vulnerability ────────────────────────────

/**
 * Compute a composite risk score for a single vulnerability.
 *
 * @param {object} vuln - Enriched vulnerability object (from scanner pipeline)
 *   Expected fields:
 *     - nvd.cvssScore        (number 0-10 or null)
 *     - severity             ("critical"|"high"|"medium"|"low")
 *     - blastRadius          (number, from dependencyTree)
 *     - reachability         (object from reachabilityAnalyzer, optional)
 *     - advisories           (array of advisory objects)
 *
 * @returns {object} Vulnerability with added .risk field
 */
function classifyRisk(vuln) {
  // ── 1. CVSS Score (normalized to 0-1) ──
  const rawCVSS = vuln.nvd?.cvssScore ?? severityToScore(vuln.severity);
  const cvssNormalized = Math.min(rawCVSS / 10, 1);

  // ── 2. Reachability Score (0 or 1) ──
  //   1.0 = vulnerable function IS reachable in code
  //   0.3 = unknown / not analyzed yet (assume partial risk)
  //   0.0 = confirmed NOT reachable (phantom vuln)
  let reachabilityScore = 0.3; // default: unknown
  if (vuln.reachability) {
    if (vuln.reachability.isReachable === true) {
      reachabilityScore = 1.0;
    } else if (vuln.reachability.isReachable === false) {
      reachabilityScore = 0.0;
    }
  }

  // ── 3. Blast Radius (normalized to 0-1) ──
  //   Scale: 0 dependents = 0, 50+ dependents = 1.0
  const blastRadius = vuln.blastRadius || 0;
  const blastNormalized = Math.min(blastRadius / 50, 1);

  // ── 4. Exploit Maturity (0 or 1) ──
  //   Check if there are references to exploit code, poc, or exploit-db
  const exploitMaturity = hasPublicExploit(vuln) ? 1.0 : 0.2;

  // ── Composite Score ──
  const compositeScore =
    WEIGHTS.cvss * cvssNormalized +
    WEIGHTS.reachability * reachabilityScore +
    WEIGHTS.blastRadius * blastNormalized +
    WEIGHTS.exploitMaturity * exploitMaturity;

  // Scale to 0-10 for readability
  const riskScore = Math.round(compositeScore * 100) / 10;

  return {
    ...vuln,
    risk: {
      score: riskScore,
      label: getSeverityLabel(riskScore),
      breakdown: {
        cvss: { raw: rawCVSS, normalized: round(cvssNormalized), weight: WEIGHTS.cvss },
        reachability: { value: round(reachabilityScore), weight: WEIGHTS.reachability },
        blastRadius: { raw: blastRadius, normalized: round(blastNormalized), weight: WEIGHTS.blastRadius },
        exploitMaturity: { value: round(exploitMaturity), weight: WEIGHTS.exploitMaturity },
      },
      isPhantom: reachabilityScore === 0.0,
      isExploitable: exploitMaturity === 1.0,
      recommendation: generateRecommendation(riskScore, reachabilityScore, rawCVSS),
    },
  };
}

// ─── Classify All Vulnerabilities ───────────────────────────────

/**
 * Classify and sort the entire vulnerability list by composite risk.
 * @param {Array<object>} vulnList - Enriched vulnerability list
 * @returns {Array<object>} Sorted list (highest risk first)
 */
function classifyAll(vulnList) {
  console.log(`[ShieldBot:Risk] Classifying ${vulnList.length} vulnerabilities...`);

  const classified = vulnList.map((v) => classifyRisk(v));

  // Sort descending by risk score
  classified.sort((a, b) => b.risk.score - a.risk.score);

  // Log summary
  const phantomCount = classified.filter((v) => v.risk.isPhantom).length;
  const criticalCount = classified.filter((v) => v.risk.label === "critical").length;
  const exploitableCount = classified.filter((v) => v.risk.isExploitable).length;

  console.log(
    `[ShieldBot:Risk] Classification complete:\n` +
    `  🔴 Critical: ${criticalCount}\n` +
    `  ⚪ Phantom (not reachable): ${phantomCount}\n` +
    `  💀 Publicly exploitable: ${exploitableCount}\n` +
    `  📊 Actionable (non-phantom): ${classified.length - phantomCount}`
  );

  return classified;
}

// ─── Generate Risk Matrix ───────────────────────────────────────

/**
 * Build a summary matrix for dashboard display.
 * @param {Array<object>} classifiedVulns - Output of classifyAll()
 * @returns {object} Risk matrix
 */
function generateRiskMatrix(classifiedVulns) {
  const matrix = {
    total: classifiedVulns.length,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byReachability: { reachable: 0, phantom: 0, unknown: 0 },
    byExploitability: { exploitable: 0, theoretical: 0 },
    topRisks: [],
    phantomVulns: [],
    averageRiskScore: 0,
  };

  let totalScore = 0;

  for (const v of classifiedVulns) {
    // By severity
    const label = v.risk.label;
    if (matrix.bySeverity[label] !== undefined) {
      matrix.bySeverity[label]++;
    }

    // By reachability
    if (v.risk.isPhantom) {
      matrix.byReachability.phantom++;
      matrix.phantomVulns.push({
        name: v.packageName,
        severity: v.severity,
        reason: "Vulnerable function not reachable in project code",
      });
    } else if (v.risk.breakdown.reachability.value === 1.0) {
      matrix.byReachability.reachable++;
    } else {
      matrix.byReachability.unknown++;
    }

    // By exploitability
    if (v.risk.isExploitable) {
      matrix.byExploitability.exploitable++;
    } else {
      matrix.byExploitability.theoretical++;
    }

    totalScore += v.risk.score;
  }

  matrix.averageRiskScore = classifiedVulns.length > 0
    ? round(totalScore / classifiedVulns.length)
    : 0;

  // Top 5 highest-risk vulnerabilities
  matrix.topRisks = classifiedVulns.slice(0, 5).map((v) => ({
    package: v.packageName,
    riskScore: v.risk.score,
    severity: v.risk.label,
    reachable: !v.risk.isPhantom,
    exploitable: v.risk.isExploitable,
    recommendation: v.risk.recommendation,
  }));

  return matrix;
}

// ─── Helpers ────────────────────────────────────────────────────

/**
 * Convert severity string to approximate CVSS score.
 */
function severityToScore(severity) {
  const map = {
    critical: 9.5,
    high: 7.5,
    moderate: 5.5,
    medium: 5.5,
    low: 2.5,
    info: 0.5,
  };
  return map[severity] || 5.0;
}

/**
 * Map a 0-10 risk score to a severity label.
 */
function getSeverityLabel(score) {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

/**
 * Check if a vulnerability has a known public exploit.
 */
function hasPublicExploit(vuln) {
  const exploitKeywords = [
    "exploit",
    "poc",
    "proof-of-concept",
    "exploit-db",
    "metasploit",
    "payload",
  ];

  // Check NVD references for exploit tags
  const nvdRefs = vuln.nvd?.references || [];
  for (const ref of nvdRefs) {
    if (ref.tags && ref.tags.some((t) => t.toLowerCase().includes("exploit"))) {
      return true;
    }
    if (ref.url && exploitKeywords.some((kw) => ref.url.toLowerCase().includes(kw))) {
      return true;
    }
  }

  // Check OSV references
  const osvRefs = vuln.osv?.advisories || [];
  for (const adv of osvRefs) {
    const refs = adv.references || [];
    for (const ref of refs) {
      if (ref.type === "EXPLOIT" || ref.type === "EVIDENCE") return true;
      if (ref.url && exploitKeywords.some((kw) => ref.url.toLowerCase().includes(kw))) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Generate a human-readable recommendation based on risk analysis.
 */
function generateRecommendation(riskScore, reachability, cvss) {
  if (reachability === 0.0) {
    return "PHANTOM — Vulnerable function is not reachable. Low priority, but consider updating when convenient.";
  }
  if (riskScore >= 9.0) {
    return "CRITICAL — Immediately patch. Active exploit risk with reachable vulnerable code.";
  }
  if (riskScore >= 7.0) {
    return "HIGH — Patch within 24 hours. Significant risk to application security.";
  }
  if (riskScore >= 4.0) {
    return "MEDIUM — Schedule patch within this sprint. Monitor for exploit activity.";
  }
  return "LOW — Track and patch during regular maintenance cycles.";
}

function round(n) {
  return Math.round(n * 100) / 100;
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  classifyRisk,
  classifyAll,
  getSeverityLabel,
  generateRiskMatrix,
  WEIGHTS,
};
