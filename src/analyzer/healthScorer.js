/**
 * healthScorer.js
 * ────────────────
 * Proactive dependency health scoring — goes beyond vulnerability detection
 * to PREDICT which packages are likely to become risky.
 *
 * Scores each dependency on a weighted scale (A+ to F):
 *   - Known CVE count (past 12 months)    → 30%
 *   - Maintainer activity (last commit)   → 20%
 *   - Download trend (rising/falling)     → 15%
 *   - License risk                        → 10%
 *   - Transitive dependency depth         → 15%
 *   - Typosquatting similarity            → 10%
 *
 * Exports:
 *   - scorePackage(name, version, metadata)  → health score object
 *   - scoreAll(packages)                     → scored + sorted list
 *   - getGrade(score)                        → "A+" to "F"
 *   - generateHealthReport(scoredPackages)   → summary for dashboard
 */

// ─── Weight Configuration ───────────────────────────────────────

const WEIGHTS = {
  cveHistory: 0.30,
  maintainerActivity: 0.20,
  downloadTrend: 0.15,
  licenseRisk: 0.10,
  transitiveDependencyDepth: 0.15,
  typosquatRisk: 0.10,
};

// Risky licenses when your project is MIT/ISC
const RISKY_LICENSES = new Set([
  "GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0",
  "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
  "SSPL-1.0", "BSL-1.1", "EUPL-1.2",
]);

const COPYLEFT_LICENSES = new Set([
  "GPL-2.0", "GPL-3.0", "AGPL-3.0", "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
]);

// ─── Score a Single Package ─────────────────────────────────────

/**
 * Compute a health score for a single package.
 *
 * @param {string} name     - Package name
 * @param {string} version  - Installed version
 * @param {object} metadata - Enrichment data:
 *   - cveCount          (number)  CVEs in past 12 months
 *   - lastPublishDate   (string)  ISO date of last npm publish
 *   - weeklyDownloads   (number)  Current weekly download count
 *   - prevWeekDownloads (number)  Previous period downloads (for trend)
 *   - license           (string)  Package license (e.g., "MIT")
 *   - directDepCount    (number)  How many direct deps this package has
 *   - transitiveDepth   (number)  Deepest transitive chain length
 *   - typosquatScore    (number)  0-1, from typosquatDetector
 *   - maintainerCount   (number)  Number of npm maintainers
 *
 * @returns {object} Health score result
 */
function scorePackage(name, version, metadata = {}) {
  const scores = {};

  // ── 1. CVE History (30%) ──
  // 0 CVEs = 1.0, 1 CVE = 0.7, 3+ CVEs = 0.2, 5+ = 0.0
  const cveCount = metadata.cveCount || 0;
  if (cveCount === 0) scores.cveHistory = 1.0;
  else if (cveCount === 1) scores.cveHistory = 0.7;
  else if (cveCount <= 3) scores.cveHistory = 0.4;
  else if (cveCount <= 5) scores.cveHistory = 0.2;
  else scores.cveHistory = 0.0;

  // ── 2. Maintainer Activity (20%) ──
  // Published in last 3 months = 1.0, 6 months = 0.7, 1 year = 0.4, 2+ years = 0.1
  const lastPublish = metadata.lastPublishDate
    ? new Date(metadata.lastPublishDate)
    : null;

  if (lastPublish) {
    const daysSincePublish = Math.floor(
      (Date.now() - lastPublish.getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSincePublish <= 90) scores.maintainerActivity = 1.0;
    else if (daysSincePublish <= 180) scores.maintainerActivity = 0.7;
    else if (daysSincePublish <= 365) scores.maintainerActivity = 0.4;
    else if (daysSincePublish <= 730) scores.maintainerActivity = 0.2;
    else scores.maintainerActivity = 0.1;
  } else {
    scores.maintainerActivity = 0.3; // unknown
  }

  // ── 3. Download Trend (15%) ──
  // Rising = 1.0, Stable = 0.6, Falling = 0.3
  const currentDownloads = metadata.weeklyDownloads || 0;
  const prevDownloads = metadata.prevWeekDownloads || currentDownloads;

  if (prevDownloads === 0) {
    scores.downloadTrend = currentDownloads > 100 ? 0.6 : 0.3;
  } else {
    const changeRatio = currentDownloads / prevDownloads;
    if (changeRatio >= 1.1) scores.downloadTrend = 1.0;  // Growing 10%+
    else if (changeRatio >= 0.9) scores.downloadTrend = 0.6;  // Stable
    else if (changeRatio >= 0.5) scores.downloadTrend = 0.3;  // Declining
    else scores.downloadTrend = 0.1;  // Rapid decline — warning sign
  }

  // ── 4. License Risk (10%) ──
  const license = metadata.license || "UNKNOWN";
  if (license === "MIT" || license === "ISC" || license === "BSD-2-Clause" || license === "BSD-3-Clause" || license === "Apache-2.0") {
    scores.licenseRisk = 1.0;
  } else if (COPYLEFT_LICENSES.has(license)) {
    scores.licenseRisk = 0.2;
  } else if (RISKY_LICENSES.has(license)) {
    scores.licenseRisk = 0.4;
  } else if (license === "UNKNOWN" || license === "UNLICENSED") {
    scores.licenseRisk = 0.3;
  } else {
    scores.licenseRisk = 0.6; // Uncommon but not risky
  }

  // ── 5. Transitive Dependency Depth (15%) ──
  // 0-5 deps = 1.0, 10-20 = 0.5, 50+ = 0.1
  const depDepth = metadata.transitiveDepth || metadata.directDepCount || 0;
  if (depDepth <= 5) scores.transitiveDependencyDepth = 1.0;
  else if (depDepth <= 10) scores.transitiveDependencyDepth = 0.7;
  else if (depDepth <= 20) scores.transitiveDependencyDepth = 0.5;
  else if (depDepth <= 50) scores.transitiveDependencyDepth = 0.3;
  else scores.transitiveDependencyDepth = 0.1;

  // ── 6. Typosquat Risk (10%) ──
  // From typosquatDetector: 0 = safe, 1 = suspicious
  const typosquatRisk = metadata.typosquatScore || 0;
  scores.typosquatRisk = 1.0 - typosquatRisk; // Invert: high similarity = low health

  // ── Composite Score ──
  const composite =
    WEIGHTS.cveHistory * scores.cveHistory +
    WEIGHTS.maintainerActivity * scores.maintainerActivity +
    WEIGHTS.downloadTrend * scores.downloadTrend +
    WEIGHTS.licenseRisk * scores.licenseRisk +
    WEIGHTS.transitiveDependencyDepth * scores.transitiveDependencyDepth +
    WEIGHTS.typosquatRisk * scores.typosquatRisk;

  const healthScore = Math.round(composite * 100);
  const grade = getGrade(healthScore);

  return {
    packageName: name,
    version,
    healthScore,
    grade,
    breakdown: scores,
    flags: generateFlags(scores, metadata),
  };
}

// ─── Fetch Package Metadata from npm Registry ──────────────────

/**
 * Fetch package metadata from the npm registry API.
 * @param {string} name - Package name
 * @returns {Promise<object>} Package metadata
 */
async function fetchPackageMetadata(name) {
  try {
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    if (!response.ok) return {};

    const data = await response.json();
    const latestVersion = data["dist-tags"]?.latest;
    const lastPublishDate = latestVersion ? data.time?.[latestVersion] : null;
    const license = data.versions?.[latestVersion]?.license || "UNKNOWN";
    const maintainerCount = data.maintainers?.length || 0;
    const deps = data.versions?.[latestVersion]?.dependencies || {};

    return {
      lastPublishDate,
      license: typeof license === "object" ? license.type : license,
      maintainerCount,
      directDepCount: Object.keys(deps).length,
    };
  } catch {
    return {};
  }
}

/**
 * Fetch weekly download stats from npm Downloads API.
 * Compares current week vs previous week for accurate trend detection.
 *
 * API: https://api.npmjs.org/downloads/point/{period}/{package}
 *
 * @param {string} name - Package name
 * @returns {Promise<{weeklyDownloads: number, prevWeekDownloads: number}>}
 */
async function fetchDownloadStats(name) {
  const encodedName = encodeURIComponent(name);
  const now = new Date();

  // Calculate date ranges for current week and previous week
  const currentEnd = now.toISOString().split("T")[0];
  const currentStart = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
  const prevEnd = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
  const prevStart = new Date(now - 14 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];

  try {
    // Fetch current week and previous week downloads in parallel
    const [currentRes, prevRes] = await Promise.all([
      fetch(`https://api.npmjs.org/downloads/point/${currentStart}:${currentEnd}/${encodedName}`),
      fetch(`https://api.npmjs.org/downloads/point/${prevStart}:${prevEnd}/${encodedName}`),
    ]);

    const currentData = currentRes.ok ? await currentRes.json() : {};
    const prevData = prevRes.ok ? await prevRes.json() : {};

    return {
      weeklyDownloads: currentData.downloads || 0,
      prevWeekDownloads: prevData.downloads || 0,
    };
  } catch {
    return { weeklyDownloads: 0, prevWeekDownloads: 0 };
  }
}

// ─── Score All Packages ─────────────────────────────────────────

/**
 * Score all packages with live npm registry data.
 * @param {Array<{name: string, version: string}>} packages
 * @param {object} extraData - Optional extra metadata per package
 * @returns {Promise<Array<object>>} Scored and sorted list (lowest health first)
 */
async function scoreAll(packages, extraData = {}) {
  console.log(`[ShieldBot:Health] Scoring ${packages.length} packages...`);

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    // Fetch live metadata from npm
    const [registryMeta, downloadMeta] = await Promise.all([
      fetchPackageMetadata(pkg.name),
      fetchDownloadStats(pkg.name),
    ]);

    const metadata = {
      ...registryMeta,
      ...downloadMeta,
      ...(extraData[pkg.name] || {}),
      cveCount: extraData[pkg.name]?.cveCount || 0,
      typosquatScore: extraData[pkg.name]?.typosquatScore || 0,
    };

    const score = scorePackage(pkg.name, pkg.version, metadata);
    results.push(score);

    // Rate limiting
    if (i < packages.length - 1) {
      await new Promise((r) => setTimeout(r, 50));
    }

    if ((i + 1) % 20 === 0) {
      console.log(`[ShieldBot:Health] Progress: ${i + 1}/${packages.length}`);
    }
  }

  // Sort: lowest health score first (most risky)
  results.sort((a, b) => a.healthScore - b.healthScore);

  const risky = results.filter((r) => r.healthScore < 50).length;
  console.log(
    `[ShieldBot:Health] Scoring complete: ${risky} packages below 50% health`
  );

  return results;
}

// ─── Generate Health Report ─────────────────────────────────────

/**
 * Build a summary report for dashboard display.
 * @param {Array<object>} scoredPackages - Output of scoreAll()
 * @returns {object} Health report
 */
function generateHealthReport(scoredPackages) {
  const gradeDistribution = { "A+": 0, A: 0, B: 0, C: 0, D: 0, F: 0 };
  let totalScore = 0;

  for (const pkg of scoredPackages) {
    gradeDistribution[pkg.grade]++;
    totalScore += pkg.healthScore;
  }

  const avgScore = scoredPackages.length > 0
    ? Math.round(totalScore / scoredPackages.length)
    : 0;

  return {
    totalPackages: scoredPackages.length,
    averageHealthScore: avgScore,
    overallGrade: getGrade(avgScore),
    gradeDistribution,
    riskyPackages: scoredPackages
      .filter((p) => p.healthScore < 50)
      .map((p) => ({
        name: p.packageName,
        score: p.healthScore,
        grade: p.grade,
        flags: p.flags,
      })),
    topHealthy: scoredPackages
      .filter((p) => p.healthScore >= 80)
      .slice(-5)
      .reverse()
      .map((p) => ({ name: p.packageName, score: p.healthScore, grade: p.grade })),
  };
}

// ─── Helpers ────────────────────────────────────────────────────

/**
 * Convert score (0-100) to letter grade.
 */
function getGrade(score) {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 65) return "B";
  if (score >= 50) return "C";
  if (score >= 35) return "D";
  return "F";
}

/**
 * Generate warning flags based on individual scores.
 */
function generateFlags(scores, metadata) {
  const flags = [];

  if (scores.cveHistory <= 0.2)
    flags.push("🔴 Multiple CVEs in past year");
  if (scores.maintainerActivity <= 0.2)
    flags.push("⚠️ Package appears abandoned (no updates in 1+ year)");
  if (scores.downloadTrend <= 0.3)
    flags.push("📉 Download trend declining — community may be migrating away");
  if (scores.licenseRisk <= 0.3)
    flags.push(`⚖️ License risk: ${metadata?.license || "unknown"}`);
  if (scores.transitiveDependencyDepth <= 0.3)
    flags.push("🌳 Deep dependency tree (large attack surface)");
  if (scores.typosquatRisk <= 0.5)
    flags.push("🎭 Name is suspiciously similar to a popular package");

  if ((metadata?.maintainerCount || 0) === 1)
    flags.push("👤 Single maintainer — bus factor risk");

  return flags;
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  scorePackage,
  scoreAll,
  getGrade,
  generateHealthReport,
  fetchPackageMetadata,
  fetchDownloadStats,
  WEIGHTS,
};
