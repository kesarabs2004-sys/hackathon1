/**
 * osvClient.js
 * ─────────────
 * Queries the OSV.dev API (Google's free, open-source vulnerability database)
 * to fetch real-time CVE/advisory data for npm packages.
 *
 * API Docs: https://osv.dev/docs/
 *
 * Exports:
 *   - queryPackage(name, version)     → vulnerabilities for a specific version
 *   - queryBatch(packages)            → batch query for multiple packages
 *   - enrichWithOSV(vulnList)         → enrich npm audit results with OSV data
 */

const OSV_API_BASE = "https://api.osv.dev/v1";

// ─── Query Single Package ───────────────────────────────────────

/**
 * Query OSV.dev for vulnerabilities affecting a specific package version.
 * @param {string} name    - Package name (e.g., "lodash")
 * @param {string} version - Exact version (e.g., "4.17.20")
 * @returns {Promise<Array>} List of OSV vulnerability objects
 */
async function queryPackage(name, version) {
  const url = `${OSV_API_BASE}/query`;

  const body = {
    package: {
      name: name,
      ecosystem: "npm",
    },
  };

  // If version is provided, query for that specific version
  if (version) {
    body.version = version;
  }

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      console.error(
        `[ShieldBot:OSV] API error for ${name}@${version}: ${response.status}`
      );
      return [];
    }

    const data = await response.json();
    return (data.vulns || []).map((vuln) => parseOSVEntry(vuln, name, version));
  } catch (err) {
    console.error(`[ShieldBot:OSV] Network error for ${name}: ${err.message}`);
    return [];
  }
}

// ─── Batch Query (Up to 1000 Packages) ──────────────────────────

/**
 * Query OSV.dev for multiple packages at once using the batch endpoint.
 * @param {Array<{name: string, version: string}>} packages - List of packages
 * @returns {Promise<Map<string, Array>>} Map of "name@version" → vulnerabilities
 */
async function queryBatch(packages) {
  const url = `${OSV_API_BASE}/querybatch`;
  const resultsMap = new Map();

  // OSV batch API accepts an array of queries
  const queries = packages.map((pkg) => ({
    package: {
      name: pkg.name,
      ecosystem: "npm",
    },
    version: pkg.version || undefined,
  }));

  // Split into chunks of 100 to avoid overloading
  const CHUNK_SIZE = 100;
  for (let i = 0; i < queries.length; i += CHUNK_SIZE) {
    const chunk = queries.slice(i, i + CHUNK_SIZE);
    const chunkPkgs = packages.slice(i, i + CHUNK_SIZE);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries: chunk }),
      });

      if (!response.ok) {
        console.error(`[ShieldBot:OSV] Batch query failed: ${response.status}`);
        continue;
      }

      const data = await response.json();
      const results = data.results || [];

      results.forEach((result, idx) => {
        const pkg = chunkPkgs[idx];
        const key = `${pkg.name}@${pkg.version}`;
        const vulns = (result.vulns || []).map((v) =>
          parseOSVEntry(v, pkg.name, pkg.version)
        );
        resultsMap.set(key, vulns);
      });
    } catch (err) {
      console.error(`[ShieldBot:OSV] Batch network error: ${err.message}`);
    }

    // Rate limiting: small delay between chunks
    if (i + CHUNK_SIZE < queries.length) {
      await sleep(200);
    }
  }

  return resultsMap;
}

// ─── Enrich npm audit results with OSV Data ────────────────────

/**
 * Take the vulnerability list from npmAuditScanner and enrich each
 * entry with CVE IDs, references, and severity from OSV.dev.
 * @param {Array<object>} vulnList - Output from npmAuditScanner.getVulnList()
 * @returns {Promise<Array<object>>} Enriched vulnerability list
 */
async function enrichWithOSV(vulnList) {
  console.log(
    `[ShieldBot:OSV] Enriching ${vulnList.length} vulnerabilities with OSV data...`
  );

  const enriched = [];

  for (const vuln of vulnList) {
    const osvResults = await queryPackage(vuln.packageName, null);

    // Add a small delay to respect rate limits
    await sleep(100);

    enriched.push({
      ...vuln,
      osv: {
        totalAdvisories: osvResults.length,
        cveIds: [
          ...new Set(osvResults.flatMap((r) => r.cveIds)),
        ],
        advisories: osvResults.slice(0, 10), // Cap at 10 most relevant
        lastModified: osvResults.length > 0
          ? osvResults
              .map((r) => r.modified)
              .sort()
              .pop()
          : null,
      },
    });
  }

  console.log(`[ShieldBot:OSV] Enrichment complete for ${enriched.length} packages`);
  return enriched;
}

// ─── Lookup a Specific CVE ID ───────────────────────────────────

/**
 * Fetch full details for a specific vulnerability ID (e.g., "GHSA-xxxx" or "CVE-2024-xxxx").
 * @param {string} vulnId - The OSV / GHSA / CVE identifier
 * @returns {Promise<object|null>} Full OSV vulnerability object or null
 */
async function getVulnById(vulnId) {
  const url = `${OSV_API_BASE}/vulns/${encodeURIComponent(vulnId)}`;

  try {
    const response = await fetch(url, { method: "GET" });
    if (!response.ok) {
      console.error(`[ShieldBot:OSV] Vuln lookup failed for ${vulnId}: ${response.status}`);
      return null;
    }
    const data = await response.json();
    return parseOSVEntry(data, null, null);
  } catch (err) {
    console.error(`[ShieldBot:OSV] Lookup error for ${vulnId}: ${err.message}`);
    return null;
  }
}

// ─── Parse OSV Entry ────────────────────────────────────────────

/**
 * Normalize an OSV vulnerability object into our internal format.
 */
function parseOSVEntry(osvVuln, packageName, packageVersion) {
  // Extract CVE aliases
  const aliases = osvVuln.aliases || [];
  const cveIds = aliases.filter((a) => a.startsWith("CVE-"));
  const ghsaIds = aliases.filter((a) => a.startsWith("GHSA-"));

  // Extract severity (CVSS)
  let cvssScore = null;
  let cvssVector = null;
  if (osvVuln.severity && osvVuln.severity.length > 0) {
    const cvss = osvVuln.severity.find((s) => s.type === "CVSS_V3");
    if (cvss) {
      cvssVector = cvss.score;
      // Extract numeric score from vector string if present
      const match = cvssVector?.match(/CVSS:3\.\d+\/.*$/);
      if (match) {
        cvssScore = parseCVSSVector(cvssVector);
      }
    }
  }

  // Extract affected version ranges
  const affected = (osvVuln.affected || [])
    .filter(
      (a) =>
        a.package?.ecosystem === "npm" &&
        (!packageName || a.package?.name === packageName)
    )
    .map((a) => ({
      name: a.package?.name,
      ranges: (a.ranges || []).map((r) => ({
        type: r.type,
        events: r.events,
      })),
      versions: a.versions || [],
    }));

  // Extract references (URLs for more info)
  const references = (osvVuln.references || []).map((r) => ({
    type: r.type,
    url: r.url,
  }));

  return {
    id: osvVuln.id,
    summary: osvVuln.summary || "No summary available",
    details: osvVuln.details || "",
    cveIds,
    ghsaIds,
    aliases,
    cvssScore,
    cvssVector,
    severity: classifySeverity(cvssScore),
    published: osvVuln.published || null,
    modified: osvVuln.modified || null,
    affected,
    references,
    packageName,
    packageVersion,
  };
}

// ─── CVSS Helpers ───────────────────────────────────────────────

/**
 * Very simplified CVSS v3 base score extraction from vector string.
 * For accurate scoring, the NVD client should be used instead.
 */
function parseCVSSVector(vector) {
  // This is a simplified extraction — in production use a proper CVSS library
  // The vector itself doesn't contain the numeric score directly
  // We return null and rely on NVD for accurate scores
  return null;
}

/**
 * Classify CVSS score into severity bucket.
 */
function classifySeverity(score) {
  if (score === null) return "unknown";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

// ─── Utility ────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  queryPackage,
  queryBatch,
  enrichWithOSV,
  getVulnById,
};
