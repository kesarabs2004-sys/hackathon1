/**
 * nvdClient.js
 * ─────────────
 * Fetches CVSS severity scores and detailed vulnerability information
 * from NIST's National Vulnerability Database (NVD) API v2.0.
 *
 * API Docs: https://nvd.nist.gov/developers/vulnerabilities
 * Rate Limit: ~5 requests per 30 seconds (without API key)
 *             ~50 requests per 30 seconds (with free API key)
 *
 * Get a free API key: https://nvd.nist.gov/developers/request-an-api-key
 *
 * Exports:
 *   - getCVE(cveId)              → full CVE details + CVSS score
 *   - getCVSSScore(cveId)        → just the numeric score + severity
 *   - batchLookup(cveIds)        → scores for multiple CVEs
 *   - enrichWithNVD(vulnList)    → add CVSS scores to vulnerability list
 */

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// Optional: Set your free NVD API key here or via environment variable
const NVD_API_KEY = process.env.NVD_API_KEY || null;

// Rate limiting: NVD allows ~5 req/30s without key, ~50/30s with key
const RATE_LIMIT_MS = NVD_API_KEY ? 600 : 6000;

// ─── Get Full CVE Details ───────────────────────────────────────

/**
 * Fetch complete CVE record from NVD.
 * @param {string} cveId - CVE identifier (e.g., "CVE-2024-1234")
 * @returns {Promise<object|null>} Parsed CVE data or null on failure
 */
async function getCVE(cveId) {
  if (!cveId || !cveId.startsWith("CVE-")) {
    console.warn(`[ShieldBot:NVD] Invalid CVE ID: ${cveId}`);
    return null;
  }

  const url = `${NVD_API_BASE}?cveId=${encodeURIComponent(cveId)}`;
  const headers = { "Content-Type": "application/json" };

  if (NVD_API_KEY) {
    headers["apiKey"] = NVD_API_KEY;
  }

  try {
    const response = await fetch(url, { method: "GET", headers });

    if (response.status === 403) {
      console.error(`[ShieldBot:NVD] Rate limited. Waiting before retry...`);
      await sleep(RATE_LIMIT_MS * 2);
      return getCVE(cveId); // Retry once
    }

    if (!response.ok) {
      console.error(
        `[ShieldBot:NVD] API error for ${cveId}: ${response.status} ${response.statusText}`
      );
      return null;
    }

    const data = await response.json();
    const vulns = data.vulnerabilities || [];

    if (vulns.length === 0) {
      console.warn(`[ShieldBot:NVD] No data found for ${cveId}`);
      return null;
    }

    return parseCVERecord(vulns[0].cve);
  } catch (err) {
    console.error(`[ShieldBot:NVD] Network error for ${cveId}: ${err.message}`);
    return null;
  }
}

// ─── Get Just the CVSS Score ────────────────────────────────────

/**
 * Fetch only the CVSS score and severity for a CVE.
 * @param {string} cveId - CVE identifier
 * @returns {Promise<{score: number|null, severity: string, vector: string|null}>}
 */
async function getCVSSScore(cveId) {
  const cve = await getCVE(cveId);
  if (!cve) {
    return { score: null, severity: "unknown", vector: null };
  }
  return {
    score: cve.cvssScore,
    severity: cve.severity,
    vector: cve.cvssVector,
  };
}

// ─── Batch Lookup ───────────────────────────────────────────────

/**
 * Look up CVSS scores for multiple CVE IDs.
 * Respects NVD rate limits with delays between requests.
 * @param {string[]} cveIds - Array of CVE identifiers
 * @returns {Promise<Map<string, object>>} Map of cveId → CVE data
 */
async function batchLookup(cveIds) {
  const uniqueIds = [...new Set(cveIds.filter((id) => id?.startsWith("CVE-")))];
  const results = new Map();

  console.log(
    `[ShieldBot:NVD] Batch lookup for ${uniqueIds.length} CVEs (rate limit: ${RATE_LIMIT_MS}ms/req)...`
  );

  for (let i = 0; i < uniqueIds.length; i++) {
    const cveId = uniqueIds[i];

    const cveData = await getCVE(cveId);
    if (cveData) {
      results.set(cveId, cveData);
    }

    // Rate limiting delay between requests
    if (i < uniqueIds.length - 1) {
      await sleep(RATE_LIMIT_MS);
    }

    // Progress logging every 5 CVEs
    if ((i + 1) % 5 === 0) {
      console.log(
        `[ShieldBot:NVD] Progress: ${i + 1}/${uniqueIds.length} CVEs fetched`
      );
    }
  }

  console.log(
    `[ShieldBot:NVD] Batch complete: ${results.size}/${uniqueIds.length} CVEs resolved`
  );
  return results;
}

// ─── Enrich Vulnerability List with NVD Data ────────────────────

/**
 * Take a vulnerability list (from npmAuditScanner or osvClient) and
 * add accurate CVSS scores from NVD.
 * @param {Array<object>} vulnList - Vulnerability list with .osv.cveIds or .advisories
 * @returns {Promise<Array<object>>} Enriched list with NVD CVSS data
 */
async function enrichWithNVD(vulnList) {
  // Collect all unique CVE IDs from the vulnerability list
  const allCVEIds = new Set();

  for (const vuln of vulnList) {
    // From OSV enrichment
    if (vuln.osv?.cveIds) {
      vuln.osv.cveIds.forEach((id) => allCVEIds.add(id));
    }
    // From npm audit advisories
    if (vuln.advisories) {
      vuln.advisories.forEach((adv) => {
        if (adv.url && adv.url.includes("CVE-")) {
          const match = adv.url.match(/(CVE-\d{4}-\d+)/);
          if (match) allCVEIds.add(match[1]);
        }
      });
    }
  }

  if (allCVEIds.size === 0) {
    console.log("[ShieldBot:NVD] No CVE IDs found to enrich");
    return vulnList;
  }

  console.log(
    `[ShieldBot:NVD] Enriching with ${allCVEIds.size} unique CVE IDs...`
  );

  // Batch fetch all CVE data
  const nvdData = await batchLookup([...allCVEIds]);

  // Enrich each vulnerability with NVD data
  return vulnList.map((vuln) => {
    const cveIds = vuln.osv?.cveIds || [];
    const nvdEntries = cveIds
      .map((id) => nvdData.get(id))
      .filter(Boolean);

    // Use the highest CVSS score among all associated CVEs
    let maxScore = null;
    let maxSeverity = "unknown";
    let maxVector = null;

    for (const entry of nvdEntries) {
      if (entry.cvssScore !== null && (maxScore === null || entry.cvssScore > maxScore)) {
        maxScore = entry.cvssScore;
        maxSeverity = entry.severity;
        maxVector = entry.cvssVector;
      }
    }

    return {
      ...vuln,
      nvd: {
        cvssScore: maxScore,
        severity: maxSeverity,
        cvssVector: maxVector,
        cweIds: [...new Set(nvdEntries.flatMap((e) => e.cweIds))],
        descriptions: nvdEntries.map((e) => e.description).filter(Boolean),
        references: nvdEntries.flatMap((e) => e.references).slice(0, 10),
        exploitabilityScore: nvdEntries[0]?.exploitabilityScore ?? null,
        impactScore: nvdEntries[0]?.impactScore ?? null,
        published: nvdEntries[0]?.published ?? null,
        lastModified: nvdEntries[0]?.lastModified ?? null,
      },
    };
  });
}

// ─── Parse NVD CVE Record ───────────────────────────────────────

/**
 * Normalize an NVD CVE record into our internal format.
 */
function parseCVERecord(cve) {
  // Try CVSS v3.1 first, then v3.0, then v2
  let cvssScore = null;
  let cvssVector = null;
  let severity = "unknown";
  let exploitabilityScore = null;
  let impactScore = null;

  // CVSS v3.1
  const v31 = cve.metrics?.cvssMetricV31?.[0];
  if (v31) {
    cvssScore = v31.cvssData?.baseScore ?? null;
    cvssVector = v31.cvssData?.vectorString ?? null;
    severity = v31.cvssData?.baseSeverity?.toLowerCase() ?? "unknown";
    exploitabilityScore = v31.exploitabilityScore ?? null;
    impactScore = v31.impactScore ?? null;
  }

  // Fallback: CVSS v3.0
  if (cvssScore === null) {
    const v30 = cve.metrics?.cvssMetricV30?.[0];
    if (v30) {
      cvssScore = v30.cvssData?.baseScore ?? null;
      cvssVector = v30.cvssData?.vectorString ?? null;
      severity = v30.cvssData?.baseSeverity?.toLowerCase() ?? "unknown";
      exploitabilityScore = v30.exploitabilityScore ?? null;
      impactScore = v30.impactScore ?? null;
    }
  }

  // Fallback: CVSS v2
  if (cvssScore === null) {
    const v2 = cve.metrics?.cvssMetricV2?.[0];
    if (v2) {
      cvssScore = v2.cvssData?.baseScore ?? null;
      cvssVector = v2.cvssData?.vectorString ?? null;
      severity = v2.baseSeverity?.toLowerCase() ?? "unknown";
      exploitabilityScore = v2.exploitabilityScore ?? null;
      impactScore = v2.impactScore ?? null;
    }
  }

  // CWE IDs
  const cweIds = [];
  const weaknesses = cve.weaknesses || [];
  for (const w of weaknesses) {
    for (const d of w.description || []) {
      if (d.value && d.value.startsWith("CWE-")) {
        cweIds.push(d.value);
      }
    }
  }

  // Description (English)
  const descriptions = cve.descriptions || [];
  const engDesc = descriptions.find((d) => d.lang === "en");
  const description = engDesc?.value || descriptions[0]?.value || "";

  // References
  const references = (cve.references || []).map((ref) => ({
    url: ref.url,
    source: ref.source || null,
    tags: ref.tags || [],
  }));

  return {
    id: cve.id,
    description,
    cvssScore,
    cvssVector,
    severity,
    exploitabilityScore,
    impactScore,
    cweIds,
    references,
    published: cve.published || null,
    lastModified: cve.lastModified || null,
  };
}

// ─── Utility ────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  getCVE,
  getCVSSScore,
  batchLookup,
  enrichWithNVD,
};
