/**
 * typosquatDetector.js
 * ─────────────────────
 * Detects potential typosquatting attacks by comparing package names
 * against a database of popular npm packages using string similarity.
 *
 * Techniques used:
 *   - Levenshtein distance (edit distance)
 *   - Character swap detection (lodash vs loadsh)
 *   - Prefix/suffix manipulation (express vs express-js vs expressjs)
 *   - Scope confusion (@babel/core vs babel-core)
 *   - Homoglyph detection (l vs 1, o vs 0)
 *
 * Exports:
 *   - checkPackage(name)             → typosquat analysis result
 *   - checkAll(packageNames)         → batch check
 *   - levenshtein(a, b)             → edit distance
 *   - getSimilarityScore(a, b)      → 0-1 similarity
 *   - enrichWithTyposquatting(pkgs) → add typosquat data to package list
 */

// ─── Top 200 Most Popular npm Packages (by downloads) ──────────
// This serves as the reference set to compare against.

const POPULAR_PACKAGES = new Set([
  // Core / Build
  "lodash", "chalk", "express", "react", "react-dom", "typescript",
  "webpack", "babel-core", "@babel/core", "eslint", "prettier",
  "commander", "yargs", "minimist", "glob", "rimraf", "mkdirp",
  "semver", "uuid", "debug", "dotenv", "cors", "axios", "node-fetch",
  "moment", "dayjs", "date-fns", "underscore", "ramda",

  // Server / HTTP
  "body-parser", "cookie-parser", "morgan", "helmet", "compression",
  "http-proxy", "express-session", "passport", "jsonwebtoken", "bcrypt",
  "bcryptjs", "mongoose", "sequelize", "knex", "pg", "mysql", "mysql2",
  "redis", "ioredis", "socket.io", "ws",

  // Testing
  "jest", "mocha", "chai", "sinon", "nyc", "supertest", "enzyme",
  "@testing-library/react", "cypress", "puppeteer", "playwright",

  // File / Path / Stream
  "fs-extra", "chokidar", "archiver", "formidable", "multer",
  "busboy", "readable-stream", "through2", "concat-stream",

  // Util
  "async", "bluebird", "rxjs", "eventemitter3", "cross-env",
  "concurrently", "nodemon", "pm2", "winston", "pino", "bunyan",
  "colors", "ora", "inquirer", "prompts", "listr",

  // Security-adjacent
  "helmet", "csurf", "express-rate-limit", "hpp", "xss-clean",
  "sanitize-html", "validator", "joi", "zod", "yup", "ajv",

  // Frontend
  "vue", "angular", "svelte", "next", "nuxt", "gatsby",
  "tailwindcss", "bootstrap", "styled-components", "emotion",
  "@mui/material", "antd", "classnames", "clsx",

  // Crypto
  "crypto-js", "node-forge", "tweetnacl", "elliptic", "bn.js",
]);

// Common homoglyph substitutions
const HOMOGLYPHS = {
  "o": ["0"],
  "0": ["o"],
  "l": ["1", "i"],
  "1": ["l", "i"],
  "i": ["1", "l"],
  "s": ["5"],
  "5": ["s"],
  "a": ["@"],
  "e": ["3"],
  "3": ["e"],
  "b": ["6"],
  "g": ["9"],
  "9": ["g"],
  "t": ["7"],
};

// ─── Check a Single Package ─────────────────────────────────────

/**
 * Analyze a package name for potential typosquatting.
 *
 * @param {string} name - Package name to check
 * @returns {object} Analysis result
 */
function checkPackage(name) {
  const result = {
    packageName: name,
    isSuspicious: false,
    riskScore: 0,        // 0-1 (0 = safe, 1 = very suspicious)
    similarTo: null,     // The popular package it resembles
    attackType: null,     // Type of typosquatting detected
    details: "",
    allMatches: [],      // All similar packages found
  };

  // If it IS a popular package, it's safe
  if (POPULAR_PACKAGES.has(name)) {
    result.details = "This is a known popular package";
    return result;
  }

  // Check against every popular package
  const matches = [];

  for (const popular of POPULAR_PACKAGES) {
    const analysis = analyzeNamePair(name, popular);
    if (analysis.score > 0.3) {
      matches.push({
        popularPackage: popular,
        score: analysis.score,
        type: analysis.type,
        detail: analysis.detail,
      });
    }
  }

  if (matches.length === 0) {
    result.details = "No similarity to known popular packages";
    return result;
  }

  // Sort by similarity score, highest first
  matches.sort((a, b) => b.score - a.score);
  const bestMatch = matches[0];

  result.allMatches = matches.slice(0, 5);
  result.riskScore = bestMatch.score;
  result.similarTo = bestMatch.popularPackage;
  result.attackType = bestMatch.type;
  result.details = bestMatch.detail;
  result.isSuspicious = bestMatch.score >= 0.7;

  return result;
}

// ─── Analyze a Name Pair ────────────────────────────────────────

/**
 * Compare a suspect name against a popular package name.
 * Returns a similarity score and attack type.
 */
function analyzeNamePair(suspect, popular) {
  const results = [];

  // 1. Levenshtein distance check
  const editDist = levenshtein(suspect, popular);
  const maxLen = Math.max(suspect.length, popular.length);
  const levScore = 1 - editDist / maxLen;

  if (editDist === 1) {
    results.push({
      score: 0.9,
      type: "single-char-edit",
      detail: `"${suspect}" is 1 edit away from "${popular}" — likely typosquatting`,
    });
  } else if (editDist === 2 && maxLen >= 5) {
    results.push({
      score: 0.75,
      type: "two-char-edit",
      detail: `"${suspect}" is 2 edits away from "${popular}"`,
    });
  }

  // 2. Character swap detection
  if (isCharSwap(suspect, popular)) {
    results.push({
      score: 0.95,
      type: "character-swap",
      detail: `"${suspect}" appears to be a character swap of "${popular}"`,
    });
  }

  // 3. Prefix/suffix manipulation
  const prefixSuffixScore = checkPrefixSuffix(suspect, popular);
  if (prefixSuffixScore.score > 0) {
    results.push(prefixSuffixScore);
  }

  // 4. Homoglyph detection
  const homoglyphScore = checkHomoglyphs(suspect, popular);
  if (homoglyphScore > 0.5) {
    results.push({
      score: homoglyphScore,
      type: "homoglyph",
      detail: `"${suspect}" uses look-alike characters mimicking "${popular}"`,
    });
  }

  // 5. Scope confusion (@scope/pkg vs scope-pkg)
  const scopeScore = checkScopeConfusion(suspect, popular);
  if (scopeScore.score > 0) {
    results.push(scopeScore);
  }

  // Return the highest-scoring match
  if (results.length === 0) {
    return { score: levScore > 0.6 ? levScore * 0.8 : 0, type: "none", detail: "" };
  }

  results.sort((a, b) => b.score - a.score);
  return results[0];
}

// ─── Levenshtein Distance ───────────────────────────────────────

/**
 * Compute the edit distance between two strings.
 * @param {string} a
 * @param {string} b
 * @returns {number} Minimum edits to transform a into b
 */
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;

  if (m === 0) return n;
  if (n === 0) return m;

  const matrix = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,       // deletion
        matrix[i][j - 1] + 1,       // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return matrix[m][n];
}

/**
 * Get normalized similarity score (0-1).
 */
function getSimilarityScore(a, b) {
  const dist = levenshtein(a, b);
  const maxLen = Math.max(a.length, b.length);
  return maxLen === 0 ? 1 : 1 - dist / maxLen;
}

// ─── Character Swap Detection ───────────────────────────────────

/**
 * Check if one string is a single character swap of another.
 * e.g., "lodash" vs "loadsh" — adjacent char swap
 */
function isCharSwap(a, b) {
  if (a.length !== b.length) return false;

  const diffs = [];
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) diffs.push(i);
  }

  if (diffs.length !== 2) return false;
  const [i, j] = diffs;
  return a[i] === b[j] && a[j] === b[i];
}

// ─── Prefix/Suffix Manipulation ─────────────────────────────────

function checkPrefixSuffix(suspect, popular) {
  const suspectClean = suspect.replace(/[-_.]/g, "");
  const popularClean = popular.replace(/[-_.]/g, "");

  // Check: "expressjs" mimicking "express"
  if (suspectClean === popularClean && suspect !== popular) {
    return {
      score: 0.85,
      type: "separator-manipulation",
      detail: `"${suspect}" is "${popular}" with separators changed`,
    };
  }

  // Check: "express-js" mimicking "express"
  const addedSuffixes = ["-js", "js", "-node", "-npm", "-pkg", "-lib", "-dev"];
  for (const suffix of addedSuffixes) {
    if (suspect === popular + suffix || suspect === popular.replace(/-/g, "") + suffix) {
      return {
        score: 0.7,
        type: "suffix-addition",
        detail: `"${suspect}" adds "${suffix}" to popular package "${popular}"`,
      };
    }
  }

  // Check: "my-express" mimicking "express"
  if (suspect.endsWith(popular) && suspect.length - popular.length <= 4) {
    return {
      score: 0.6,
      type: "prefix-addition",
      detail: `"${suspect}" prepends characters to "${popular}"`,
    };
  }

  return { score: 0, type: null, detail: "" };
}

// ─── Homoglyph Detection ────────────────────────────────────────

function checkHomoglyphs(suspect, popular) {
  if (suspect.length !== popular.length) return 0;

  let homoglyphSwaps = 0;
  let totalDiffs = 0;

  for (let i = 0; i < suspect.length; i++) {
    if (suspect[i] !== popular[i]) {
      totalDiffs++;
      const subs = HOMOGLYPHS[popular[i]] || [];
      if (subs.includes(suspect[i])) {
        homoglyphSwaps++;
      }
    }
  }

  if (totalDiffs === 0) return 0;
  if (homoglyphSwaps === totalDiffs && totalDiffs <= 2) {
    return 0.9; // All differences are homoglyph substitutions
  }
  if (homoglyphSwaps > 0) {
    return 0.6 + (homoglyphSwaps / totalDiffs) * 0.3;
  }
  return 0;
}

// ─── Scope Confusion ────────────────────────────────────────────

function checkScopeConfusion(suspect, popular) {
  // @babel/core vs babel-core
  if (popular.startsWith("@")) {
    const unscoped = popular.replace("@", "").replace("/", "-");
    if (suspect === unscoped) {
      return {
        score: 0.6,
        type: "scope-confusion",
        detail: `"${suspect}" matches unscoped version of "${popular}"`,
      };
    }
  }

  // babel-core vs @babel/core
  if (suspect.includes("-") && !suspect.startsWith("@")) {
    const parts = suspect.split("-");
    if (parts.length === 2) {
      const asScoped = `@${parts[0]}/${parts[1]}`;
      if (POPULAR_PACKAGES.has(asScoped)) {
        return {
          score: 0.5,
          type: "scope-confusion",
          detail: `"${suspect}" could be confused with scoped package "${asScoped}"`,
        };
      }
    }
  }

  return { score: 0, type: null, detail: "" };
}

// ─── Batch Check ────────────────────────────────────────────────

/**
 * Check multiple package names for typosquatting.
 * @param {string[]} packageNames
 * @returns {Array<object>} Analysis results (only suspicious ones)
 */
function checkAll(packageNames) {
  console.log(
    `[ShieldBot:Typosquat] Checking ${packageNames.length} packages for typosquatting...`
  );

  const results = [];
  let suspiciousCount = 0;

  for (const name of packageNames) {
    const result = checkPackage(name);
    results.push(result);
    if (result.isSuspicious) suspiciousCount++;
  }

  console.log(
    `[ShieldBot:Typosquat] Check complete: ${suspiciousCount} suspicious packages found`
  );

  return results;
}

// ─── Enrich Package List ────────────────────────────────────────

/**
 * Add typosquatting analysis to a list of packages.
 * @param {Array<{name: string}>} packages
 * @returns {Array<object>} Enriched with .typosquat field
 */
function enrichWithTyposquatting(packages) {
  return packages.map((pkg) => ({
    ...pkg,
    typosquat: checkPackage(pkg.name || pkg.packageName),
  }));
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  checkPackage,
  checkAll,
  levenshtein,
  getSimilarityScore,
  enrichWithTyposquatting,
  POPULAR_PACKAGES,
};
