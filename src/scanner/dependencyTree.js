/**
 * dependencyTree.js
 * ──────────────────
 * Parses package.json and package-lock.json to build a complete
 * dependency tree, including all transitive dependencies.
 *
 * Provides utilities to:
 *   - Build a full dependency graph (direct + transitive)
 *   - Find all paths to a vulnerable package
 *   - Count the "blast radius" (how many packages depend on a given one)
 *   - List direct vs transitive dependencies
 *
 * Exports:
 *   - buildTree(projectPath)           → full dependency tree object
 *   - getDirect(projectPath)           → list of direct dependencies only
 *   - findPaths(tree, packageName)     → all dependency paths to a package
 *   - getBlastRadius(tree, pkgName)    → number of packages affected if this breaks
 *   - getInstalledVersion(tree, name)  → currently installed version string
 *   - getAllPackages(tree)              → flat list of {name, version} for every dep
 */

const path = require("node:path");
const fs = require("node:fs");

// ─── Build Dependency Tree ──────────────────────────────────────

/**
 * Parse package-lock.json and build a structured dependency tree.
 * Supports lockfile versions 2 and 3 (npm v7+).
 * @param {string} projectPath - Absolute path to the project root
 * @returns {object} Dependency tree with metadata
 */
function buildTree(projectPath) {
  const pkgPath = path.join(projectPath, "package.json");
  const lockPath = path.join(projectPath, "package-lock.json");

  if (!fs.existsSync(pkgPath)) {
    throw new Error(`No package.json found at ${pkgPath}`);
  }
  if (!fs.existsSync(lockPath)) {
    throw new Error(
      `No package-lock.json found at ${lockPath}. Run 'npm install' first.`
    );
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));

  const directDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  // lockfileVersion 2/3 uses "packages" field
  // lockfileVersion 1 uses "dependencies" field
  const packages = lock.packages || {};
  const legacyDeps = lock.dependencies || {};

  const tree = {
    name: pkg.name || "root",
    version: pkg.version || "0.0.0",
    lockfileVersion: lock.lockfileVersion || 1,
    directDependencies: Object.keys(pkg.dependencies || {}),
    devDependencies: Object.keys(pkg.devDependencies || {}),
    totalPackages: 0,
    packages: {},   // name → { version, resolved, isDirect, isDev, dependencies }
    graph: {},      // name → [list of packages that depend on it]
  };

  if (lock.lockfileVersion >= 2 && Object.keys(packages).length > 0) {
    // Modern lockfile (npm 7+)
    parseModernLockfile(packages, directDeps, tree);
  } else {
    // Legacy lockfile (npm 6)
    parseLegacyLockfile(legacyDeps, directDeps, tree);
  }

  // Build reverse dependency graph (who depends on whom)
  buildReverseGraph(tree);

  tree.totalPackages = Object.keys(tree.packages).length;

  console.log(
    `[ShieldBot:DepTree] Built tree: ${tree.totalPackages} packages ` +
    `(${tree.directDependencies.length} direct, ${tree.devDependencies.length} dev)`
  );

  return tree;
}

// ─── Parse Modern Lockfile (v2/v3) ────────────────────────────

function parseModernLockfile(packages, directDeps, tree) {
  for (const [pkgPath, pkgData] of Object.entries(packages)) {
    // Skip the root entry (empty string key)
    if (pkgPath === "") continue;

    // Extract package name from path like "node_modules/lodash"
    // or "node_modules/@scope/name"
    const name = extractPackageName(pkgPath);
    if (!name) continue;

    const isDirect = name in directDeps;
    const isDev = pkgData.dev === true;

    tree.packages[name] = {
      version: pkgData.version || "unknown",
      resolved: pkgData.resolved || null,
      integrity: pkgData.integrity || null,
      isDirect,
      isDev,
      dependencies: Object.keys(pkgData.dependencies || {}),
      devDependencies: Object.keys(pkgData.devDependencies || {}),
      peerDependencies: Object.keys(pkgData.peerDependencies || {}),
      engines: pkgData.engines || null,
      funding: pkgData.funding || null,
    };
  }
}

// ─── Parse Legacy Lockfile (v1) ─────────────────────────────────

function parseLegacyLockfile(dependencies, directDeps, tree) {
  function walk(deps, parentPath = "") {
    for (const [name, data] of Object.entries(deps)) {
      const isDirect = name in directDeps;

      tree.packages[name] = {
        version: data.version || "unknown",
        resolved: data.resolved || null,
        integrity: data.integrity || null,
        isDirect,
        isDev: data.dev === true,
        dependencies: Object.keys(data.requires || {}),
        devDependencies: [],
        peerDependencies: [],
        engines: null,
        funding: null,
      };

      // Recurse into nested dependencies
      if (data.dependencies) {
        walk(data.dependencies, name);
      }
    }
  }
  walk(dependencies);
}

// ─── Build Reverse Dependency Graph ─────────────────────────────

/**
 * For each package, track which other packages depend on it.
 * This lets us calculate "blast radius".
 */
function buildReverseGraph(tree) {
  // Initialize graph
  for (const name of Object.keys(tree.packages)) {
    tree.graph[name] = [];
  }

  // For each package, add it as a dependent of its dependencies
  for (const [name, pkg] of Object.entries(tree.packages)) {
    for (const dep of pkg.dependencies) {
      if (tree.graph[dep]) {
        tree.graph[dep].push(name);
      }
    }
  }
}

// ─── Get Direct Dependencies ────────────────────────────────────

/**
 * Return only direct (non-transitive) dependencies.
 * @param {string} projectPath - Path to project root
 * @returns {Array<{name: string, version: string, isDev: boolean}>}
 */
function getDirect(projectPath) {
  const pkgPath = path.join(projectPath, "package.json");
  const lockPath = path.join(projectPath, "package-lock.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));

  const results = [];
  const prodDeps = Object.keys(pkg.dependencies || {});
  const devDeps = Object.keys(pkg.devDependencies || {});

  const allPackages = lock.packages || {};

  for (const name of [...prodDeps, ...devDeps]) {
    const lockEntry =
      allPackages[`node_modules/${name}`] ||
      lock.dependencies?.[name];

    results.push({
      name,
      requestedRange: pkg.dependencies?.[name] || pkg.devDependencies?.[name],
      installedVersion: lockEntry?.version || "unknown",
      isDev: devDeps.includes(name),
    });
  }

  return results;
}

// ─── Find All Paths to a Package ────────────────────────────────

/**
 * Find every dependency chain that leads to a specific package.
 * Useful for understanding HOW a transitive vulnerability got in.
 *
 * @param {object} tree      - Dependency tree from buildTree()
 * @param {string} targetPkg - Name of the package to find paths to
 * @returns {Array<string[]>} Array of paths, each path is an array of package names
 */
function findPaths(tree, targetPkg) {
  const paths = [];

  function dfs(current, visited, currentPath) {
    if (current === targetPkg && currentPath.length > 0) {
      paths.push([...currentPath, current]);
      return;
    }

    if (visited.has(current)) return; // Avoid cycles
    visited.add(current);

    const pkg = tree.packages[current];
    if (!pkg) return;

    for (const dep of pkg.dependencies) {
      dfs(dep, visited, [...currentPath, current]);
    }

    visited.delete(current);
  }

  // Start DFS from all direct dependencies
  for (const directDep of tree.directDependencies) {
    dfs(directDep, new Set(), []);
  }

  return paths;
}

// ─── Calculate Blast Radius ─────────────────────────────────────

/**
 * How many packages in the tree depend on this package (directly or transitively)?
 * Higher blast radius = more impactful if this package breaks.
 *
 * @param {object} tree    - Dependency tree from buildTree()
 * @param {string} pkgName - Package to check
 * @returns {{ directDependents: string[], totalAffected: number }}
 */
function getBlastRadius(tree, pkgName) {
  const directDependents = tree.graph[pkgName] || [];
  const allAffected = new Set();

  // BFS upward through reverse graph
  const queue = [...directDependents];
  while (queue.length > 0) {
    const current = queue.shift();
    if (allAffected.has(current)) continue;
    allAffected.add(current);

    const upstreamDeps = tree.graph[current] || [];
    for (const dep of upstreamDeps) {
      if (!allAffected.has(dep)) {
        queue.push(dep);
      }
    }
  }

  return {
    directDependents,
    totalAffected: allAffected.size,
    affectedPackages: [...allAffected],
  };
}

// ─── Get Installed Version ──────────────────────────────────────

/**
 * Look up the exact installed version of a package.
 * @param {object} tree    - Dependency tree from buildTree()
 * @param {string} pkgName - Package name
 * @returns {string|null} Installed version or null if not found
 */
function getInstalledVersion(tree, pkgName) {
  return tree.packages[pkgName]?.version || null;
}

// ─── Get All Packages (Flat List) ───────────────────────────────

/**
 * Return a flat list of every package in the dependency tree.
 * Useful for batch querying OSV/NVD.
 * @param {object} tree - Dependency tree from buildTree()
 * @returns {Array<{name: string, version: string}>}
 */
function getAllPackages(tree) {
  return Object.entries(tree.packages).map(([name, data]) => ({
    name,
    version: data.version,
    isDirect: data.isDirect,
    isDev: data.isDev,
  }));
}

// ─── Helpers ────────────────────────────────────────────────────

/**
 * Extract package name from lockfile path.
 * "node_modules/lodash" → "lodash"
 * "node_modules/@babel/core" → "@babel/core"
 */
function extractPackageName(pkgPath) {
  const prefix = "node_modules/";
  const idx = pkgPath.lastIndexOf(prefix);
  if (idx === -1) return null;
  return pkgPath.substring(idx + prefix.length);
}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  buildTree,
  getDirect,
  findPaths,
  getBlastRadius,
  getInstalledVersion,
  getAllPackages,
};
