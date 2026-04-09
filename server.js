/**
 * server.js
 * ──────────
 * Express API server for the NPM ShieldBot dashboard.
 * Serves the dashboard UI and exposes REST endpoints for scanning.
 *
 * Run: node server.js
 * Dashboard: http://localhost:3000
 * API:       http://localhost:3000/api/scan
 */

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const url = require("node:url");

const scanner = require("./src/scanner");
const analyzer = require("./src/analyzer");

const PORT = process.env.PORT || 3000;
const DASHBOARD_DIR = path.join(__dirname, "dashboard");

// MIME types
const MIME = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

// ─── Create HTTP Server ─────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── API Routes ──
  if (pathname.startsWith("/api/")) {
    return handleAPI(req, res, pathname, parsed.query);
  }

  // ── Serve Dashboard Static Files ──
  let filePath = pathname === "/" ? "/index.html" : pathname;
  filePath = path.join(DASHBOARD_DIR, filePath);

  const ext = path.extname(filePath);
  const contentType = MIME[ext] || "application/octet-stream";

  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("404 Not Found");
  }
});

// ─── API Handler ────────────────────────────────────────────────

async function handleAPI(req, res, pathname, query) {
  const json = (data, status = 200) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  };

  try {
    // POST /api/scan — Run full scan + analysis pipeline
    if (pathname === "/api/scan" && req.method === "POST") {
      const body = await readBody(req);
      const projectPath = body.projectPath || process.cwd();

      console.log(`\n[API] Running full pipeline on: ${projectPath}\n`);

      // Step 1: Scan
      const scanResults = await scanner.scan(projectPath);

      // Step 2: Analyze
      const analysisResults = await analyzer.analyze(projectPath, scanResults, {
        skipHealth: body.skipHealth || false,
        skipTyposquat: body.skipTyposquat || false,
      });

      return json({
        success: true,
        summary: scanResults.summary,
        vulnerabilities: analysisResults.vulnerabilities,
        riskMatrix: analysisResults.riskMatrix,
        typosquatAlerts: analysisResults.typosquatAlerts,
        healthScores: analysisResults.healthScores,
        healthReport: analysisResults.healthReport,
        dependencyTree: scanResults.dependencyTree,
        scanDuration: scanResults.scanDuration,
        analysisDuration: analysisResults.analysisDuration,
        timestamp: new Date().toISOString(),
      });
    }

    // GET /api/health — Quick health check
    if (pathname === "/api/health") {
      return json({ status: "ok", version: "1.0.0", uptime: process.uptime() });
    }

    // GET /api/scan-quick — Scan without analysis (faster)
    if (pathname === "/api/scan-quick") {
      const projectPath = query.path || process.cwd();
      const scanResults = await scanner.scan(projectPath, { skipOSV: true, skipNVD: true });
      return json({ success: true, ...scanResults });
    }

    json({ error: "Not found" }, 404);
  } catch (err) {
    console.error(`[API] Error: ${err.message}`);
    json({ error: err.message }, 500);
  }
}

// ─── Read Request Body ──────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

// ─── Start Server ───────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`\n${"═".repeat(50)}`);
  console.log(`  🛡️  NPM ShieldBot Server`);
  console.log(`  Dashboard: http://localhost:${PORT}`);
  console.log(`  API:       http://localhost:${PORT}/api/scan`);
  console.log(`${"═".repeat(50)}\n`);
});
