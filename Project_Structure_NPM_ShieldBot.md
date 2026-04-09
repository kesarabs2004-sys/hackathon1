# NPM ShieldBot — Project File Structure

Here is the complete outline of the files and directories we've built for the NPM ShieldBot project so far:

```text
npm-shieldbot/
├── package.json               # Project manifest, dependencies (none!), and run scripts
├── server.js                  # Express-like API Server (serves the dashboard & handles scan requests)
├── README.md                  # Project documentation stub
│
├── dashboard/                 # Frontend User Interface
│   ├── index.html             # The main layout (Glassmorphism design, Cards, Tables)
│   ├── style.css              # Dark-mode styling, animations, and responsive grid rules
│   └── app.js                 # Frontend logic (Chart.js charts, table filtering, demo data injection)
│
├── src/                       # Core Backend Logic
│   ├── scanner/               # Module 1: The Data Gatherers
│   │   ├── index.js               # Orchestrator for the scanning phase (Batching & Pipeline)
│   │   ├── npmAuditScanner.js     # Runs `npm audit` and parses raw vulnerabilities
│   │   ├── dependencyTree.js      # Maps `package-lock.json` and calculates Blast Radius
│   │   ├── osvClient.js           # API Client for OSV.dev (Vulnerability Enrichment)
│   │   └── nvdClient.js           # API Client for NVD (CVSS scoring via National Vuln Database)
│   │
│   └── analyzer/              # Module 2: The Assessment Brain (CARP)
│       ├── index.js               # Orchestrator for the analysis phase
│       ├── reachabilityAnalyzer.js# AST parser to check if vulns are actually used (Phantom detection)
│       ├── riskClassifier.js      # The CARP Engine: Computes a final Risk Score (1-10) based on context
│       ├── typosquatDetector.js   # Uses Levenshtein distance to detect fake/malicious package names
│       └── healthScorer.js        # Grades packages (A+ to F) proactively based on download trends & history
│
└── tests/                     # Unit Tests Suite (Zero-Dependency testing)
    ├── scanner.test.js        # Validates npm parsing, dependency tree building, and API clients
    └── analyzer.test.js       # Validates Reachability logic, Math engine, typsquatting, and health grades
```

## Summary of Execution Flow
1. **Initiation**: The user runs `npm run dashboard` (which executes `server.js`).
2. **UI Action**: User clicks "Run Scan" in `dashboard/index.html`.
3. **Scan Pipeline**: `src/scanner/index.js` fires up, executing `npm audit`, tracing the `dependencyTree`, and enriching data with `osvClient` & `nvdClient`.
4. **Analysis Pipeline**: Data passes to `src/analyzer/index.js`. Here, `reachabilityAnalyzer` checks for phantom vulns, while the `typosquatDetector` and `healthScorer` do background checks. Finally, `riskClassifier` crunches the numbers into a final Priority Score.
5. **Presentation**: The API sends the JSON payload back to `dashboard/app.js` which updates the UI.
