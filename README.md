# Application Security Analysis: OWASP Juice Shop

I ran a layered security assessment on OWASP Juice Shop using SAST, SCA, and DAST. The goal was to see where each method finds bugs the others miss, and to triage findings the way a real AppSec team would.

## Why This Project

Application security matters because vulnerabilities in code don't stay in code - they cost real money. A single SQL injection on a login page is the same bug class behind the 2017 Equifax breach (147 million records leaked, ~$1.4 billion in costs), the 2021 T-Mobile breach (76 million customers, $350 million settlement), and dozens of smaller incidents most companies never recover from. IBM's 2024 Cost of a Data Breach report put the global average at $4.88 million per breach - and that's before brand damage, customer churn, and regulatory fines.

The cheapest place to fix a security bug is before it ships. Fixing a vulnerability in development costs roughly $80. Fixing the same bug after deployment costs about $7,600. Fixing it after an actual breach can run into the millions. This is the entire economic case for "shift left" security - catch issues during development, not after attackers find them.

I built this project to prove I can actually do that work: take a real codebase, run the same kinds of tools a production AppSec team uses, separate real bugs from noise, and explain what each finding would cost the business if it shipped. AppSec isn't about running scanners - it's about reducing the risk that ends up in production. That's the skill I wanted to demonstrate.

## Overview

Juice Shop is OWASP's intentionally vulnerable web app, used widely as a training target. I scanned it three ways: source code (Semgrep), dependencies (npm audit), and runtime behavior (OWASP ZAP). Running scanners is easy. The harder part - and the whole point of this project - was reading the output, separating real bugs from noise, and noticing where two tools agreed on the same issue.

## Why SAST, SCA, and DAST Together

No single tool catches everything. Each one is built to find a different category of problem, and a real AppSec program runs all three because they cover each other's blind spots:

- **SAST (Static Application Security Testing)** reads source code without running it. It's great at finding patterns like SQL injection, hardcoded secrets, and unsafe function usage. But it can't see how the deployed app actually behaves or what's in third-party dependencies.
- **SCA (Software Composition Analysis)** checks the libraries an app depends on for known CVEs. Modern apps are mostly third-party code - Juice Shop pulls in over 1,500 packages. Even perfectly-written first-party code can ship critical vulnerabilities through a single bad dependency.
- **DAST (Dynamic Application Security Testing)** attacks the running application from the outside, like a real attacker would. It catches runtime issues SAST can't see - missing security headers, misconfigured CORS, server config problems, authentication flow bugs.

Skipping any of these leaves a gap. SAST-only misses dependency vulnerabilities. SCA-only misses code-level bugs. DAST-only misses everything that doesn't surface through HTTP. Running all three is how mature AppSec programs operate, and that's why I structured this project around all three.

## Architecture

| Component | Tool | Role |
|-----------|------|------|
| Target | OWASP Juice Shop (Node.js / TypeScript / Angular) | App under test |
| SAST | Semgrep OSS (1,059 community rules) | Source code analysis |
| SCA | npm audit | Dependency CVE scanning |
| DAST | OWASP ZAP (Automated Scan) | Runtime vulnerability detection |
| Host | Azure Ubuntu 24.04 VM | Isolated lab for the vulnerable target |

Juice Shop ran on the Azure VM on port 3000. ZAP attacked it from my Windows host. Semgrep and npm audit ran on the VM directly against the cloned source.

## Methodology

**SAST first.** Ran Semgrep with `--config=auto` so it picked rulesets based on the languages it detected (TypeScript, JavaScript, YAML, HTML, Solidity, JSON, Dockerfile, Bash). It scanned 1,113 files in about 40 seconds and flagged 42 findings.

![Semgrep Scan Summary](Screenshots/SAST/01_Scan%20results.PNG)

**SCA in parallel.** `npm audit` against `package.json` pulled up 42 known CVEs in dependencies - 6 critical, 23 high, 9 moderate, 4 low. These are bugs in third-party code that SAST against first-party code won't catch.

**DAST last.** With Juice Shop running, I pointed ZAP's Automated Scan at `http://VM:3000`. ZAP ran its traditional spider, AJAX spider, and active scan to find anything that only shows up at runtime.

**Why this order:** SAST is the fastest and finds the most surface area, so it's a good baseline. SCA is basically free once dependencies are already installed. DAST is the slowest but catches stuff the others can't see, like missing security headers and runtime config issues.

## Findings Breakdown

Here's how the 42 Semgrep findings broke down by rule:

![Findings Breakdown](Screenshots/SAST/02_Findings%20breakdown.PNG)

## Key Findings

### 1. SQL Injection - Critical (SAST)

**Location:** `routes/login.ts:34`  
**Rule:** `javascript.sequelize.security.audit.sequelize-injection-express`

User input goes straight into a raw SQL query via template literal:

```javascript
