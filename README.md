# Application Security Analysis: OWASP Juice Shop

A layered security assessment of OWASP Juice Shop using SAST, SCA, and DAST methodologies. This project demonstrates how multiple analysis techniques produce complementary findings, and where each tool's coverage gaps lie.

## Overview

OWASP Juice Shop is an intentionally vulnerable web application maintained as a security training target. This project applies three categories of security tooling against it to identify vulnerabilities the way a real AppSec program would: catching issues in source code (SAST), dependencies (SCA), and runtime behavior (DAST) before they reach production.

The goal is not just to run scanners, but to triage findings: distinguish true positives from noise, correlate findings across tools, and identify what each methodology misses.

## Architecture

| Component | Tool | Role |
|-----------|------|------|
| Target | OWASP Juice Shop (Node.js/TypeScript/Angular) | Application under test |
| SAST | Semgrep OSS (1,059 community rules) | Source-code analysis |
| SCA | npm audit | Dependency vulnerability scanning |
| DAST | OWASP ZAP (Automated Scan) | Runtime vulnerability detection |
| Host | Azure Ubuntu 24.04 VM | Isolated lab environment for the vulnerable target |

Juice Shop ran on the Azure VM at port 3000. ZAP ran on a Windows host and attacked the live application across the network. Semgrep and npm audit ran directly on the VM against the cloned source code.

## Methodology

**SAST first.** I ran Semgrep against the Juice Shop source with `--config=auto`, which automatically selects rulesets based on detected languages (TypeScript, JavaScript, YAML, HTML, Solidity, JSON, Dockerfile, Bash). 1,113 files were scanned in ~40 seconds, producing 42 findings.

**SCA in parallel.** `npm audit` against `package.json` surfaced 42 vulnerabilities in transitive dependencies (4 low, 9 moderate, 23 high, 6 critical). This catches vulnerabilities introduced through third-party code that SAST against first-party code cannot.

**DAST last.** With Juice Shop running, I pointed OWASP ZAP's Automated Scan at `http://VM:3000`. ZAP ran traditional spider, AJAX spider, and Active Scan modules to find runtime vulnerabilities that only manifest when the application is executing.

**Why this order:** SAST finds the most issues fastest and informs what to look for at runtime. SCA is essentially free once dependencies are installed. DAST is the slowest but catches issues neither SAST nor SCA can see, like server configuration and authentication flow problems.

## Key Findings

### 1. SQL Injection — Critical (SAST)

**Location:** `routes/login.ts:34`
**Rule:** `javascript.sequelize.security.audit.sequelize-injection-express`

User-controlled input (`req.body.email`) is concatenated directly into a raw SQL query via template literals:

```javascript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' 
   AND password = '${security.hash(req.body.password || '')}' 
   AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

**Exploit:** Submitting `' OR 1=1--` as the email bypasses authentication entirely by short-circuiting the WHERE clause and commenting out the password check. This logs the attacker in as the first user in the database — in Juice Shop, that's the admin account.

**Severity rationale:** This isn't data exposure, it's full authentication bypass on a route that gates all user functionality.

**Fix:** Use Sequelize's parameterized query syntax (`replacements` or `bind`) instead of string interpolation.

![SQL Injection Finding](screenshots/sast/03_sql_injection.png)

### 2. Path Traversal — High (SAST + DAST correlation)

**Locations:** 4 routes serving files with `res.sendFile` and user-controlled paths:

| File | Vulnerable Code |
|------|-----------------|
| `routes/fileServer.ts:33` | `res.sendFile(path.resolve('ftp/', file))` |
| `routes/keyServer.ts:14` | `res.sendFile(path.resolve('encryptionkeys/', file))` |
| `routes/logfileServer.ts:14` | `res.sendFile(path.resolve('logs/', file))` |
| `routes/quarantineServer.ts` | `res.sendFile(path.resolve('ftp/quarantine/', file))` |

**Why critical:** `path.resolve` does not block `../` traversal — it just resolves the path. A request like `?file=../../etc/passwd` would resolve outside the intended directory. The `keyServer.ts` instance is particularly severe because it serves encryption keys; a successful traversal there could expose cryptographic material used elsewhere in the app.

**DAST correlation:** ZAP's spider independently discovered URLs like `http://VM:3000/home/labuser/juice-shop/node_modules/serve-index/...`, confirming at runtime that the server exposes paths outside its intended directories. The SAST static analysis and DAST runtime behavior agreed on the same class of vulnerability — this is exactly the kind of cross-tool corroboration mature AppSec programs aim for.

**Fix:** Validate that `path.resolve(file)` begins with the allowed directory; reject otherwise.

![Path Traversal Findings](screenshots/sast/04_path_traversal.png)
![DAST Path Disclosure](screenshots/dast/11_zap_path_traversal.png)

### 3. GitHub Actions Shell Injection — High (SAST)

**Locations:** 3 workflow files in `.github/workflows/`:
- `update-challenges-ebook.yml:25`
- `update-challenges-www-legacy.yml:28`
- `update-challenges-www.yml:28`

**Pattern:** `${{ github.ref_name }}` is interpolated directly into `run:` shell scripts. GitHub Actions performs this substitution *before* bash sees the command, so an attacker who can control `ref_name` (by pushing a maliciously-named branch) can inject arbitrary shell commands into the CI runner.

**Why this matters:** CI runners have access to secrets, package registries, and deployment credentials. This is the attack class behind several real-world supply chain incidents.

**Fix:** Pass the value through an `env:` block instead, then reference it as `"$VAR"` in the shell script. The shell sees a variable expansion rather than a textual substitution.

The same anti-pattern across three workflow files suggests no security review process on CI/CD changes — itself a finding worth raising.

![GitHub Actions Shell Injection](screenshots/sast/05_github_actions.png)

### 4. Hardcoded Secrets — Medium (SAST)

Two categories of secret exposure:

- **`data/static/users.yml:151`** — A real-looking TOTP secret (`IFTXE3SP0EYVURT2MRYGI52TKJ4HC3KH`) is hardcoded into seed data for a test user.
- **JWT tokens and HMAC keys** — Detected in source files; while these are demo credentials, the same pattern in a production codebase would be a critical leak.

**Why this matters even for "test" credentials:** Test fixtures often migrate to production environments without review. Anything that looks like a real credential will eventually be scanned, indexed, and tried against real systems.

**Fix:** Load all secrets from environment variables or a secret manager. Use clearly fake placeholders (`PLACEHOLDER_DO_NOT_USE`) in fixtures.

![Hardcoded Secrets](screenshots/sast/06_hardcoded_secrets.png)

### 5. Dependency Vulnerabilities — Mixed (SCA)

`npm audit` flagged 42 known CVEs in transitive dependencies: **6 critical, 23 high, 9 moderate, 4 low.**

These represent supply-chain risk independent of how Juice Shop's own code is written. Even a perfectly-coded application can ship critical vulnerabilities through a compromised dependency. This is a category SAST against first-party code structurally cannot find.

In a real environment, the next step would be triaging which of these are reachable from the application's actual call paths — many dependency CVEs are in code paths the application never exercises. Tools like Snyk or Semgrep Supply Chain perform this reachability analysis.

![npm audit](screenshots/sca/07_npm_audit.png)

### 6. CSP Misconfiguration & Header Issues — Medium (DAST)

ZAP's automated scan produced 5 distinct alerts, the most significant being:

- **Content Security Policy header not set** (Medium) — no CSP defense-in-depth against XSS
- **CSP: Failure to Define Directive with No Fallback** (Medium) — even where CSP exists, key directives fall back to permissive defaults
- **Cross-Domain Misconfiguration** (Low) — CORS settings too permissive
- **Timestamp Disclosure - Unix** (Informational) — server leaks internal timestamps

These are deployment- and configuration-layer issues that SAST cannot detect because they only exist at runtime. This is exactly why DAST complements SAST rather than replacing it.

![ZAP CSP Alert](screenshots/dast/10_zap_alerts.png)

## SAST/DAST Correlation

The strongest signal in this assessment came from the convergence of SAST and DAST on path traversal. Semgrep flagged 4 `res.sendFile` instances statically. ZAP's spider independently navigated to filesystem paths (`/home/labuser/juice-shop/node_modules/...`) at runtime, confirming the application does in fact expose paths outside its intended directories.

When two independent methodologies flag the same vulnerability class, it raises confidence the finding is real and exploitable. This is the goal of layered analysis: each tool covers the others' blind spots, and overlap is signal, not redundancy.

## False Positives and Tuning

Not every finding was a real bug. Notable false positives:

- **`data/static/codefixes/`** — Semgrep flagged code in this directory, but it contains Juice Shop's *intentionally fixed* reference implementations of vulnerabilities. In a production setup, I would add a `.semgrepignore` rule to suppress findings in this path.
- **`frontend/src/assets/private/three.js`** — Semgrep timed out on this minified third-party library file. Third-party assets should generally be excluded from first-party SAST scans and covered separately by SCA.

False-positive triage is a core AppSec engineering responsibility. Tools that cry wolf get tuned out by developers, defeating the purpose of shift-left security.

## What I'd Build Next

This project established baseline coverage. The natural extensions:

- **CI/CD integration** — Run Semgrep on every PR via GitHub Actions, gate merges on new High/Critical findings, upload SARIF to the GitHub Security tab.
- **Custom Semgrep rules** — Write project-specific rules for patterns the community ruleset misses (e.g., Juice Shop's specific Sequelize injection pattern).
- **Authenticated DAST** — Configure ZAP with valid session credentials so the Active Scan can reach authenticated endpoints. The unauthenticated scan in this project only saw publicly accessible routes.
- **Reachability-based SCA** — Use a tool that determines whether vulnerable dependency functions are actually invoked, rather than just flagging every CVE in `node_modules`.
- **IaC scanning** — The Juice Shop repo contains Dockerfiles and Kubernetes manifests; scanning these with Checkov or tfsec would extend the analysis to infrastructure.

## Lessons Learned

- **Tool selection should match the platform.** I initially attempted Docker Desktop on Windows for the target environment. After significant time spent debugging AMD virtualization and Hyper-V conflicts, I pivoted to an Azure Ubuntu VM. Cloud-hosted lab environments are often the faster path for security tooling that targets Linux.
- **Semgrep OSS vs. paid tiers.** Semgrep's free OSS tier ran 1,059 community rules. The paid Semgrep Code tier would add ~1,700 proprietary rules with reduced false-positive rates, which I would evaluate for a production rollout.
- **Cyber range NSG patterns.** The Azure cyber range used a permissive inbound + strict outbound NSG pattern — appropriate for a vulnerable-target lab because it contains any compromise to the VM rather than allowing it to be weaponized against external targets. This is a legitimate defense-in-depth design choice for security training environments.
- **DAST scans are only as good as their crawl.** My initial ZAP scan completed in 5 minutes with sparse findings because the AJAX Spider didn't fully crawl Juice Shop's Angular routes. Real DAST against single-page applications requires more crawler configuration than a typical multi-page site.

## Repository Contents
