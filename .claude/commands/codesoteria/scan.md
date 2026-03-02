You are performing an automated security audit of a codebase.

**Target path**: $ARGUMENTS

If no target path was provided, ask the user which directory to audit.

## Reference Files

Find the CodeSoteria reference files by checking these locations in order:
1. `~/.claude/codesoteria/references/` (global install)
2. `./references/` (running from CodeSoteria project root)

You need the following reference files during this audit:
- `agents/*.md` — per-agent playbooks (read by each spawned agent)
- `tool-registry.md` — master catalog of external security tools
- `finding-schema.md` — JSON schema for structured findings
- `report-template.md` — final report structure
- `severity-model.md` — severity/confidence definitions
- `cross-correlation.md` — deduplication and correlation rules

Read these files when you reach the relevant phase. If they cannot be found at either location, inform the user and abort.

## Output Directory

Create `codesoteria-output/` in the current working directory for all artifacts:
```
codesoteria-output/
  inventory.json
  agent-plan.json
  tool-status.json
  scope/
  findings/
  report/
```

Create the directory structure at the start:
```bash
mkdir -p codesoteria-output/{scope,findings,report}
```

## User Configuration

Check if the user provided any configuration flags in their arguments. Supported options (all optional):

- **exclude_paths**: Directories/patterns to skip (e.g., `vendor/`, `node_modules/`, `*.test.*`)
- **compliance_targets**: Standards to check against (e.g., `OWASP Top 10`, `CWE Top 25`, `SOC2`, `HIPAA`)
- **severity_threshold**: Minimum severity to report (default: `LOW` — report everything)
- **focus_areas**: Specific agents to run (e.g., `auth,api,deps`). Default: all applicable agents.
- **language_hints**: Explicit language declarations if auto-detection might miss them

If no arguments beyond the path are provided, proceed with defaults.

---

## Phase 0: Codebase Inventory

### 0.1 — Language & Framework Detection

Scan the target path to identify:

**Languages** — Detect by file extensions and shebang lines:
- JavaScript/TypeScript: `.js`, `.ts`, `.jsx`, `.tsx`, `package.json`
- Python: `.py`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py`
- Go: `.go`, `go.mod`, `go.sum`
- Rust: `.rs`, `Cargo.toml`, `Cargo.lock`
- Java: `.java`, `pom.xml`, `build.gradle`
- C/C++: `.c`, `.cpp`, `.h`, `.hpp`, `CMakeLists.txt`, `Makefile`
- Ruby: `.rb`, `Gemfile`, `Gemfile.lock`
- PHP: `.php`, `composer.json`, `composer.lock`
- C#: `.cs`, `*.csproj`, `*.sln`

**Frameworks** — Detect by imports, config files, and manifest contents:
- Express/Fastify/Koa/NestJS (Node.js)
- Django/Flask/FastAPI (Python)
- Spring Boot (Java)
- ASP.NET (C#)
- Rails (Ruby)
- Gin/Echo/Fiber (Go)
- Actix/Axum/Rocket (Rust)
- Laravel (PHP)

**Infrastructure & Config Files:**
- Dockerfiles: `Dockerfile`, `Dockerfile.*`, `docker-compose.yml`, `compose.yml`
- Kubernetes: `*.yaml`/`*.yml` with `apiVersion` and `kind` fields
- Terraform: `*.tf`, `*.tfvars`
- CloudFormation: templates with `AWSTemplateFormatVersion`
- CI/CD: `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`
- Environment: `.env`, `.env.*`

**Dependency Manifests:**
- `package.json` + `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`
- `requirements.txt` / `Pipfile.lock` / `poetry.lock`
- `go.sum`
- `Cargo.lock`
- `Gemfile.lock`
- `composer.lock`
- `pom.xml` / `build.gradle.kts`

**Crypto Indicators** — Check for imports of:
- `crypto`, `openssl`, `cryptography`, `javax.crypto`, `ring`, `sodium`, `bcrypt`, `argon2`
- TLS/SSL configuration files
- JWT libraries (`jsonwebtoken`, `PyJWT`, `golang-jwt`, `jjwt`)

Use `find` and `grep` commands to efficiently detect these. Apply user-provided `exclude_paths` to skip irrelevant directories. Always exclude `node_modules/`, `.git/`, `vendor/`, `__pycache__/`, `.venv/`, `venv/`, `dist/`, `build/` by default.

Save the inventory to `codesoteria-output/inventory.json`:
```json
{
  "target_path": "/absolute/path",
  "languages": ["typescript", "python"],
  "frameworks": ["express", "react"],
  "has_docker": true,
  "has_kubernetes": false,
  "has_terraform": true,
  "has_ci_cd": true,
  "has_dependency_manifests": true,
  "has_crypto_imports": true,
  "has_api_routes": true,
  "has_database_models": true,
  "manifest_files": ["package.json", "requirements.txt"],
  "iac_files": ["Dockerfile", "terraform/main.tf"],
  "ci_cd_files": [".github/workflows/ci.yml"],
  "approximate_loc": 15000,
  "file_count": 120,
  "excluded_paths": ["node_modules/", "dist/"]
}
```

### 0.2 — Determine Applicable Agents

Based on the inventory, determine which agents to run:

| Agent | Condition | Always? |
|-------|-----------|---------|
| SAST | Source code files exist | Yes |
| SECRETS | Any text files exist | Yes |
| AUTH | Web framework or API framework detected, OR auth-related keywords in code | Yes (for any non-trivial project) |
| API | API routes/endpoints detected (Express routes, Django URLs, Spring controllers, etc.) | Yes (for web projects) |
| DEPS | At least one dependency manifest or lock file exists | Conditional |
| CRYPTO | Crypto library imports detected, OR JWT/TLS usage | Conditional |
| CONFIG | Dockerfiles, k8s manifests, Terraform files, or CI/CD configs exist | Conditional |
| DATA | Database models, ORM usage, or PII-handling patterns detected | Conditional |

If the user specified `focus_areas`, only activate those agents (but warn if they're skipping applicable agents).

Save to `codesoteria-output/agent-plan.json`:
```json
{
  "agents": {
    "SAST": {"active": true, "reason": "Source code detected"},
    "DEPS": {"active": true, "reason": "package.json and requirements.txt found"},
    "SECRETS": {"active": true, "reason": "Always active"},
    "CONFIG": {"active": true, "reason": "Dockerfile and Terraform files found"},
    "AUTH": {"active": true, "reason": "Express with passport.js detected"},
    "CRYPTO": {"active": false, "reason": "No crypto library imports detected"},
    "API": {"active": true, "reason": "Express routes found"},
    "DATA": {"active": true, "reason": "Sequelize models detected"}
  }
}
```

### 0.3 — Prepare Scoped File Lists

For each active agent, generate a focused list of files relevant to its domain. This prevents agents from wasting context on irrelevant files.

**SAST**: All source code files (`.js`, `.ts`, `.py`, `.go`, `.rs`, `.java`, `.c`, `.cpp`, `.rb`, `.php`, `.cs`) excluding tests, generated files, and vendored code.

**DEPS**: All manifest and lock files only.

**SECRETS**: All text files (source, config, env, yaml, json, xml, properties, ini). Include `.env*` files explicitly.

**CONFIG**: Dockerfiles, `docker-compose.yml`, `*.tf`, `*.tfvars`, k8s manifests, CI/CD configs, web server configs (nginx.conf, apache configs), `.env` files.

**AUTH**: Source files containing auth-related keywords (filter by imports: passport, auth, session, jwt, oauth, login, middleware; and by file paths: `auth/`, `middleware/`, `routes/`, `controllers/`).

**CRYPTO**: Source files that import crypto libraries or reference crypto primitives.

**API**: Route handlers, controllers, middleware, OpenAPI/Swagger specs, GraphQL schemas and resolvers.

**DATA**: Database models, migrations, serializers, ORM queries, logging configuration, data transfer objects.

Save each list to `codesoteria-output/scope/<agent-lowercase>-files.txt` (one file path per line).

Present the scope summary to the user before proceeding:

```
Codebase Inventory Complete
============================
Languages: TypeScript, Python
Frameworks: Express, React
LOC: ~15,000 | Files: 120

Active Agents: SAST, DEPS, SECRETS, CONFIG, AUTH, API, DATA (7 of 8)
Skipped: CRYPTO (no crypto imports detected)

Files per agent:
  SAST:    85 source files
  DEPS:    4 manifest files
  SECRETS: 110 text files
  CONFIG:  6 infrastructure files
  AUTH:    12 auth-related files
  API:     18 route/controller files
  DATA:    14 model/query files
```

---

## Phase 1: Pre-Flight Tool Check

### 1.1 — Check Tool Availability

Look for the pre-flight script at `~/.claude/codesoteria/scripts/preflight.sh` or `./scripts/preflight.sh`. If found, run it. Otherwise, manually check each tool needed by active agents.

Read `tool-registry.md` for the complete tool catalog. For each active agent with external tools:

```bash
# Quick check for each tool
command -v <tool_name> >/dev/null 2>&1 && echo "AVAILABLE" || echo "MISSING"
```

Determine installability for missing tools:
- If `pip3` is available → Python tools (semgrep, bandit, etc.) are INSTALLABLE
- If `brew` is available → most binary tools are INSTALLABLE via Homebrew
- If `go` is available → Go tools (gosec, osv-scanner, etc.) are INSTALLABLE
- If `npm` is available → JS tools (eslint) are INSTALLABLE
- If `cargo` is available → Rust tools (cargo-audit) are INSTALLABLE
- If none of these apply → tool is UNAVAILABLE

### 1.2 — Present Tool Status

Display a structured summary to the user:

```
Security Tool Pre-Flight
=========================

AVAILABLE:
  semgrep          v1.56.0
  npm              v10.2.0
  gitleaks         v8.18.0

INSTALLABLE:
  bandit           pip install bandit (~30 sec)
  osv-scanner      brew install osv-scanner (~30 sec)
  checkov          pip install checkov (~2 min)
  hadolint         brew install hadolint (~30 sec)

UNAVAILABLE:
  gosec            Go runtime not installed
  trivy            No install method detected

Impact of unavailable tools:
  - gosec: Go-specific SAST patterns will rely on Semgrep + LLM review only
  - trivy: Container image cross-check scanning will not be performed
```

### 1.3 — User Decision

Ask the user how to proceed with missing tools:

**Option A**: Install all installable tools, then scan
**Option B**: Let me choose which tools to install
**Option C**: Skip all installs — run with available tools + LLM-only analysis
**Option D**: Abort the audit

If the user chooses A or B, proceed to installation. If C, mark all unavailable/missing tools accordingly and proceed. If D, stop.

### 1.4 — Install and Verify

For each tool to install:
1. Run the install command from `tool-registry.md` (prefer Homebrew on macOS for binary tools, pip for Python tools)
2. Verify with the tool's verify command
3. Report success or failure

Install independent tools in parallel where possible (separate pip installs, separate brew installs).

If any installation fails, report the failure and proceed with that tool marked as UNAVAILABLE.

Save final status to `codesoteria-output/tool-status.json`:
```json
{
  "tools": {
    "semgrep": {"status": "available", "version": "1.56.0"},
    "bandit": {"status": "installed", "version": "1.7.7"},
    "osv-scanner": {"status": "unavailable", "reason": "brew install failed"},
    "gitleaks": {"status": "available", "version": "8.18.0"}
  }
}
```

**Tell the user the pre-flight is complete and confirm before proceeding to the scan.**

---

## Phase 2: Agent Execution

### Sub-Agent Prompt Template

For each active agent, spawn a subagent using the Agent tool with this prompt structure. Find the reference file path first (check both locations from the top of this file).

```
You are a specialized security auditor performing the [AGENT_ID] analysis as part of an automated security audit.

**Target repository**: [TARGET_PATH]
**Scoped files**: Read the file list at [CWD]/codesoteria-output/scope/[agent-lowercase]-files.txt — only analyze files in this list.
**Available tools**: [LIST each tool with status: available/unavailable]
**Codebase context**: [LANGUAGES], [FRAMEWORKS], ~[LOC] lines of code

## Instructions

1. Read your playbook at: [REFERENCES_PATH]/agents/[agent-lowercase]-playbook.md
2. Read the finding schema at: [REFERENCES_PATH]/finding-schema.md
3. Read the severity model at: [REFERENCES_PATH]/severity-model.md
4. Follow your playbook precisely.
5. For each AVAILABLE external tool, run it via Bash and analyze its output.
6. Perform LLM-based code review for patterns tools may miss.
7. Apply balanced false-positive filtering per the severity model.
8. Create the raw output directory if using tools: mkdir -p [CWD]/codesoteria-output/findings/[agent-lowercase]-raw

Save your structured findings to: [CWD]/codesoteria-output/findings/[agent-lowercase].json
Save a human-readable summary to: [CWD]/codesoteria-output/findings/[agent-lowercase]-summary.md

Your JSON output MUST conform to finding-schema.md exactly. The summary should be a concise narrative (1-2 pages) covering what was checked, key findings, and overall assessment.
```

### Execution

Spawn ALL active agents in **parallel** using the Agent tool with `run_in_background: true` for each. Use `subagent_type: "general-purpose"` for all agents.

Example for 7 active agents — send all Agent tool calls in a single message:

1. Agent: SAST (run_in_background: true)
2. Agent: DEPS (run_in_background: true)
3. Agent: SECRETS (run_in_background: true)
4. Agent: CONFIG (run_in_background: true)
5. Agent: AUTH (run_in_background: true)
6. Agent: API (run_in_background: true)
7. Agent: DATA (run_in_background: true)

**Wait for ALL agents to complete before proceeding to Phase 3.**

As each agent completes, note whether it succeeded or failed. If an agent fails, record the failure reason but continue with the others.

---

## Phase 3: Collection & Cross-Correlation

### 3.1 — Collect All Findings

Read all JSON files from `codesoteria-output/findings/*.json` (excluding raw directories). For each file:
1. Validate it conforms to the finding schema
2. Count findings by severity
3. If a file is missing or invalid, note the agent failure

### 3.2 — Deduplicate and Cross-Correlate

Read `cross-correlation.md` for the detailed rules. Perform:

1. **Same-location deduplication**: Merge findings from different agents that reference the same file + line range (±5 lines)
2. **Compound finding detection**: Check all cross-agent finding pairs against the compound patterns
3. **Cross-referencing**: Add `related_findings` links between findings that reference the same files or dependencies
4. **Final severity reassessment**: Multi-agent confirmation increases confidence; compound chains escalate severity

### 3.3 — Generate Consolidated Output

Write the merged, deduplicated, and correlated findings to:
`codesoteria-output/findings/consolidated.json`

This file uses the same schema as individual agent outputs, with additional fields:
- `contributing_agents` for merged findings
- `related_findings` for cross-references
- `compound_chain` for compound findings

---

## Phase 4: Report Generation

### 4.1 — Generate the Report

Read `report-template.md` for the full template. Generate the report at:
`codesoteria-output/report/security-audit.md`

Fill in all sections:
- **Executive Summary**: Overall risk rating (based on highest-severity confirmed finding), finding counts, top 5 findings
- **Tool Coverage**: Which agents ran, which tools were used, any gaps
- **Findings by Domain**: All findings grouped by agent, sorted by severity
- **Compound Findings**: Any attack chains identified in cross-correlation
- **Remediation Roadmap**: All findings organized by priority (P0 → P3), with quick wins highlighted
- **Appendices**: Configuration, file counts, SBOM path if generated

### 4.2 — Generate Machine-Readable Output

Also generate `codesoteria-output/report/security-audit.json` with the full structured data.

### 4.3 — Present Results

Tell the user the audit is complete. Display:

```
Security Audit Complete
========================
Overall Risk: [RATING]

Findings: [TOTAL] total
  CRITICAL: [N]    HIGH: [N]
  MEDIUM: [N]      LOW: [N]

Compound findings: [N] attack chains identified

Reports saved to:
  codesoteria-output/report/security-audit.md   (full report)
  codesoteria-output/report/security-audit.json  (machine-readable)
  codesoteria-output/findings/consolidated.json  (all findings)

Top actions:
  1. [TOP_P0_FINDING_TITLE]
  2. [NEXT_FINDING_TITLE]
  3. [NEXT_FINDING_TITLE]
```

Offer the user follow-up options:
- Deep-dive into any specific finding or domain
- Re-run a specific agent
- Generate a shorter executive briefing
- Explain any finding in more detail
