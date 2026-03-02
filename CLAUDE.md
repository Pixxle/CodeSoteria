# CodeSoteria — Automated Security Audit Skill

CodeSoteria performs comprehensive automated security audits by orchestrating parallel analysis agents. Each agent specializes in a security domain and uses a combination of external tools and LLM-based code review.

## Commands

- `/codesoteria:scan <path>` — Run a full security audit on the target codebase

## Architecture

**Orchestrator** (scan.md) manages the lifecycle:
1. Inventory the codebase (languages, frameworks, manifests, IaC)
2. Pre-flight check (verify external tool availability)
3. Spawn parallel agents (each scoped to a security domain)
4. Collect findings, deduplicate, cross-correlate
5. Generate unified report

**8 Specialized Agents:**
- SAST — Static Application Security Testing (Semgrep + language-specific tools + LLM)
- DEPS — Dependency & Supply Chain (OSV-Scanner, Grype, Trivy, native audit tools + LLM)
- SECRETS — Secret & Credential Detection (Gitleaks, TruffleHog, detect-secrets + LLM)
- CONFIG — Configuration & Infrastructure (Checkov, Hadolint, Kube-linter + LLM)
- AUTH — Authentication & Authorization (LLM-only)
- CRYPTO — Cryptography Review (LLM-only)
- API — API Security (LLM-only)
- DATA — Data Handling & Privacy (Bearer + LLM)

## File Layout

```
.claude/commands/codesoteria/
  scan.md                    # Orchestrator entry point
references/
  agents/                    # Per-agent playbooks (8 files)
  tool-registry.md           # External tool catalog
  finding-schema.md          # JSON schema for findings
  report-template.md         # Report structure
  severity-model.md          # Severity/confidence model
  cross-correlation.md       # Dedup and correlation rules
scripts/
  install.sh                 # Global install
  preflight.sh               # Tool availability checker
```

## Output Convention

All audit artifacts are written to `codesoteria-output/` in the current working directory.

## Global Install

```bash
bash scripts/install.sh
```

## Design Decisions

- **Git history scanning**: On by default (opt-out) for TruffleHog
- **False-positive filtering**: Balanced — filter obvious FPs, flag uncertain as needs-review
- **Scanner mode**: Thorough — always run all available scanners per domain
- **Verified secrets**: Disabled — never test found credentials against live APIs
- **Severity model**: CRITICAL/HIGH/MEDIUM/LOW with HIGH/MEDIUM/LOW confidence
- **Priority matrix**: P0-P3 derived from severity x confidence
