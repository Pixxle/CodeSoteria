<p align="center">
  <img src="assets/banner.jpeg" alt="CodeAtlas" width="700">
</p>

# CodeSoteria

Automated security audits for codebases, powered by [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview).

Orchestrates 8 parallel specialized agents to analyze SAST, dependencies, secrets, infrastructure, authentication, cryptography, API security, and data handling — producing a prioritized report with remediation guidance backed by concrete evidence.

## Install

```bash
bash scripts/install.sh
```

## Usage

```
/codesoteria:scan <path>    # Full security audit
```

## Agents

| Agent | Domain | Tooling |
|-------|--------|---------|
| **SAST** | Injection, XSS, deserialization, path traversal | Semgrep, Bandit, Gosec, Flawfinder, ESLint |
| **DEPS** | Vulnerable dependencies, supply chain, license risk | OSV-Scanner, Grype, Syft, Trivy, npm/pip/cargo audit |
| **SECRETS** | Hardcoded credentials, API keys, git history leaks | Gitleaks, TruffleHog, detect-secrets |
| **CONFIG** | Docker, Kubernetes, Terraform, CI/CD misconfigs | Checkov, Hadolint, Kube-linter, Dockle |
| **AUTH** | Broken access control, session management, JWT flaws | LLM analysis |
| **CRYPTO** | Weak algorithms, key management, TLS configuration | LLM analysis |
| **API** | Input validation, rate limiting, CORS, mass assignment | LLM analysis |
| **DATA** | PII handling, logging hygiene, privacy compliance | Bearer + LLM analysis |

External tools are optional. Agents fall back to LLM-only analysis when tools are unavailable.

## How It Works

1. **Inventory** — Detects languages, frameworks, and infrastructure
2. **Pre-Flight** — Checks tool availability, offers to install missing ones
3. **Parallel Scan** — Spawns all applicable agents simultaneously
4. **Cross-Correlation** — Deduplicates findings and identifies attack chains
5. **Report** — Generates prioritized findings with remediation roadmap

## Output

Reports are saved to `codesoteria-output/` in your working directory:

```
codesoteria-output/
  report/security-audit.md       # Full report
  report/security-audit.json     # Machine-readable
  findings/consolidated.json     # Deduplicated & correlated
  findings/<agent>.json          # Per-agent findings
```

## License

[MIT](LICENSE)
