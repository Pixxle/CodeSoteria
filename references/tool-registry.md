# Tool Registry

Master catalog of all external security tools used by CodeSoteria agents.

## SAST Tools

| Tool | Agent | macOS Install | Linux Install | Min Version | Verify Command |
|------|-------|---------------|---------------|-------------|----------------|
| semgrep | SAST | `pip install semgrep` | `pip install semgrep` | 1.0+ | `semgrep --version` |
| bandit | SAST | `pip install bandit` | `pip install bandit` | 1.7+ | `bandit --version` |
| gosec | SAST | `brew install gosec` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | 2.0+ | `gosec --version` |
| flawfinder | SAST | `pip install flawfinder` | `pip install flawfinder` | 2.0+ | `flawfinder --version` |
| eslint | SAST | `npm install -g eslint eslint-plugin-security` | `npm install -g eslint eslint-plugin-security` | 8.0+ | `eslint --version` |

## Dependency & Supply Chain Tools

| Tool | Agent | macOS Install | Linux Install | Min Version | Verify Command |
|------|-------|---------------|---------------|-------------|----------------|
| osv-scanner | DEPS | `brew install osv-scanner` | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` | 1.0+ | `osv-scanner --version` |
| grype | DEPS | `brew install grype` | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh -s -- -b /usr/local/bin` | 0.70+ | `grype version` |
| syft | DEPS | `brew install syft` | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh -s -- -b /usr/local/bin` | 0.90+ | `syft version` |
| trivy | DEPS | `brew install trivy` | `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \| sh -s -- -b /usr/local/bin` | 0.48+ | `trivy --version` |
| npm | DEPS | (built-in with Node.js) | (built-in with Node.js) | 8.0+ | `npm --version` |
| pip-audit | DEPS | `pip install pip-audit` | `pip install pip-audit` | 2.0+ | `pip-audit --version` |
| cargo-audit | DEPS | `cargo install cargo-audit` | `cargo install cargo-audit` | 0.18+ | `cargo audit --version` |

## Secret Detection Tools

| Tool | Agent | macOS Install | Linux Install | Min Version | Verify Command |
|------|-------|---------------|---------------|-------------|----------------|
| gitleaks | SECRETS | `brew install gitleaks` | `go install github.com/gitleaks/gitleaks/v8@latest` | 8.0+ | `gitleaks version` |
| trufflehog | SECRETS | `brew install trufflehog` | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh -s -- -b /usr/local/bin` | 3.0+ | `trufflehog --version` |
| detect-secrets | SECRETS | `pip install detect-secrets` | `pip install detect-secrets` | 1.4+ | `detect-secrets --version` |

## Configuration & Infrastructure Tools

| Tool | Agent | macOS Install | Linux Install | Min Version | Verify Command |
|------|-------|---------------|---------------|-------------|----------------|
| checkov | CONFIG | `pip install checkov` | `pip install checkov` | 3.0+ | `checkov --version` |
| hadolint | CONFIG | `brew install hadolint` | `wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x /usr/local/bin/hadolint` | 2.0+ | `hadolint --version` |
| kube-linter | CONFIG | `brew install kube-linter` | `go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest` | 0.6+ | `kube-linter version` |
| dockle | CONFIG | `brew install goodwithtech/r/dockle` | `curl -sSfL https://raw.githubusercontent.com/goodwithtech/dockle/master/install.sh \| sh -s -- -b /usr/local/bin` | 0.4+ | `dockle --version` |

## Data Flow Tools

| Tool | Agent | macOS Install | Linux Install | Min Version | Verify Command |
|------|-------|---------------|---------------|-------------|----------------|
| bearer | DATA | `brew install bearer/tap/bearer` | `curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \| sh -s -- -b /usr/local/bin` | 1.0+ | `bearer version` |

## Runtime Requirements

These are prerequisites for installing and running certain tools:

| Runtime | Required By | Check Command |
|---------|-------------|---------------|
| Python 3 | semgrep, bandit, flawfinder, pip-audit, detect-secrets, checkov | `python3 --version` |
| pip | semgrep, bandit, flawfinder, pip-audit, detect-secrets, checkov | `pip --version` or `pip3 --version` |
| Node.js | eslint, npm audit | `node --version` |
| npm | eslint, npm audit | `npm --version` |
| Go | gosec, osv-scanner, gitleaks, kube-linter | `go version` |
| Cargo | cargo-audit | `cargo --version` |
| Homebrew | (macOS alternative for most tools) | `brew --version` |
| Docker | dockle (image scanning only) | `docker --version` |

## Agent → Tool Mapping

Quick reference for which tools each agent needs:

| Agent | Required Tools | Optional Tools |
|-------|---------------|----------------|
| SAST | semgrep | bandit (Python), gosec (Go), flawfinder (C/C++), eslint (JS/TS) |
| DEPS | osv-scanner | grype, syft, trivy, npm (JS), pip-audit (Python), cargo-audit (Rust) |
| SECRETS | gitleaks | trufflehog, detect-secrets |
| CONFIG | checkov | hadolint, kube-linter, dockle |
| AUTH | (none — LLM-only) | |
| CRYPTO | (none — LLM-only) | |
| API | (none — LLM-only) | |
| DATA | (none) | bearer |

"Required" means the primary tool for that agent. "Optional" means language-specific or supplementary tools that improve coverage.
