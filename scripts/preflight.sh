#!/usr/bin/env bash
# preflight.sh — Check availability of security analysis tools
#
# Outputs structured lines in the format:
#   STATUS|AGENT|TOOL|VERSION_OR_NOTE
#
# STATUS: AVAILABLE, MISSING
# The orchestrator parses this output to determine installability.

set -euo pipefail

echo "PREFLIGHT_START"

check_tool() {
    local name="$1"
    local agent="$2"
    local verify_cmd="$3"

    if command -v "$name" &>/dev/null; then
        version=$($verify_cmd 2>&1 | head -1 || echo "unknown")
        echo "AVAILABLE|$agent|$name|$version"
    else
        echo "MISSING|$agent|$name|"
    fi
}

echo "--- RUNTIMES ---"
check_tool "python3" "RUNTIME" "python3 --version"
check_tool "pip3" "RUNTIME" "pip3 --version"
check_tool "node" "RUNTIME" "node --version"
check_tool "npm" "RUNTIME" "npm --version"
check_tool "go" "RUNTIME" "go version"
check_tool "cargo" "RUNTIME" "cargo --version"
check_tool "brew" "RUNTIME" "brew --version"
check_tool "docker" "RUNTIME" "docker --version"

echo "--- SAST TOOLS ---"
check_tool "semgrep" "SAST" "semgrep --version"
check_tool "bandit" "SAST" "bandit --version"
check_tool "gosec" "SAST" "gosec --version"
check_tool "flawfinder" "SAST" "flawfinder --version"
check_tool "eslint" "SAST" "eslint --version"

echo "--- DEPS TOOLS ---"
check_tool "osv-scanner" "DEPS" "osv-scanner --version"
check_tool "grype" "DEPS" "grype version"
check_tool "syft" "DEPS" "syft version"
check_tool "trivy" "DEPS" "trivy --version"
check_tool "pip-audit" "DEPS" "pip-audit --version"
# npm is checked under runtimes
# cargo-audit is a cargo subcommand
if command -v cargo &>/dev/null && cargo audit --version &>/dev/null 2>&1; then
    version=$(cargo audit --version 2>&1 | head -1)
    echo "AVAILABLE|DEPS|cargo-audit|$version"
else
    echo "MISSING|DEPS|cargo-audit|"
fi

echo "--- SECRETS TOOLS ---"
check_tool "gitleaks" "SECRETS" "gitleaks version"
check_tool "trufflehog" "SECRETS" "trufflehog --version"
check_tool "detect-secrets" "SECRETS" "detect-secrets --version"

echo "--- CONFIG TOOLS ---"
check_tool "checkov" "CONFIG" "checkov --version"
check_tool "hadolint" "CONFIG" "hadolint --version"
check_tool "kube-linter" "CONFIG" "kube-linter version"
check_tool "dockle" "CONFIG" "dockle --version"

echo "--- DATA TOOLS ---"
check_tool "bearer" "DATA" "bearer version"

echo "PREFLIGHT_COMPLETE"
