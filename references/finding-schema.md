# Finding Schema

All agents must output a JSON file conforming to this schema. This is the contract that enables cross-agent deduplication, correlation, and unified reporting.

## Top-Level Structure

```json
{
  "agent": "<AGENT_ID>",
  "scan_timestamp": "<ISO 8601>",
  "target_path": "/absolute/path/to/codebase",
  "tools_used": [
    {
      "name": "semgrep",
      "version": "1.56.0",
      "status": "ran_successfully | failed | skipped | unavailable",
      "note": "Optional explanation if failed/skipped"
    }
  ],
  "findings": [ ... ],
  "summary": { ... }
}
```

**Agent IDs:** `SAST`, `DEPS`, `SECRETS`, `CONFIG`, `AUTH`, `CRYPTO`, `API`, `DATA`

## Finding Object

Each entry in the `findings` array must contain:

```json
{
  "id": "<AGENT_ID>-F<NNN>",
  "title": "Short descriptive title",
  "description": "Detailed explanation of the vulnerability and its impact",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "confidence": "HIGH | MEDIUM | LOW",
  "category": "<primary category>",
  "cwe_id": "CWE-<number> or null if not applicable",
  "owasp_category": "A01:2021-Broken Access Control | ... | null",
  "location": {
    "file": "relative/path/from/repo/root",
    "line_start": 45,
    "line_end": 52,
    "snippet": "The relevant code lines (max 10 lines)"
  },
  "evidence": "Tool output, reasoning, or proof that supports this finding",
  "source": "tool | llm-review | both",
  "source_tool": "semgrep | bandit | osv-scanner | ... | null",
  "remediation": {
    "description": "How to fix this issue",
    "effort": "LOW | MEDIUM | HIGH",
    "priority": "P0 | P1 | P2 | P3",
    "code_suggestion": "Optional corrected code snippet or null"
  },
  "references": [
    "https://cwe.mitre.org/data/definitions/89.html"
  ],
  "false_positive_risk": "LOW | MEDIUM | HIGH",
  "false_positive_reasoning": "Why this might or might not be a false positive",
  "tags": ["injection", "database", "user-input"]
}
```

### Field Notes

- **id**: Sequential within each agent. Format: `SAST-F001`, `DEPS-F002`, etc.
- **severity**: See `severity-model.md` for rating criteria.
- **confidence**: HIGH = confirmed by tool + code review or unambiguous pattern. MEDIUM = flagged by tool OR LLM with supporting evidence. LOW = heuristic match, may be false positive.
- **category**: Primary category from: `injection`, `xss`, `auth`, `access-control`, `crypto`, `secrets`, `config`, `dependency`, `api`, `data-exposure`, `privacy`, `deserialization`, `path-traversal`, `ssrf`, `race-condition`, `information-disclosure`, `other`.
- **location**: `line_start` and `line_end` should point to the vulnerable code. `snippet` is the extracted code (for report display).
- **source**: `tool` = found by external tool only. `llm-review` = found by LLM analysis only. `both` = found by tool and confirmed by LLM.
- **false_positive_risk**: Use balanced filtering — LOW means almost certainly a real issue, MEDIUM means needs manual review, HIGH means likely false positive but included for completeness.
- **effort**: LOW = single-line or config change. MEDIUM = refactor a function or add middleware. HIGH = architectural change or multi-file refactor.
- **priority**: Derived from severity x confidence per the priority matrix in severity-model.md.

## Summary Object

```json
{
  "total_findings": 12,
  "by_severity": {
    "CRITICAL": 1,
    "HIGH": 3,
    "MEDIUM": 5,
    "LOW": 3
  },
  "by_confidence": {
    "HIGH": 6,
    "MEDIUM": 4,
    "LOW": 2
  },
  "by_source": {
    "tool": 4,
    "llm-review": 5,
    "both": 3
  },
  "tool_coverage": "Description of what was and wasn't scanned, any gaps or limitations",
  "key_observations": "1-2 sentence summary of the most important patterns found"
}
```

## Output Paths

Each agent writes two files:

1. **JSON findings**: `codesoteria-output/findings/<agent-lowercase>.json` — must conform to this schema exactly
2. **Markdown summary**: `codesoteria-output/findings/<agent-lowercase>-summary.md` — human-readable narrative of findings for quick review

If an agent runs external tools, save raw tool output to:
- `codesoteria-output/findings/<agent-lowercase>-raw/<toolname>-output.json`

This preserves the full tool output for debugging without bloating the main findings file.
