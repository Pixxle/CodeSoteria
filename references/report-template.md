# Report Template

Use this template to generate the final security audit report. Fill in all sections based on the consolidated findings and audit metadata.

---

## Report Structure

```markdown
# Security Audit Report

**Project**: [PROJECT_NAME]
**Audit Date**: [DATE]
**Prepared by**: CodeSoteria — Automated Security Audit
**Scope**: [LANGUAGES] | [LOC] lines | [FILE_COUNT] files scanned
**Duration**: [DURATION]

---

## 1. Executive Summary

### Overall Risk Rating: [CRITICAL / HIGH / MEDIUM / LOW]

[One paragraph summarizing the security posture. Include:
- Total number of findings
- Breakdown by severity
- Whether any CRITICAL findings require immediate action
- Key positive observations (if any)
- Overall assessment for the project's maturity stage]

### Top Findings

| # | Severity | Title | Location | Priority |
|---|----------|-------|----------|----------|
| 1 | [SEV] | [TITLE] | [FILE:LINE] | [P0/P1/P2/P3] |
| 2 | [SEV] | [TITLE] | [FILE:LINE] | [P0/P1/P2/P3] |
| 3 | [SEV] | [TITLE] | [FILE:LINE] | [P0/P1/P2/P3] |
| 4 | [SEV] | [TITLE] | [FILE:LINE] | [P0/P1/P2/P3] |
| 5 | [SEV] | [TITLE] | [FILE:LINE] | [P0/P1/P2/P3] |

[List the top 5 findings by severity, then confidence. If fewer than 5 findings exist, list all.]

### Finding Summary

| Severity | Count |
|----------|-------|
| CRITICAL | [N] |
| HIGH | [N] |
| MEDIUM | [N] |
| LOW | [N] |
| **Total** | **[N]** |

---

## 2. Tool Coverage

### Agents Deployed

| Agent | Domain | External Tools Used | LLM Review | Status |
|-------|--------|-------------------|------------|--------|
| SAST | Static Analysis | [tools or "none"] | Yes | Ran / Skipped |
| DEPS | Dependencies | [tools or "none"] | Yes | Ran / Skipped |
| SECRETS | Secret Detection | [tools or "none"] | Yes | Ran / Skipped |
| CONFIG | Configuration | [tools or "none"] | Yes | Ran / Skipped |
| AUTH | Authentication | (LLM-only) | Yes | Ran / Skipped |
| CRYPTO | Cryptography | (LLM-only) | Yes | Ran / Skipped |
| API | API Security | (LLM-only) | Yes | Ran / Skipped |
| DATA | Data Handling | [tools or "none"] | Yes | Ran / Skipped |

### Coverage Gaps

[List any tools that were unavailable and the impact on coverage. For example:
- "Trivy was unavailable; container image vulnerability scanning was not performed."
- "Bearer was unavailable; data flow analysis relied on LLM review only."
If no gaps: "All applicable tools ran successfully. Full coverage achieved."]

### Exclusions

[List any paths or files excluded from the audit, and why.]

---

## 3. Findings by Domain

[For each agent that produced findings, create a subsection. Order by severity of findings within each domain.]

### 3.1 [AGENT_NAME] Findings

[For each finding in this domain:]

#### [FINDING_ID]: [TITLE]

| Attribute | Value |
|-----------|-------|
| **Severity** | [CRITICAL/HIGH/MEDIUM/LOW] |
| **Confidence** | [HIGH/MEDIUM/LOW] |
| **Priority** | [P0/P1/P2/P3] |
| **CWE** | [CWE-ID or N/A] |
| **OWASP** | [Category or N/A] |
| **Source** | [Tool name / LLM Review / Both] |
| **Location** | `[file]:[line_start]-[line_end]` |

**Description**: [DESCRIPTION]

**Evidence**:
```
[Code snippet or tool output excerpt]
```

**Remediation**: [REMEDIATION_DESCRIPTION]

**Effort**: [LOW/MEDIUM/HIGH]

[If code suggestion available:]
**Suggested Fix**:
```[language]
[CODE_SUGGESTION]
```

---

## 4. Compound Findings

[If any compound findings were identified during cross-correlation, list them here. These represent attack chains combining findings from multiple agents.]

### [COMPOUND_ID]: [TITLE]

**Chain**: [FINDING_A_ID] ([AGENT]) + [FINDING_B_ID] ([AGENT]) → [COMPOUND_RISK]

| Attribute | Value |
|-----------|-------|
| **Severity** | [ESCALATED_SEVERITY] |
| **Confidence** | [CONFIDENCE] |
| **Priority** | [P0/P1/P2/P3] |

**Description**: [How the two findings combine to create elevated risk]

**Remediation**: [Fix either or both findings in the chain]

---

## 5. Remediation Roadmap

### P0 — Immediate (fix now)

[List all P0 findings with one-line remediation summary and effort]

| Finding | Remediation | Effort |
|---------|-------------|--------|
| [ID]: [TITLE] | [ONE_LINE_FIX] | [LOW/MED/HIGH] |

### P1 — Short Term (within 1 week)

| Finding | Remediation | Effort |
|---------|-------------|--------|
| [ID]: [TITLE] | [ONE_LINE_FIX] | [LOW/MED/HIGH] |

### P2 — Medium Term (within 30 days)

| Finding | Remediation | Effort |
|---------|-------------|--------|
| [ID]: [TITLE] | [ONE_LINE_FIX] | [LOW/MED/HIGH] |

### P3 — Backlog

| Finding | Remediation | Effort |
|---------|-------------|--------|
| [ID]: [TITLE] | [ONE_LINE_FIX] | [LOW/MED/HIGH] |

### Quick Wins

[Highlight any LOW-effort fixes from the P0/P1 lists — these should be done first as they have the best effort-to-impact ratio.]

---

## 6. Appendices

### A: Audit Configuration

```json
{
  "target_path": "[PATH]",
  "exclude_paths": [LIST],
  "compliance_targets": [LIST],
  "severity_threshold": "[THRESHOLD]",
  "scan_timestamp": "[TIMESTAMP]"
}
```

### B: Files Scanned Per Agent

| Agent | File Count | Key Directories |
|-------|-----------|-----------------|
| SAST | [N] | [DIRS] |
| DEPS | [N] | [MANIFEST_FILES] |
| ... | ... | ... |

### C: Raw Tool Outputs

Raw tool outputs are saved in `codesoteria-output/findings/<agent>-raw/`.

### D: SBOM

[If SBOM was generated, note the path: `codesoteria-output/findings/deps-raw/sbom-cyclonedx.json`]

### E: Methodology

This audit was performed by CodeSoteria, an automated security audit system that combines:
- **External scanning tools**: Industry-standard SAST, SCA, secret detection, and IaC scanning tools
- **LLM-based code review**: AI-powered analysis for business logic, authentication, cryptography, API, and data handling patterns
- **Cross-correlation**: Automated deduplication and compound finding detection across all agents

All findings are rated using a standardized severity model (CRITICAL/HIGH/MEDIUM/LOW) with confidence levels (HIGH/MEDIUM/LOW) and balanced false-positive filtering.
```

## Report Generation Rules

1. **Sort findings within each domain** by severity DESC, then confidence DESC, then priority ASC
2. **Include ALL findings** at or above the user's configured severity threshold (default: include all)
3. **Compound findings** go in section 4, not duplicated in section 3
4. **Keep descriptions concise** — 2-3 sentences max per finding description
5. **Always include code snippets** when available — developers need to see the exact code
6. **Remediation must be actionable** — not just "fix this" but how to fix it
7. **If zero findings**: Still generate the report with a clean bill of health, noting what was checked

## Machine-Readable Output

In addition to the markdown report, generate `codesoteria-output/report/security-audit.json` containing:

```json
{
  "metadata": {
    "project": "[NAME]",
    "audit_date": "[ISO8601]",
    "tool": "CodeSoteria",
    "version": "1.0.0",
    "target_path": "[PATH]",
    "configuration": { ... }
  },
  "summary": {
    "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
    "total_findings": N,
    "by_severity": { ... },
    "by_agent": { ... },
    "compound_findings": N
  },
  "findings": [ ... ],
  "compound_findings": [ ... ],
  "tool_coverage": { ... },
  "remediation_roadmap": {
    "p0": [ ... ],
    "p1": [ ... ],
    "p2": [ ... ],
    "p3": [ ... ]
  }
}
```
