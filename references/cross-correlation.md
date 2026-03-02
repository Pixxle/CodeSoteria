# Cross-Correlation Rules

After all agents have completed, the orchestrator runs a deduplication and cross-correlation pass on the consolidated findings. This document defines the rules for that pass.

## Phase 1: Deduplication

### Same-Location Dedup

When two or more findings from different agents reference the same file and overlapping line ranges (within ±5 lines), they may be duplicates of the same underlying issue.

**Merge rules:**
1. Compare the `file` + `line_start`/`line_end` fields across all findings
2. If two findings overlap within ±5 lines in the same file:
   - Check if they describe the same underlying issue (use title and description similarity)
   - If yes: merge into a single finding
     - Keep the higher severity
     - Keep the higher confidence
     - Combine evidence from both agents
     - Set `source` to `"multiple-agents"`
     - Add both agent IDs to a new `contributing_agents` field
     - Use the more specific title
   - If no (different issues at nearby lines): keep both findings, add cross-reference in `tags`

### Same-CVE Dedup (DEPS agent internal)

This should already be handled by the DEPS agent internally, but verify:
- The same CVE/advisory should not appear multiple times in the consolidated output
- If it does (from different scanners in the DEPS agent), merge keeping the most detailed entry

### Same-Secret Dedup

If SECRETS agent and another agent (e.g., SAST or CONFIG) both flag the same hardcoded credential:
- Merge into the SECRETS agent's finding (more specialized)
- Add the other agent's context to the evidence

## Phase 2: Cross-Correlation

Look for findings from different agents that, when combined, create a higher-severity compound risk. Create new compound findings for these chains.

### Compound Finding Patterns

#### Chain 1: Secret + Auth Flow
- **SECRETS** finding: hardcoded secret/credential
- **AUTH** finding: the same credential is used in an authentication flow
- **Compound**: The authentication system relies on a compromised secret
- **Severity**: Escalate to CRITICAL (regardless of individual severities)
- **ID format**: `COMPOUND-C001`

#### Chain 2: Vulnerable Dependency + Reachable Code Path
- **DEPS** finding: vulnerable dependency (CVE)
- **SAST** finding: code that imports/calls the vulnerable function from that dependency
- **Compound**: The vulnerability is confirmed reachable (not just present in lock file)
- **Severity**: Escalate — at minimum HIGH, CRITICAL if the CVE is CRITICAL
- **ID format**: `COMPOUND-C002`

#### Chain 3: SQL Injection + PII in Database
- **SAST** finding: SQL injection vulnerability
- **DATA** finding: the affected table/query handles PII
- **Compound**: SQL injection can directly expose personal data
- **Severity**: CRITICAL
- **ID format**: `COMPOUND-C003`

#### Chain 4: Missing Auth + Sensitive Endpoint
- **AUTH** finding: endpoint missing authentication
- **API** finding: the same endpoint handles sensitive operations or data
- **Compound**: Unauthenticated access to sensitive functionality
- **Severity**: CRITICAL
- **ID format**: `COMPOUND-C004`

#### Chain 5: Open Port/Config + No Auth on Internal Endpoint
- **CONFIG** finding: privileged container or exposed port
- **AUTH** finding: missing auth on internal-facing endpoint
- **Compound**: Container escape or network access leads directly to unprotected service
- **Severity**: Escalate by one level
- **ID format**: `COMPOUND-C005`

#### Chain 6: Weak Crypto + Auth Token Generation
- **CRYPTO** finding: weak algorithm or key management issue
- **AUTH** finding: the weak crypto is used for token/session generation
- **Compound**: Authentication tokens are cryptographically weak
- **Severity**: HIGH minimum
- **ID format**: `COMPOUND-C006`

#### Chain 7: Secret in Code + Missing .gitignore + Public Repo
- **SECRETS** finding: secret in code or config
- **CONFIG** finding: no `.gitignore` entry for the file type
- **Compound**: Secret is at high risk of exposure through version control
- **Severity**: Escalate to CRITICAL if any cloud/admin credential
- **ID format**: `COMPOUND-C007`

#### Chain 8: No Rate Limiting + Auth Endpoint
- **API** finding: no rate limiting
- **AUTH** finding: authentication endpoint (login, password reset)
- **Compound**: Authentication brute-force is possible
- **Severity**: HIGH
- **ID format**: `COMPOUND-C008`

#### Chain 9: Data Exposure + Information Disclosure
- **DATA** finding: PII over-exposure in API responses
- **API** finding: verbose error handling on the same endpoint
- **Compound**: Multiple information disclosure vectors on the same endpoint
- **Severity**: Keep highest of the two, escalate if both are MEDIUM → HIGH
- **ID format**: `COMPOUND-C009`

### Cross-Reference Rules

Even when findings don't form a compound chain, add cross-references between related findings:

- If two findings reference the same file, add each other's ID to a `related_findings` array
- If a DEPS vulnerability is for a package that appears in SAST imports, cross-reference them
- If CONFIG and AUTH findings affect the same service/deployment, cross-reference them

## Phase 3: Final Severity Reassessment

After deduplication and cross-correlation:

1. **Multi-agent confirmation**: If the same issue was independently identified by 2+ agents, increase confidence to HIGH (multiple independent signals)
2. **Tool + LLM confirmation**: If a tool finding was confirmed by LLM review, increase confidence to HIGH
3. **Single-source findings**: If a finding comes from only one tool with no LLM confirmation, keep original confidence but add a note
4. **Compound findings**: Severity is set per the compound patterns above (usually escalated)
5. **Context-dependent adjustment**: If the orchestrator has context that an endpoint is internal-only, or behind a VPN, note this but do not lower severity (assume worst-case deployment)

## Output

Write the consolidated findings to:
`codesoteria-output/findings/consolidated.json`

The consolidated file uses the same schema as individual agent outputs, with these additions:
- `contributing_agents`: array of agent IDs that contributed to this finding (for merged findings)
- `related_findings`: array of finding IDs that are related but not merged
- `compound_chain`: for compound findings, an array of the original finding IDs that form the chain
- `original_agent`: the primary agent that owns this finding (for non-compound findings)

Compound findings should appear at the top of the findings array (they are typically the most important).
