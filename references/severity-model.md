# Severity Model

Use this model to rate all findings consistently across agents.

## Severity Levels

| Level | Criteria | Examples |
|-------|----------|---------|
| **CRITICAL** | Exploitable remotely with no or trivial preconditions. Leads to full system compromise, data breach, or remote code execution. | RCE via deserialization, SQL injection on unauthenticated endpoint, hardcoded admin credentials in production, leaked AWS root key with full access |
| **HIGH** | Exploitable with some preconditions (authenticated attacker, specific configuration). Significant impact if exploited. | Stored XSS in authenticated area, IDOR on sensitive resources (medical records, financial data), vulnerable dependency with known public exploit, privilege escalation from user to admin |
| **MEDIUM** | Limited exploitability or moderate impact. Requires chaining with other issues or specific user interaction. | Reflected XSS, missing rate limiting on login, CSRF on non-critical state changes, overly verbose error messages revealing stack traces, missing security headers |
| **LOW** | Informational or best-practice violations. Minimal direct security impact. Defense-in-depth improvements. | Missing X-Frame-Options header, outdated dependency with no known exploitable CVE, weak hash for non-security purpose (e.g., cache key), debug comments in code |

## Confidence Levels

| Level | Criteria |
|-------|----------|
| **HIGH** | Confirmed by external tool AND validated by code review, OR the pattern is unambiguous (e.g., `eval(user_input)`, hardcoded `password = "admin123"`). No reasonable false-positive interpretation. |
| **MEDIUM** | Flagged by external tool OR identified by LLM review, with supporting evidence. The pattern is likely a real issue but context could change the assessment. |
| **LOW** | Heuristic match or pattern-based suspicion. The code looks concerning but may be intentional, mitigated elsewhere, or unreachable. Requires manual verification. |

## Priority Assignment Matrix

Priority determines remediation urgency. Derived from severity x confidence:

| | Confidence HIGH | Confidence MEDIUM | Confidence LOW |
|---|---|---|---|
| **CRITICAL** | **P0** — Fix immediately | **P0** — Fix immediately | **P1** — Fix within 1 week |
| **HIGH** | **P1** — Fix within 1 week | **P1** — Fix within 1 week | **P2** — Fix within 30 days |
| **MEDIUM** | **P2** — Fix within 30 days | **P2** — Fix within 30 days | **P3** — Backlog |
| **LOW** | **P3** — Backlog | **P3** — Backlog | **P3** — Backlog |

## False-Positive Filtering (Balanced Mode)

Apply balanced filtering to every finding:

1. **Obvious false positives** — Suppress entirely. Do not include in output.
   - Test fixtures with dummy credentials (e.g., `password = "test123"` in `test_auth.py`)
   - Example/placeholder values in documentation or comments
   - Hashed or encrypted values flagged as "secrets"
   - Dead code behind feature flags that are permanently off

2. **Likely real issues** — Include with `false_positive_risk: "LOW"`.
   - Tool flagged it AND code review confirms the pattern
   - No mitigating controls visible in surrounding code

3. **Uncertain cases** — Include with `false_positive_risk: "MEDIUM"` and explain reasoning.
   - Tool flagged it but context is ambiguous
   - Pattern looks risky but may be mitigated by framework defaults
   - Input appears to come from a trusted internal source (but verify)

4. **Suspicious but likely benign** — Include with `false_positive_risk: "HIGH"`.
   - Pattern matches a vulnerability class but the specific usage appears safe
   - Framework is known to handle this automatically (e.g., Django ORM prevents SQL injection)
   - Include these so the user can make the final call

Always explain your false-positive reasoning in the `false_positive_reasoning` field.

## Severity Escalation

Some conditions warrant escalating severity beyond the base assessment:

- **Publicly accessible**: If the vulnerable endpoint/code is reachable without authentication, escalate by one level
- **PII involved**: If the vulnerability exposes personally identifiable information, escalate by one level
- **Chained exploit**: If this finding combines with another finding to create a more severe attack, note both findings and assess the chain's severity independently
- **No compensating controls**: If there are no mitigating factors (WAF, rate limiter, input validation elsewhere), keep severity as-is. If controls exist, consider lowering by one level.

Do NOT escalate above CRITICAL.
