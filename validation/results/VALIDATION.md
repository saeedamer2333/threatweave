# Validation Results

Each scenario was executed through the production engine against real scan data captured from OWASP Juice Shop and a live AWS account. Analyst suppression was disabled so the reduction figures reflect deduplication and remediation grouping only.

| Scenario | Health | Raw | Actionable | Reduction | Attack paths | Crit/High | Runtime | Result |
|---|---|---|---|---|---|---|---|---|
| Baseline (remediated) | 97/100 | 12 | 6 | 50.0% | 0 | 0/0 | 39.5s | PASS |
| Moderate risk (partially remediated) | 70/100 | 47 | 23 | 51.1% | 0 | 0/1 | 14.6s | PASS |
| Critical (unremediated) | 11/100 | 538 | 147 | 72.7% | 1 | 6/130 | 44.6s | PASS |

## Acceptance criteria

**Baseline (remediated)** — expected: Health above 80, no attack paths
- PASS: health 80-100 (actual: 97)
- PASS: clusters <= 0 (actual: 0)

**Moderate risk (partially remediated)** — expected: Health 40-79, remaining internet exposure surfaced
- PASS: health 40-79 (actual: 70)
- PASS: internet-facing findings >= 1 (actual: 1)

**Critical (unremediated)** — expected: Health below 40, at least one attack path
- PASS: health 0-39 (actual: 11)
- PASS: clusters >= 1 (actual: 1)
