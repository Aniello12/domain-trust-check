# Scoring methodology

## Purpose

TrustCheck provides a reproducible technical triage score. It ranks domains for human review; it does not decide whether a domain, message, person, or organisation is malicious.

## Baseline and signals

Every domain starts at 50. Positive signals can increase the score and risk signals decrease it. A source failure or unavailable field is neutral.

| Signal | Change | Interpretation |
| --- | ---: | --- |
| Registration under 7 / 30 / 90 days | -25 / -20 / -13 | Newly registered domains need closer review. |
| Registration under one year | -5 | Modest recency signal. |
| Registration older than one year | +7 | Historic registration only. |
| Expiry within 30 days | -8 | Weak operational-risk signal. |
| A/AAAA, MX, SPF | +4 / +4 / +5 | Public address and mail configuration. |
| DMARC monitoring / enforcement | +3 / +10 | Published email policy. |
| DNSSEC validated response | +3 | Resolver-reported validation. |
| Certificate Transparency record | +7 | Public issuance history exists. |
| One-edit protected-brand lookalike | -45 and score cap 30 | High-priority impersonation review. |

Scores are clamped to 0–100: `alto` begins at 75, `medio` at 45, and `basso` is below 45. The brand-lookalike cap overrides positive infrastructure signals because a well-configured lookalike can still support impersonation.

## Brand-lookalike rule

The detector compares the leftmost label to a small, versioned curated list. It triggers only for a one-character insertion, deletion, or substitution; exact brand domains are not flagged.

| Domain | Result |
| --- | --- |
| `gmai.com` | Lookalike of `gmail`; review required, score capped at 30. |
| `gmail.com` | Not a lookalike under this rule. |
| `example.com` | No brand-lookalike signal. |

The rule intentionally does not cover every technique. Homographs, keyboard-layout variants, compound labels, affiliate abuse, and web content need separate, tested detectors.

## Source semantics and versioning

Certificate Transparency entries show only that a certificate name was publicly logged; they do not prove active HTTPS, ownership, validity, or safety. RDAP data can be redacted and DNS can vary by resolver.

Responses contain `methodology_version`. Cache entries from an older version are not reused after a scoring update.
