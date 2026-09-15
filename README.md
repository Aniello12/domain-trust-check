# TrustCheck

> An explainable domain-trust API and minimal admin console for email-security triage.

TrustCheck enriches a domain from public, passive data sources and returns a transparent 0–100 technical trust score. It helps an analyst prioritise review; it is **not** a malware scanner, blocklist, or security verdict.

It uses no API keys, paid feeds, or third-party runtime dependencies.

## Features

- Manual domain queries in a lightweight admin dashboard.
- JSON API for integration.
- Passive DNS, RDAP, and Certificate Transparency collection.
- One-edit protected-brand lookalike detection, such as `gmai.com` → `gmail`.
- SQLite report cache and aggregate operational metrics.
- An explainable report with sources, score contributions, and timestamps.

## Quick start

Python 3.9+ is the only requirement.

```bash
git clone https://github.com/YOUR-ACCOUNT/trustcheck.git
cd trustcheck
python3 -m app.main
```

Open <http://127.0.0.1:8000>. To use another port, run `PORT=8080 python3 -m app.main`.

## API

```bash
curl -X POST http://127.0.0.1:8000/api/v1/check \
  -H 'Content-Type: application/json' \
  --data '{"domain":"example.com"}'
```

Set `"refresh": true` to bypass a fresh stored report. A response includes `trust_score`, `rating`, `checks`, `sources`, `evidence`, `cache_hit`, `checked_at`, and `expires_at`.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/health` | Service readiness |
| `GET /health` | Liveness probe |
| `POST /api/v1/check` | Domain enrichment and score |
| `GET /api/v1/metrics` | Aggregate query/cache metrics |
| `GET /` | Admin dashboard |

## Methodology

The score starts at 50. It changes only when an explicit signal is available: RDAP registration age and expiry, DNS address/mail/SPF/DMARC/DNSSEC signals, and public Certificate Transparency history. Missing data is neutral.

Brand lookalikes are high priority: a label within one edit of a curated protected brand is capped at **30/100**, even with mature infrastructure. This means *review required*, not that the registrant is necessarily malicious. See [the full methodology](docs/METHODOLOGY.md).

## Data sources and privacy

TrustCheck uses public DNS-over-HTTPS, RDAP, and Certificate Transparency records only. It does not crawl sites, open URLs, submit samples, perform HTTPS handshakes, or query commercial/restricted DNS blocklists.

SQLite stores domain names, technical evidence, scores, and aggregate query metrics. Do not submit credentials, full URLs containing tokens, email bodies, or personal data. See [privacy and operations](docs/PRIVACY_AND_OPERATIONS.md).

## Development

```bash
python3 -m unittest discover -v
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes and [SECURITY.md](SECURITY.md) for responsible vulnerability reporting.

## Project layout

```text
app/       WSGI API, collection, scoring, SQLite persistence
static/    Dependency-free admin dashboard
tests/     Unit and regression tests
docs/      Methodology, privacy, and operations documentation
```

## License

Released under the [MIT License](LICENSE).
