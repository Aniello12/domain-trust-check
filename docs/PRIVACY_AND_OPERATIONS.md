# Privacy and operations

## Data handling

TrustCheck is built for domain names and public technical metadata. Its SQLite database stores cached reports and aggregate query events. It does not need email content, credentials, API keys, or user identities.

Do not submit credentials, message bodies, full URLs containing tokens, or personal data. For shared use, put the service behind your organisation's authentication and retention controls.

## External requests

Each uncached lookup makes bounded, read-only calls to public DNS, RDAP, and Certificate Transparency services. Short timeouts, source rate limits, and caches minimise load. A source outage is returned as unavailable rather than failing the entire report.

No commercial DNSBL is queried because many have licensing, attribution, or volume restrictions.

## Shared deployment

The built-in WSGI server is for local use and the beta. For a shared deployment:

1. Run a maintained reverse proxy and production WSGI server.
2. Require authentication and limit network access.
3. Terminate TLS at the reverse proxy.
4. Protect persistent storage and define retention/backups.
5. Monitor source availability, request volume, and methodology changes.

## False positives and incidents

Use a score as a review aid, never as an automatic block. When a false positive or false negative is found, add a minimal regression test, document the rationale, increment the methodology version, and invalidate stale cached reports.
