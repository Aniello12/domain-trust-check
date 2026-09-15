"""Low-cost, passive domain intelligence.

The collector uses only public protocols/endpoints: DNS-over-HTTPS, RDAP and the
public certificate-transparency JSON feed.  It deliberately does not probe the
target, crawl a web site, submit samples, or query commercial DNSBL zones.

This module has no third-party dependencies and is safe to call from the API.
Results are cached in-process; the API may additionally persist the returned
document in SQLite for cache sharing across restarts.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


USER_AGENT = "DomainTrustBeta/0.1 (passive-domain-enrichment)"
DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query?name={name}&type={record_type}"
RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"
CT_ENDPOINT = "https://crt.sh/?q=%25.{domain}&output=json"

# The values are intentionally conservative.  Missing public records are not
# treated as proof of maliciousness: small/parked domains often have none.
METHODOLOGY_VERSION = "2026-09-passive-v2"
_CACHE_TTL = {"dns": 15 * 60, "rdap": 12 * 60 * 60, "certificate_transparency": 6 * 60 * 60}
_MIN_SOURCE_INTERVAL = {"dns": 0.15, "rdap": 0.5, "certificate_transparency": 1.0}
_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_last_source_request: dict[str, float] = {}
_lock = threading.RLock()

# This intentionally small, curated set catches the most common impersonation
# targets without pretending that a lexical resemblance is a malware verdict.
# A match means "needs review", not that the registrant is malicious.  Keep
# this list under change control; it is a local rule, not external threat intel.
PROTECTED_BRAND_LABELS = frozenset({
    "gmail", "google", "microsoft", "office", "outlook", "paypal", "apple",
    "amazon", "docusign", "dropbox", "linkedin", "facebook", "instagram",
    "whatsapp", "telegram", "okta",
})


def normalize_domain(value: str) -> str:
    """Return a canonical hostname or raise ValueError.

    Only registrable-looking DNS names are accepted.  This prevents the
    collector from being used as a general HTTP fetcher or SSRF primitive.
    """
    if not isinstance(value, str):
        raise ValueError("domain must be a string")
    domain = value.strip().rstrip(".").lower()
    if "://" in domain or "/" in domain or "@" in domain:
        raise ValueError("submit a domain name, not a URL or email address")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain") from exc
    if len(domain) > 253 or "." not in domain:
        raise ValueError("domain must include a public suffix")
    labels = domain.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise ValueError("invalid domain label")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("IP addresses are not accepted")


def _get_json(url: str, accept: str = "application/json", max_bytes: int = 1_000_000) -> Any:
    request = Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=8) as response:  # nosec B310: URLs are fixed constants
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError("source response exceeded size limit")
            return json.loads(raw.decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(str(exc)) from exc


def _cached(source: str, domain: str, loader) -> dict[str, Any]:
    key = (source, domain)
    now = time.monotonic()
    with _lock:
        saved = _cache.get(key)
        if saved and now - saved[0] < _CACHE_TTL[source]:
            return {**saved[1], "cache": "hit"}
        # A small, cooperative in-process rate limit protects public services.
        delay = _MIN_SOURCE_INTERVAL[source] - (now - _last_source_request.get(source, 0))
    if delay > 0:
        time.sleep(delay)
    try:
        payload = loader()
        result = {"status": "ok", "retrieved_at": _iso_now(), "cache": "miss", **payload}
    except Exception as exc:  # Individual source outages must not fail a query.
        result = {"status": "unavailable", "retrieved_at": _iso_now(), "cache": "miss", "error": str(exc)[:180]}
    with _lock:
        _last_source_request[source] = time.monotonic()
        _cache[key] = (time.monotonic(), result)
    return result


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _dns(domain: str) -> dict[str, Any]:
    def lookup(name: str, record_type: str) -> tuple[list[str], bool]:
        response = _get_json(DNS_ENDPOINT.format(name=quote(name, safe="."), record_type=record_type), "application/dns-json", 250_000)
        answers = response.get("Answer", []) if isinstance(response, dict) else []
        return ([str(a.get("data", "")) for a in answers if isinstance(a, dict) and a.get("data")], bool(response.get("AD")))

    a, ad_a = lookup(domain, "A")
    aaaa, ad_aaaa = lookup(domain, "AAAA")
    mx, ad_mx = lookup(domain, "MX")
    txt, ad_txt = lookup(domain, "TXT")
    dmarc, ad_dmarc = lookup("_dmarc." + domain, "TXT")
    caa, ad_caa = lookup(domain, "CAA")
    return {
        "records": {"a": a[:20], "aaaa": aaaa[:20], "mx": mx[:20], "txt": txt[:30], "dmarc": dmarc[:10], "caa": caa[:20]},
        "dnssec_validated": any((ad_a, ad_aaaa, ad_mx, ad_txt, ad_dmarc, ad_caa)),
    }


def _event_date(events: Any, action: str) -> str | None:
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == action and isinstance(event.get("eventDate"), str):
            return event["eventDate"]
    return None


def _rdap(domain: str) -> dict[str, Any]:
    data = _get_json(RDAP_ENDPOINT.format(domain=quote(domain, safe=".")))
    if not isinstance(data, dict):
        raise ValueError("unexpected RDAP response")
    entities = data.get("entities", [])
    registrar = None
    if isinstance(entities, list):
        for entity in entities:
            if isinstance(entity, dict) and "registrar" in entity.get("roles", []):
                registrar = entity.get("handle")
                break
    nameservers = [n.get("ldhName") for n in data.get("nameservers", []) if isinstance(n, dict) and n.get("ldhName")]
    return {
        "created_at": _event_date(data.get("events"), "registration"),
        "expires_at": _event_date(data.get("events"), "expiration"),
        "last_changed_at": _event_date(data.get("events"), "last changed"),
        "registrar_handle": registrar,
        "nameservers": nameservers[:20],
    }


def _certificate_transparency(domain: str) -> dict[str, Any]:
    rows = _get_json(CT_ENDPOINT.format(domain=quote(domain, safe=".")), max_bytes=2_000_000)
    if not isinstance(rows, list):
        raise ValueError("unexpected CT response")
    matched: list[dict[str, Any]] = []
    suffix = "." + domain
    for row in rows[:5000]:
        if not isinstance(row, dict):
            continue
        names = str(row.get("name_value", "")).lower().splitlines()
        if any(name.lstrip("*.") == domain or name.lstrip("*.").endswith(suffix) for name in names):
            matched.append(row)
    issuers = {str(r.get("issuer_name")) for r in matched if r.get("issuer_name")}
    before = [str(r["not_before"]) for r in matched if r.get("not_before")]
    after = [str(r["not_after"]) for r in matched if r.get("not_after")]
    return {
        # crt.sh returns issuance rows; renewals/duplicate log entries mean this
        # is deliberately *not* advertised as a count of unique certificates.
        "certificate_count": len(matched),
        "count_kind": "matching_certificate_transparency_records",
        "earliest_not_before": min(before) if before else None,
        "latest_not_after": max(after) if after else None,
        "issuer_count": len(issuers),
    }


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    """Return whether two ASCII labels differ by one edit or less.

    We only need a bounded comparison here.  It avoids a dependency and makes
    the rule deterministic for a high-priority security signal.
    """
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) <= 1
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    index = mismatch = 0
    while index < len(shorter):
        if shorter[index] != longer[index + mismatch]:
            mismatch += 1
            if mismatch > 1:
                return False
            continue
        index += 1
    return True


def _lookalike_brand(domain: str) -> str | None:
    """Return a protected label a domain's registrable-looking label mimics."""
    label = domain.split(".", 1)[0]
    for brand in PROTECTED_BRAND_LABELS:
        # Exact brand labels are legitimate reference domains, not a typo.
        if label != brand and _edit_distance_at_most_one(label, brand):
            return brand
    return None


def score_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Calculate explainable trust from passive signals; this is not a verdict."""
    score = 50
    indicators: list[dict[str, Any]] = []

    def add(code: str, points: int, rationale: str) -> None:
        nonlocal score
        score += points
        indicators.append({"id": code, "weight": points, "rationale": rationale})

    now = datetime.now(timezone.utc)
    brand = _lookalike_brand(str(evidence.get("domain", "")))
    if brand:
        add("brand_typosquatting", -45,
            f"Domain label is within one edit of protected brand '{brand}'; manual review required")
    rdap = evidence.get("source_details", {}).get("rdap", evidence.get("rdap", {}))
    created = _parse_time(rdap.get("created_at")) if rdap.get("status") == "ok" else None
    if created:
        days = max(0, (now - created).days)
        if days < 7: add("domain_very_new", -25, "Domain registered less than 7 days ago")
        elif days < 30: add("domain_new", -20, "Domain registered less than 30 days ago")
        elif days < 90: add("domain_recent", -13, "Domain registered less than 90 days ago")
        elif days < 365: add("domain_under_one_year", -5, "Domain registered less than one year ago")
        else: add("domain_established", 7, "Domain has more than one year of registration history")
    expires = _parse_time(rdap.get("expires_at")) if rdap.get("status") == "ok" else None
    if expires and 0 <= (expires - now).days < 30:
        add("registration_expiring", -8, "Registration expires within 30 days")

    dns = evidence.get("source_details", {}).get("dns", evidence.get("dns", {}))
    records = dns.get("records", {}) if dns.get("status") == "ok" else {}
    txt = " ".join(records.get("txt", [])).lower()
    dmarc = " ".join(records.get("dmarc", [])).lower()
    if records.get("a") or records.get("aaaa"): add("address_records", 4, "Domain publishes address records")
    if records.get("mx"): add("mx_records", 4, "Domain publishes mail exchanger records")
    if "v=spf1" in txt: add("spf", 5, "SPF policy is published")
    if "v=dmarc1" in dmarc:
        add("dmarc_enforced" if "p=reject" in dmarc or "p=quarantine" in dmarc else "dmarc_monitoring", 10 if "p=reject" in dmarc or "p=quarantine" in dmarc else 3, "DMARC policy is published")
    if dns.get("dnssec_validated"): add("dnssec", 3, "DNS response was DNSSEC validated by resolver")

    ct = evidence.get("source_details", {}).get("certificate_transparency", evidence.get("certificates", {}))
    if ct.get("status") == "ok" and ct.get("certificate_count", 0):
        add("certificate_transparency", 7, "At least one public certificate-transparency entry matches")
    # Strong operational controls on a lookalike domain do not make it a safe
    # sender identity. Keep it in the high-risk band until a human reviews it.
    if brand:
        score = min(score, 30)
    score = max(0, min(100, score))
    return {"score": score, "level": "high" if score >= 75 else "medium" if score >= 45 else "low", "methodology_version": METHODOLOGY_VERSION, "indicators": indicators, "disclaimer": "Passive evidence only; a brand-lookalike signal requires human review and is not, by itself, an attribution of maliciousness."}


def collect_domain_evidence(domain: str) -> dict[str, Any]:
    """Collect normalized passive evidence and an explainable 0-100 trust score."""
    domain = normalize_domain(domain)
    source_details = {
        "dns": _cached("dns", domain, lambda: _dns(domain)),
        "rdap": _cached("rdap", domain, lambda: _rdap(domain)),
        "certificate_transparency": _cached("certificate_transparency", domain, lambda: _certificate_transparency(domain)),
    }
    dns_records = source_details["dns"].get("records", {})
    rdap = source_details["rdap"]
    certificates = source_details["certificate_transparency"]
    # Flat aliases retain a stable, simple API contract for the dashboard and
    # scoring service.  `source_details` preserves raw normalized provenance.
    evidence = {
        "domain": domain,
        "collected_at": _iso_now(),
        "sources": [
            {"name": "Curated protected-brand similarity rules", "status": "ok"},
            {"name": "DNS over HTTPS (Cloudflare)", "status": source_details["dns"]["status"]},
            {"name": "RDAP public registry gateway", "status": rdap["status"]},
            {"name": "Certificate Transparency public feed", "status": certificates["status"]},
        ],
        "source_details": source_details,
        "dns": {**dns_records, "dnssec": source_details["dns"].get("dnssec_validated")},
        "rdap": {**rdap, "registrar": rdap.get("registrar_handle")},
        "certificates": {**certificates, "count": certificates.get("certificate_count")},
        # CT records prove public issuance history only.  They must never be
        # presented as a live HTTPS reachability or certificate validation test.
        "tls": {"valid": None, "issuer": "Non verificato: raccolta solo passiva"},
    }
    evidence["trust"] = score_evidence(evidence)
    evidence["collection_policy"] = {"passive_only": True, "dnsbl_queries": "not performed: public DNSBLs may require a licensed resolver", "cache_ttl_seconds": _CACHE_TTL}
    return evidence
