import tempfile
import unittest
from pathlib import Path

from app.database import Store
from app.intelligence import score_evidence
from app.service import DomainChecker, normalize_domain


def collector(_domain):
    source_details = {"dns": {"status": "ok", "records": {"a": ["192.0.2.1"], "mx": ["mx.example"], "txt": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}, "dnssec_validated": True},
                      "rdap": {"status": "ok", "created_at": "2020-01-01T00:00:00+00:00"},
                      "certificate_transparency": {"status": "ok", "certificate_count": 1}}
    evidence = {"sources": [{"name": "test", "status": "ok"}], "source_details": source_details,
                "dns": {"a": ["192.0.2.1"], "mx": ["mx.example"]}, "rdap": {}, "certificates": {"count": 1}, "tls": {"valid": None}}
    evidence["trust"] = score_evidence(evidence)
    return evidence


class BackendTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_domain("  EXAMPLE.com. "), "example.com")
        with self.assertRaises(ValueError): normalize_domain("http://localhost")

    def test_cache_and_score(self):
        with tempfile.TemporaryDirectory() as folder:
            check = DomainChecker(Store(Path(folder) / "db.sqlite"), collector)
            first, cached = check.check("example.com")
            second, cached2 = check.check("example.com")
            self.assertFalse(cached)
            self.assertTrue(cached2)
            self.assertEqual(first["trust_score"], second["trust_score"])
            self.assertGreaterEqual(first["trust_score"], 80)

    def test_brand_typosquatting_is_high_priority(self):
        evidence = collector("gmai.com")
        evidence["domain"] = "gmai.com"
        trust = score_evidence(evidence)
        codes = {item["id"] for item in trust["indicators"]}
        self.assertIn("brand_typosquatting", codes)
        self.assertLessEqual(trust["score"], 30)

    def test_actual_brand_is_not_flagged_as_a_typo(self):
        evidence = collector("gmail.com")
        evidence["domain"] = "gmail.com"
        codes = {item["id"] for item in score_evidence(evidence)["indicators"]}
        self.assertNotIn("brand_typosquatting", codes)
