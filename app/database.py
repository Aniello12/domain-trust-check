"""Small SQLite store: no customer data or credentials are persisted."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS domain_reports (
                  domain TEXT PRIMARY KEY,
                  checked_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  score INTEGER NOT NULL,
                  rating TEXT NOT NULL,
                  report_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS query_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  domain TEXT NOT NULL,
                  occurred_at TEXT NOT NULL,
                  cache_hit INTEGER NOT NULL,
                  score INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_query_events_time ON query_events(occurred_at);
            """)

    def get_fresh(self, domain: str, now: str):
        with self._connect() as conn:
            row = conn.execute("SELECT report_json FROM domain_reports WHERE domain=? AND expires_at>?", (domain, now)).fetchone()
        return json.loads(row["report_json"]) if row else None

    def save_report(self, report: dict):
        with self._connect() as conn:
            conn.execute("""INSERT INTO domain_reports(domain, checked_at, expires_at, score, rating, report_json)
              VALUES(?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET
              checked_at=excluded.checked_at, expires_at=excluded.expires_at, score=excluded.score,
              rating=excluded.rating, report_json=excluded.report_json""",
              (report["domain"], report["checked_at"], report["expires_at"], report["trust_score"], report["rating"], json.dumps(report)))

    def record_query(self, domain: str, cache_hit: bool, score: int):
        with self._connect() as conn:
            conn.execute("INSERT INTO query_events(domain, occurred_at, cache_hit, score) VALUES(?,?,?,?)",
                         (domain, utcnow(), int(cache_hit), score))

    def metrics(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM query_events").fetchone()["c"]
            cache = conn.execute("SELECT COUNT(*) c FROM query_events WHERE cache_hit=1").fetchone()["c"]
            domains = conn.execute("SELECT COUNT(*) c FROM domain_reports").fetchone()["c"]
            avg = conn.execute("SELECT AVG(score) score FROM query_events").fetchone()["score"]
            recent = [dict(r) for r in conn.execute("SELECT domain, occurred_at, cache_hit, score FROM query_events ORDER BY id DESC LIMIT 20")]
        return {"total_queries": total, "cached_queries": cache, "cache_hit_rate": round(cache / total, 3) if total else 0,
                "unique_domains": domains, "average_score": round(avg, 1) if avg is not None else None, "recent_queries": recent}
