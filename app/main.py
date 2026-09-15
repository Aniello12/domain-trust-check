"""WSGI API server. Run: python3 -m app.main"""
import json
import os
from pathlib import Path
from wsgiref.simple_server import make_server

from .config import DATABASE_PATH
from .database import Store
from .intelligence import collect_domain_evidence
from .service import DomainChecker

store = Store(DATABASE_PATH)
checker = DomainChecker(store, collect_domain_evidence)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def response(start_response, status, body, content_type="application/json; charset=utf-8"):
    raw = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
    start_response(status, [("Content-Type", content_type), ("Content-Length", str(len(raw))),
                            ("Access-Control-Allow-Origin", "*"), ("X-Content-Type-Options", "nosniff")])
    return [raw]


def read_json(environ):
    length = int(environ.get("CONTENT_LENGTH") or 0)
    if length > 4096:
        raise ValueError("payload troppo grande")
    return json.loads(environ["wsgi.input"].read(length) or b"{}")


def application(environ, start_response):
    method, path = environ["REQUEST_METHOD"], environ.get("PATH_INFO", "/")
    if method == "OPTIONS":
        return response(start_response, "204 No Content", b"")
    if method == "GET" and path in ("/health", "/api/v1/health"):
        return response(start_response, "200 OK", {"status": "ok"})
    if method == "GET" and path == "/api/v1/metrics":
        return response(start_response, "200 OK", store.metrics())
    if method == "POST" and path == "/api/v1/check":
        try:
            payload = read_json(environ)
            report, cache_hit = checker.check(payload.get("domain"), bool(payload.get("refresh")))
            return response(start_response, "200 OK", {**report, "cache_hit": cache_hit})
        except (ValueError, json.JSONDecodeError) as exc:
            return response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            # Deliberately do not expose provider/network internals to the dashboard.
            return response(start_response, "502 Bad Gateway", {"error": "impossibile raccogliere l'intelligence del dominio"})
    if method == "GET" and path in ("/", "/index.html"):
        index = STATIC_DIR / "index.html"
        if index.exists():
            return response(start_response, "200 OK", index.read_bytes(), "text/html; charset=utf-8")
    if method == "GET" and path.startswith("/static/"):
        name = Path(path).name
        asset = STATIC_DIR / name
        content_types = {".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}
        if asset.is_file() and asset.suffix in content_types:
            return response(start_response, "200 OK", asset.read_bytes(), content_types[asset.suffix])
    return response(start_response, "404 Not Found", {"error": "not found"})


if __name__ == "__main__":
    host, port = os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "8000"))
    print(f"TrustCheck beta: http://{host}:{port}")
    make_server(host, port, application).serve_forever()
