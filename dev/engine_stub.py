#!/usr/bin/env python3
"""Stand-in for the CYBROT OSINT engine, for testing the browser extension.

It implements the endpoints the extension expects (see README.md).
It does NOT scan anything: results are made-up sample data, and a scan just
takes about 12 seconds. Domains starting with "fail." end in an ENGINE_TIMEOUT
error, so the failed view can be tested.

Run:  python3 dev/engine_stub.py      (listens on http://127.0.0.1:8000)
"""
import json
import re
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST, PORT = "127.0.0.1", 8000
RUN_SECONDS = 12.0
MODULE_ORDER = ["dns", "whois", "subdomains", "ssl"]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
SCANS = {}


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def sample_results(domain):
    """Made-up sample data in the shape the extension reads."""
    return {
        "domain_details": {
            "registrar": "Sample Registrar, Inc.",
            "created": "1995-08-14",
            "expires": "2027-08-13",
            "name_servers": ["ns1.example.net", "ns2.example.net"],
        },
        "dns": [
            {"type": "A", "value": "192.0.2.10", "ttl": 300},
            {"type": "AAAA", "value": "2001:db8::10", "ttl": 300},
            {"type": "MX", "value": f"10 mail.{domain}", "ttl": 3600},
            {"type": "TXT", "value": "v=spf1 -all", "ttl": 3600},
        ],
        "subdomains": [f"{label}.{domain}" for label in ["www", "mail", "api", "cdn", "staging", "dev"]],
        "ssl": {
            "issuer": "Sample CA R3",
            "valid_until": "2027-02-03T00:00:00+00:00",
            "protocol": "TLS 1.3",
            "grade": "A",
        },
    }


def module_count(name, results):
    return {
        "dns": len(results["dns"]),
        "whois": 1,
        "subdomains": len(results["subdomains"]),
        "ssl": 1,
    }[name]


def scan_view(scan):
    """Advance the fake scan clock and build the status payload."""
    now = time.time()
    if scan["status"] == "running":
        elapsed = now - scan["started"]
        if scan["fail"] and elapsed >= RUN_SECONDS / 2:
            scan.update(status="failed", finished=now,
                        error={"code": "ENGINE_TIMEOUT", "message": "A module did not respond in time."})
        elif elapsed >= RUN_SECONDS:
            scan.update(status="completed", finished=now)

    elapsed = (scan["finished"] or now) - scan["started"]
    step = RUN_SECONDS / len(MODULE_ORDER)
    modules = {}
    for i, name in enumerate(MODULE_ORDER):
        if name not in scan["modules"]:
            continue
        if scan["status"] == "completed" or elapsed >= (i + 1) * step:
            status = "done"
        elif elapsed >= i * step:
            status = "running"
        else:
            status = "queued"
        if scan["status"] in ("failed", "cancelled") and status != "done":
            status = "skipped"
        info = {"status": status}
        if status == "done":
            info["count"] = module_count(name, scan["results"])
        elif status == "running":
            info["count"] = module_count(name, scan["results"]) // 2
        modules[name] = info

    progress = 100 if scan["status"] == "completed" else min(99, round(100 * elapsed / RUN_SECONDS))
    view = {
        "scan_id": scan["id"],
        "domain": scan["domain"],
        "status": scan["status"],
        "progress": progress,
        "modules": modules,
        "error": scan["error"],
    }
    if scan["status"] == "completed":
        view["results"] = scan["results"]
        view["finished_at"] = iso(scan["finished"])
        view["duration_seconds"] = round(scan["finished"] - scan["started"], 1)
    return view


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload=None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, error_code, message):
        self._send(code, {"error": {"code": error_code, "message": message}})

    def do_OPTIONS(self):
        self._send(204)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._send(200, {"status": "ok", "engine": "stub", "version": "0.1.0"})
        match = re.fullmatch(r"/api/scans/([A-Za-z0-9]+)", path)
        if match and match.group(1) in SCANS:
            return self._send(200, scan_view(SCANS[match.group(1)]))
        if match:
            return self._error(404, "NOT_FOUND", "Scan not found.")
        self._error(404, "NOT_FOUND", "Unknown endpoint.")

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            return self._error(400, "BAD_JSON", "Request body is not valid JSON.")
        if not isinstance(data, dict):
            return self._error(400, "BAD_JSON", "Request body must be a JSON object.")

        if path == "/api/scans":
            domain = str(data.get("domain", "")).strip().lower()
            if not DOMAIN_RE.match(domain):
                return self._error(400, "INVALID_DOMAIN", f"'{domain}' is not a domain name.")
            modules = [m for m in data.get("modules", MODULE_ORDER) if m in MODULE_ORDER]
            if not modules:
                return self._error(400, "NO_MODULES", "Choose at least one module.")
            scan_id = uuid.uuid4().hex[:12]
            SCANS[scan_id] = {
                "id": scan_id,
                "domain": domain,
                "modules": modules,
                "status": "running",
                "started": time.time(),
                "finished": None,
                "error": None,
                "fail": domain.startswith("fail."),
                "results": sample_results(domain),
            }
            return self._send(202, {"scan_id": scan_id})

        match = re.fullmatch(r"/api/scans/([A-Za-z0-9]+)/cancel", path)
        if match and match.group(1) in SCANS:
            scan = SCANS[match.group(1)]
            if scan["status"] == "running":
                scan.update(status="cancelled", finished=time.time())
            return self._send(200, {"scan_id": scan["id"], "status": scan["status"]})

        self._error(404, "NOT_FOUND", "Unknown endpoint.")

    def log_message(self, format, *args):
        pass  # keep the console quiet


if __name__ == "__main__":
    print(f"CYBROT engine stub on http://{HOST}:{PORT} (sample data only)")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
