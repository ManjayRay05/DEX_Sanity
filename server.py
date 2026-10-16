#!/usr/bin/env python3
"""
CFD Migration Sanity — local web UI.

Serves a dashboard where you pick white labels, optionally enable live order
placement, hit Run, and watch every API result stream in live (summary cards,
per-label accordions, full request/response per endpoint).

Pure standard library. Bound to 127.0.0.1 only (never exposed to the network),
because it can trigger real order placement on live accounts.

Usage:
    python server.py                 # http://127.0.0.1:8765
    python server.py --port 9000
    python server.py --no-open       # don't auto-open the browser
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import cfd_sanity as cfd

HERE = os.path.dirname(os.path.abspath(__file__))
UI_FILE = os.path.join(HERE, "ui.html")

# Serialize runs so concurrent requests don't fight over shared state.
_run_lock = threading.Lock()

# Active operator sessions: token -> {client_id, name, ts}.
SESSIONS = {}
# Cache of per-label trading auth tokens: key -> (auth, ts).
_AUTH_CACHE = {}
_AUTH_TTL = 20 * 60  # re-login a label after 20 minutes


def _labels_meta():
    return [
        {"key": l["key"], "name": l["name"], "base": l["base"],
         "client_id": l["client_id"], "pin_required": bool(l.get("pin"))}
        for l in cfd.WHITE_LABELS
    ]


def _find_label(key=None, client_id=None):
    for l in cfd.WHITE_LABELS:
        if (key and l["key"] == key) or (client_id and l["client_id"] == client_id):
            return l
    return None


def _operator_login(client_id, password):
    """Validate operator creds against the configured white labels."""
    for l in cfd.WHITE_LABELS:
        if l["client_id"] == client_id and l["password"] == password:
            return l
    return None


def _auth_for(label):
    """Return a (cached) trading auth token for a label, logging in if needed."""
    key = label["key"]
    cached = _AUTH_CACHE.get(key)
    if cached and time.time() - cached[1] < _AUTH_TTL:
        return cached[0]
    auth, _rows = cfd.authenticate(label)
    if auth:
        _AUTH_CACHE[key] = (auth, time.time())
    return auth


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter console
        pass

    # -- helpers ------------------------------------------------------------
    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _sse_event(self, event, data):
        chunk = f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8")
        self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
        self.wfile.flush()

    # -- helpers ------------------------------------------------------------
    def _session(self):
        tok = self.headers.get("X-Session", "")
        return SESSIONS.get(tok)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
        except (ValueError, TypeError):
            return {}

    # -- GET routes ---------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        if route == "/api/labels":
            self._send(200, json.dumps({"labels": _labels_meta()}))
        elif route == "/api/run":
            self._handle_run(parse_qs(parsed.query))
        elif route == "/api/funds/recent":
            self._handle_recent(parse_qs(parsed.query))
        elif route.startswith("/api/"):
            self._send(404, json.dumps({"error": "not found"}))
        else:
            # serve the SPA for "/", "/sanity", "/funds", "/login", etc.
            try:
                with open(UI_FILE, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(500, b"ui.html not found next to server.py", "text/plain")

    # -- POST routes --------------------------------------------------------
    def do_POST(self):
        route = urlparse(self.path).path
        if route == "/api/login":
            self._handle_login()
        elif route == "/api/funds/add":
            self._handle_add_funds()
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def _handle_login(self):
        body = self._read_json()
        label = _operator_login((body.get("client_id") or "").strip(),
                                body.get("password") or "")
        if not label:
            self._send(401, json.dumps({"error": "Invalid client ID or password."}))
            return
        token = secrets.token_urlsafe(24)
        SESSIONS[token] = {"client_id": label["client_id"], "name": label["name"],
                           "ts": time.time()}
        self._send(200, json.dumps({"token": token, "operator": label["name"],
                                    "client_id": label["client_id"]}))

    def _handle_recent(self, q):
        if not self._session():
            self._send(401, json.dumps({"error": "not authenticated"})); return
        key = q.get("label", [""])[0]
        label = _find_label(key=key)
        if not label:
            self._send(404, json.dumps({"error": "unknown label"})); return
        auth = _auth_for(label)
        if not auth:
            self._send(200, json.dumps({"error": "login failed for this label", "items": []}))
            return
        res = cfd.http(label["base"],
                       f"/api/v1/pg/tx/transactions?client_id={label['client_id']}",
                       auth=auth, referer="funds")
        try:
            data = json.loads(res["raw"])
        except ValueError:
            data = {}
        self._send(200, json.dumps({"raw": data, "http": res["status"]}))

    def _handle_add_funds(self):
        if not self._session():
            self._send(401, json.dumps({"error": "not authenticated"})); return
        body = self._read_json()
        # Real deposit endpoint not configured — never move client money blindly.
        self._send(200, json.dumps({
            "ok": False,
            "error": "Deposit API not configured.",
            "detail": ("Add-funds is disabled until the real deposit endpoint is "
                       "wired in. Provide the deposit cURL to enable it."),
            "echo": {"label": body.get("label"), "amount": body.get("amount")},
        }))

    # -- streaming run ------------------------------------------------------
    def _handle_run(self, q):
        keys = [k for k in (q.get("labels", [""])[0].split(",")) if k]
        place = q.get("place_orders", ["0"])[0] in ("1", "true", "yes")
        labels = [l for l in cfd.WHITE_LABELS if not keys or l["key"] in keys]

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        with _run_lock:
            self._sse_event("start", {
                "total": len(labels),
                "labels": [l["key"] for l in labels],
                "place_orders": place,
            })
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(labels))) as ex:
                    futs = {ex.submit(cfd.run_label, l, place): l for l in labels}
                    for fut in concurrent.futures.as_completed(futs):
                        try:
                            result = fut.result()
                        except Exception as e:  # noqa: BLE001
                            lab = futs[fut]
                            result = {"key": lab["key"], "name": lab["name"],
                                      "base": lab["base"], "client_id": lab["client_id"],
                                      "authenticated": False, "rows": [], "passed": 0,
                                      "total": 0, "skipped": 0, "elapsed_ms": 0,
                                      "error": f"{type(e).__name__}: {e}"}
                        self._sse_event("label", result)
                self._sse_event("done", {"ok": True})
            except (BrokenPipeError, ConnectionResetError):
                return  # client navigated away mid-run
            # terminate chunked stream
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description="CFD Migration Sanity web UI")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true", help="don't open the browser")
    args = ap.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"CFD Migration Sanity UI  ->  {url}")
    print("Press Ctrl+C to stop.")
    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping…")
        server.shutdown()


if __name__ == "__main__":
    main()
