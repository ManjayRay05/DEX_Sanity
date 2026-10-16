#!/usr/bin/env python3
"""
CFD Migration Sanity — multi white-label API health check.

Logs into each configured white label (handling the optional 2FA PIN step),
then calls a battery of read-only APIs one by one and publishes a single
self-contained HTML report (report.html) with pass/fail per endpoint.

Pure standard library — no pip install required.

Usage:
    python cfd_sanity.py                # run all labels -> report.html
    python cfd_sanity.py --out foo.html # custom output path
    python cfd_sanity.py --only marketbhai,trade246
    python cfd_sanity.py --open         # open the report when done

Safety: this script is READ-ONLY. It never places, modifies or cancels
orders, and it never writes credentials or auth tokens to the report/logs.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import html
import json
import ssl
import time
import urllib.error
import urllib.request
import webbrowser

import ws_client

# ----------------------------------------------------------------------------
# White-label configuration. pin=None means 2FA/PIN is not required.
# ----------------------------------------------------------------------------
WHITE_LABELS = [
    {"key": "marketbhai", "name": "MarketBhai",  "base": "https://web.marketbhai.one", "client_id": "A06064",  "password": "Live@7890",  "pin": "123456"},
    {"key": "tradex55",   "name": "TradeX55",    "base": "https://web.tradex55.live",  "client_id": "C48874",  "password": "Asdf@12345", "pin": "123456"},
    {"key": "stockkida",  "name": "StockKida",   "base": "https://web.stockkida.com",  "client_id": "R35773",  "password": "Live@7890",  "pin": None},
    {"key": "bullmint",   "name": "BullMint",    "base": "https://web.bullmint.app",   "client_id": "B156429", "password": "Asdf@1234",  "pin": None},
    {"key": "trade246",   "name": "Trade246",    "base": "https://web.trade246.live",  "client_id": "D111061", "password": "Dummy@246",  "pin": "123456"},
    {"key": "5trade",     "name": "5Trade",      "base": "https://web.5trade.live",    "client_id": "A05969",  "password": "Zxcv@1234",  "pin": "123456"},
    {"key": "7ocean",     "name": "7Ocean",      "base": "https://web.7ocean.site",    "client_id": "B53504",  "password": "Asdf@1234",  "pin": None},
    {"key": "forvonex",   "name": "Forvonex",    "base": "https://web.forvonex.com",   "client_id": "B112553", "password": "Live@7890",  "pin": None},
    {"key": "mytrade24",  "name": "MyTrade24",   "base": "https://web.mytrade24.in",   "client_id": "T206657", "password": "Asdf@1234",  "pin": "123456"},
    {"key": "nivesh",     "name": "Nivesh",      "base": "https://web.nivesh.pro",     "client_id": "B105001", "password": "Asdf@1234",  "pin": None},
]

# Exchange -> representative instrument token (reference only; from read.md).
EXCHANGE_TOKENS = {"NSE": "3045", "NFO": "68391", "CDS": "30", "DCSX": "2102", "MCX": "569900"}

# ---------------------------------------------------------------------------
# Order-placement tests. These place REAL MARKET orders on live accounts.
#
# Instrument tokens are SHARED across all white labels (verified: they use a
# common instrument master), so the same specs apply to every label. Each spec
# is placed once per side (BUY and SELL) — same API, only order_side differs.
# device_id mirrors the browser's x-device-id header for the /orders endpoint.
# ---------------------------------------------------------------------------
ORDER_DEVICE_ID = "bu4hot"

ORDER_SPECS = [
    {"name": "NFO NRML",     "exchange": "NFO",  "instrument_token": "48704",  "product": "NRML", "quantity": 1, "order_type": "MARKET"},
    {"name": "NFO Intraday", "exchange": "NFO",  "instrument_token": "68782",  "product": "MIS",  "quantity": 1, "order_type": "MARKET"},
    {"name": "NSE CNC",      "exchange": "NSE",  "instrument_token": "3045",   "product": "CNC",  "quantity": 1, "order_type": "MARKET"},
    {"name": "NSE MIS",      "exchange": "NSE",  "instrument_token": "3045",   "product": "MIS",  "quantity": 1, "order_type": "MARKET"},
    {"name": "MCX NRML",     "exchange": "MCX",  "instrument_token": "569900", "product": "NRML", "quantity": 1, "order_type": "MARKET"},
    {"name": "MCX MIS",      "exchange": "MCX",  "instrument_token": "569900", "product": "MIS",  "quantity": 1, "order_type": "MARKET"},
    {"name": "CDS NRML",     "exchange": "CDS",  "instrument_token": "7",      "product": "NRML", "quantity": 1, "order_type": "MARKET"},
    {"name": "DCSX CNC",     "exchange": "DCSX", "instrument_token": "2102",   "product": "CNC",  "quantity": 1, "order_type": "MARKET"},
]

# Per-label overrides (e.g. a different device_id or extra/omitted specs).
# Empty by default: every label uses the shared ORDER_SPECS above.
ORDER_TESTS = {}

# Each order spec is placed once per side (BUY and SELL) — same API, order_side differs.
ORDER_SIDES = ["BUY", "SELL"]

# Toggled on by --place-orders. When False (default) no orders are ever sent.
PLACE_ORDERS = False

# Representative market-search keys to exercise the search API per category.
SEARCH_KEYS = ["NIFTY", "BANKNIFTY", "SENSEX", "CRUDEOIL", "GOLD", "RELIANCE", "HDFCBANK"]

TIMEOUT = 25
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE

# Keys whose values are secrets and must never appear in the report.
REDACT_KEYS = {"channel_secret", "password", "pin", "answer", "answers",
               "twofa_token", "auth_token", "reference_token"}
REDACT_HEADERS = {"x-authorization-token", "cookie"}
MAX_BODY_CHARS = 8000  # truncate very large response bodies in the report


def _redact(obj):
    """Recursively replace sensitive values in a parsed JSON structure."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in REDACT_KEYS:
                out[k] = "***redacted***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


def _pretty(raw):
    """Pretty-print + redact a raw JSON response; fall back to truncated text."""
    if not raw:
        return ""
    try:
        text = json.dumps(_redact(json.loads(raw)), indent=2, ensure_ascii=False)
    except ValueError:
        text = raw
    if len(text) > MAX_BODY_CHARS:
        text = text[:MAX_BODY_CHARS] + f"\n… (truncated, {len(text)} chars total)"
    return text


# ----------------------------------------------------------------------------
# HTTP helper
# ----------------------------------------------------------------------------
def http(base, path, method="GET", body=None, auth=None, referer="dashboard",
         retries=1, device_id=None):
    """Return dict: status(int|None), api_status, message, ok(bool), ms, raw, error.

    Retries once on transport-level failures (timeout/DNS/reset) so a single
    slow response on a sluggish backend does not produce a spurious FAIL.
    Orders are never retried (see place_order) to avoid duplicate fills.
    """
    res = _http_once(base, path, method, body, auth, referer, device_id)
    attempt = 0
    while res["error"] is not None and attempt < retries:
        attempt += 1
        res = _http_once(base, path, method, body, auth, referer, device_id)
    return res


def _http_once(base, path, method="GET", body=None, auth=None, referer="dashboard", device_id=None):
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        "origin": base,
        "priority": "u=1, i",
        "referer": f"{base}/{referer}",
        "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": UA,
        "x-device-type": "web",
    }
    if auth:
        headers["x-authorization-token"] = auth
    if device_id:
        headers["x-device-id"] = device_id
    data = json.dumps(body).encode() if body is not None else None

    # Sanitized snapshot of the request for the report.
    disp_headers = {k: ("***redacted***" if k.lower() in REDACT_HEADERS else v)
                    for k, v in headers.items()}
    req_body = json.dumps(_redact(body), indent=2, ensure_ascii=False) if body is not None else ""
    req_snapshot = {"method": method, "url": base + path,
                    "headers": disp_headers, "body": req_body}

    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_SSL) as r:
            raw = r.read().decode("utf-8", "replace")
            code = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        code = e.code
    except Exception as e:  # noqa: BLE001 - network/timeout/DNS all surfaced in report
        return {"status": None, "api_status": None, "message": str(e),
                "ok": False, "ms": int((time.perf_counter() - t0) * 1000),
                "raw": "", "error": type(e).__name__,
                "req": req_snapshot, "resp": ""}
    ms = int((time.perf_counter() - t0) * 1000)
    api_status, message = None, ""
    try:
        j = json.loads(raw)
        if isinstance(j, dict):
            api_status = j.get("status")
            message = j.get("message") or ""
    except ValueError:
        pass
    ok = (code == 200) and (api_status != "error")
    return {"status": code, "api_status": api_status, "message": message,
            "ok": ok, "ms": ms, "raw": raw, "error": None,
            "req": req_snapshot, "resp": _pretty(raw)}


# ----------------------------------------------------------------------------
# Authentication (login -> optional PIN)
# ----------------------------------------------------------------------------
def authenticate(label):
    """Return (auth_token|None, list-of-check-rows) for the login flow."""
    base, cid = label["base"], label["client_id"]
    rows = []

    login = http(base, "/api/v4/user/login", method="POST", referer="login",
                 body={"channel_id": cid, "channel_secret": label["password"]})
    d = {}
    try:
        d = json.loads(login["raw"]).get("data", {}) or {}
    except ValueError:
        pass
    rows.append(_row("Login", "POST", "/api/v4/user/login", login,
                     note=("2FA required" if d.get("twofa_enabled") else "no 2FA")))
    if not login["ok"]:
        return None, rows

    # Direct token (no 2FA)?
    auth = d.get("auth_token")
    if auth:
        return auth, rows

    tf = d.get("twofa") or {}
    twofa_token = tf.get("twofa_token")
    questions = tf.get("questions") or []
    if not twofa_token or not questions:
        rows.append(_synth("PIN verify", "POST", "/api/v4/user/twofa", False,
                           "login returned no auth token and no 2FA challenge"))
        return None, rows
    if not label.get("pin"):
        rows.append(_synth("PIN verify", "POST", "/api/v4/user/twofa", False,
                           "2FA required but no PIN configured for this label"))
        return None, rows

    answers = [{"question_id": q["question_id"], "answer": label["pin"]} for q in questions]
    verify = http(base, "/api/v4/user/twofa", method="POST", referer="login",
                  body={"login_id": cid, "twofa_token": twofa_token,
                        "type": tf.get("type", "PIN"), "twofa": answers})
    rows.append(_row("PIN verify", "POST", "/api/v4/user/twofa", verify))
    if not verify["ok"]:
        return None, rows
    try:
        auth = json.loads(verify["raw"]).get("data", {}).get("auth_token")
    except ValueError:
        auth = None
    if not auth:
        rows.append(_synth("Auth token", "-", "-", False, "PIN accepted but no auth_token returned"))
    return auth, rows


# ----------------------------------------------------------------------------
# Read-only endpoint battery
# ----------------------------------------------------------------------------
def endpoint_battery(cid):
    """(section, name, method, path, referer) tuples — all read-only GETs."""
    today = dt.date.today().isoformat()
    week_ago = (dt.date.today() - dt.timedelta(days=7)).isoformat()
    b = [
        ("Account", "Profile",            "GET", f"/api/v1/user/profile?client_id={cid}", "dashboard"),
        ("Account", "Margins",            "GET", f"/api/v1/user/funds/margins?client_id={cid}", "portfolio"),

        ("Orders",  "Orders (pending)",   "GET", f"/api/v1/orders?type=pending&client_id={cid}", "orders"),
        ("Orders",  "Orders (completed)", "GET", f"/api/v1/orders?type=completed&client_id={cid}", "orders"),
        ("Orders",  "Trades",            "GET", f"/api/v1/trades?client_id={cid}", "orders"),
        ("Orders",  "GTT",               "GET", f"/api/v1/event/gtt/{cid}", "orders"),
        ("Orders",  "Basket",            "GET", f"/api/v1/basket?login_id={cid}", "orders"),

        ("Portfolio", "Positions",        "GET", f"/api/v1/positions?client_id={cid}&type=historical", "portfolio"),

        ("Funds",   "Transactions",       "GET", f"/api/v1/pg/tx/transactions?client_id={cid}", "funds"),
        ("Funds",   "Crypto wallets",     "GET", f"/api/v1/pg/tx/crypto/wallets?client_id={cid}", "funds"),

        ("Market",  "Watchlists",         "GET", "/api/v1/marketwatches", "dashboard"),
        ("Market",  "Price alerts",       "GET", "/api/v1/alerts", "price-alerts"),

        ("Screeners", "Most active (NSE)", "GET", "/api/v1/screeners/mostactivestocks?exchange=NSE", "dashboard"),
        ("Screeners", "Gainers/Losers",    "GET", "/api/v1/screeners/gainerslosers?exchange=NSE", "screeners"),
        ("Screeners", "Yearly high",       "GET", "/api/v1/screeners/yearly_high?exchange=NSE", "dashboard"),
        ("Screeners", "Yearly low",        "GET", "/api/v1/screeners/yearly_low?exchange=NSE", "dashboard"),

        ("Reports", "Trade History", "GET",
         f"/api/v1/historical-trades?page=1&page_size=50&fetch_all=ALL&client_ids={cid}"
         f"&buy_sell=&exchange=NFO&is_error_trade=false"
         f"&business_date={today}&start_business_date={week_ago}", "tradehistory"),
        ("Reports", "P&L History", "GET",
         f"/api/v1/bills/advanced?client_id={cid}&start_date={week_ago}&end_date={today}"
         f"&page=1&page_size=50&exchange=", "tradehistory"),
        ("Reports", "Ledger", "GET",
         f"/api/v1/ledger/advanced?client_id={cid}&start_date={week_ago}&end_date={today}"
         f"&page=1&page_size=20", "tradehistory"),
    ]
    for key in SEARCH_KEYS:
        b.append(("Search", f"Search: {key}", "GET", f"/api/v1/search?key={key}", "dashboard"))
    return b


def _order_body(cid, exchange, token, side, otype, price, product, qty, **extra):
    b = {
        "client_id": cid, "device": "WEB", "disclosed_quantity": 0,
        "exchange": exchange, "execution_type": "REGULAR",
        "instrument_token": token, "order_side": side, "order_type": otype,
        "price": price, "product": product, "quantity": qty, "trigger_price": 0,
        "user_order_id": int(time.time() * 1000), "validity": "DAY", "is_reducing_qty": False,
    }
    b.update(extra)
    return b


def get_quote(label, auth, exchange, token):
    """Return {'ltp','bid','ask'} from the WS feed, or {'error':...}."""
    return ws_client.get_quote(label["base"], label["client_id"], auth, exchange, token)


def _limit_price(side, quote):
    """Resting LIMIT price that satisfies BUY<ask and SELL>bid without crossing.

    BUY goes just below the BID (still < ask) and SELL just above the ASK
    (still > bid), so the two sides never self-match and both rest as pending —
    giving the modify/cancel steps something to act on. Falls back to LTP.
    """
    if side == "BUY":
        ref = quote.get("bid") or quote.get("ltp")
        if ref:
            return max(1, int(round(ref)) - 1), ref
    if side == "SELL":
        ref = quote.get("ask") or quote.get("ltp")
        if ref:
            return int(round(ref)) + 1, ref
    return None, None


def _pending_orders(label, auth):
    res = http(label["base"], f"/api/v1/orders?type=pending&client_id={label['client_id']}",
               auth=auth, referer="orders")
    try:
        j = json.loads(res["raw"])
    except ValueError:
        return res, []
    # response may be {"orders":[...]} or {"data":{"orders":[...]}}
    data = j.get("data")
    if isinstance(data, dict) and "orders" in data:
        return res, (data.get("orders") or [])
    if isinstance(data, list):
        return res, data
    return res, (j.get("orders") or [])


def place_orders(label, auth):
    """Full live order lifecycle for a label, returning report rows.

    Per instrument/side: place a MARKET order, then a resting LIMIT order priced
    off the live WS bid/ask. Then fetch pending orders, modify each (price ±1,
    quantity bumped), and finally cancel each. Read specs are shared across labels.
    """
    rows = []
    cfg = ORDER_TESTS.get(label["key"], {})
    specs = cfg.get("orders", ORDER_SPECS)
    device_id = cfg.get("device_id", ORDER_DEVICE_ID)
    cid, base = label["client_id"], label["base"]
    if not specs:
        rows.append(_synth("Order placement", "POST", "/api/v1/orders", None,
                           "no order specs configured for this label — skipped",
                           section="Order Placement"))
        return rows

    # Prefetch all quotes over ONE WS connection (fast; ltp per instrument).
    pairs = {(s["exchange"], str(s["instrument_token"])) for s in specs}
    quotes = ws_client.get_quotes(base, cid, auth, pairs)

    # 1 + 2) MARKET then LIMIT (priced off live WS quote) for each instrument/side
    for spec in specs:
        ex, tok = spec["exchange"], str(spec["instrument_token"])
        for side in ORDER_SIDES:
            market = _order_body(cid, ex, tok, side, spec.get("order_type", "MARKET"),
                                 spec.get("price", 0), spec["product"], spec["quantity"])
            res = http(base, "/api/v1/orders", method="POST", body=market, auth=auth,
                       referer="funds", retries=0, device_id=device_id)
            rows.append(_row(f"{spec['name']} — {side} (MARKET)", "POST", "/api/v1/orders",
                             res, section="Order Placement"))

            quote = quotes.get((ex, tok), {"error": "no quote"})
            lp, ref = _limit_price(side, quote)
            qtxt = (f"ltp {quote.get('ltp')}, bid {quote.get('bid')}, ask {quote.get('ask')}"
                    if not quote.get("error") else quote["error"])
            if lp is None:
                rows.append(_synth(f"{spec['name']} — {side} (LIMIT)", "POST", "/api/v1/orders",
                                   None, f"no price reference ({qtxt}) — skipped",
                                   section="LIMIT Orders"))
                continue
            limit = _order_body(cid, ex, tok, side, "LIMIT", lp, spec["product"], spec["quantity"])
            res = http(base, "/api/v1/orders", method="POST", body=limit, auth=auth,
                       referer="funds", retries=0, device_id=device_id)
            r = _row(f"{spec['name']} — {side} (LIMIT @{lp})", "POST", "/api/v1/orders",
                     res, section="LIMIT Orders", note=f"quote: {qtxt}")
            rows.append(r)

    # 3 + 4) fetch pending, modify each (price ±1, quantity bumped)
    time.sleep(1.5)
    res, pend = _pending_orders(label, auth)
    rows.append(_row(f"Pending orders ({len(pend)})", "GET",
                     f"/api/v1/orders?type=pending&client_id={cid}", res, section="Modify Pending"))
    for o in pend:
        side = o.get("order_side", "BUY")
        oldp = int(o.get("price") or 0)
        newp = max(1, oldp - 1) if side == "BUY" else oldp + 1
        newq = int(o.get("quantity") or 1) + 1
        body = _order_body(cid, o.get("exchange"), int(o.get("instrument_token") or 0), side,
                           "LIMIT", newp, o.get("product"), newq,
                           validity=o.get("validity", "DAY"),
                           exchange_order_id=o.get("exchange_order_id", ""),
                           oms_order_id=o.get("oms_order_id"))
        res = http(base, "/api/v1/orders", method="PUT", body=body, auth=auth,
                   referer="orders", retries=0, device_id=device_id)
        rows.append(_row(f"Modify {o.get('symbol','')} {side} → @{newp} x{newq}", "PUT",
                         "/api/v1/orders", res, section="Modify Pending"))

    # 5) fetch pending again, cancel each
    time.sleep(1.5)
    res, pend = _pending_orders(label, auth)
    rows.append(_row(f"Pending orders ({len(pend)})", "GET",
                     f"/api/v1/orders?type=pending&client_id={cid}", res, section="Cancel Pending"))
    for o in pend:
        oid = o.get("oms_order_id")
        res = http(base, f"/api/v1/orders/{oid}?client_id={cid}", method="DELETE",
                   auth=auth, referer="orders", retries=0, device_id=device_id)
        rows.append(_row(f"Cancel {o.get('symbol','')} {o.get('order_side','')} #{oid}",
                         "DELETE", f"/api/v1/orders/{oid}", res, section="Cancel Pending"))
    return rows


def run_label(label, place=None):
    place = PLACE_ORDERS if place is None else place
    started = time.perf_counter()
    auth, rows = authenticate(label)
    if auth:
        for section, name, method, path, referer in endpoint_battery(label["client_id"]):
            res = http(label["base"], path, method=method, auth=auth, referer=referer)
            rows.append(_row(name, method, path, res, section=section))
        if place:
            rows.extend(place_orders(label, auth))
    executed = [r for r in rows if r["ok"] is not None]  # exclude skipped
    passed = sum(1 for r in executed if r["ok"])
    return {
        "key": label["key"], "name": label["name"], "base": label["base"],
        "client_id": label["client_id"], "pin_required": bool(label.get("pin")),
        "authenticated": bool(auth), "rows": rows,
        "passed": passed, "total": len(executed),
        "skipped": len(rows) - len(executed),
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
    }


# ----------------------------------------------------------------------------
# Row builders
# ----------------------------------------------------------------------------
def _row(name, method, path, res, section="Auth", note=""):
    detail = res.get("message") or res.get("error") or ""
    if note:
        detail = f"{note}" + (f" — {detail}" if detail else "")
    return {
        "section": section, "name": name, "method": method, "path": path,
        "status": res.get("status"), "api_status": res.get("api_status"),
        "ms": res.get("ms"), "ok": res.get("ok", False), "detail": detail,
        "req": res.get("req"), "resp": res.get("resp", ""),
    }


def _synth(name, method, path, ok, detail, section="Auth"):
    return {"section": section, "name": name, "method": method, "path": path,
            "status": None, "api_status": None, "ms": None, "ok": ok, "detail": detail,
            "req": None, "resp": ""}


# ----------------------------------------------------------------------------
# HTML report
# ----------------------------------------------------------------------------
def _io_block(row, esc):
    """Collapsible Request / Response panel for one endpoint."""
    req = row.get("req")
    if req:
        hdrs = "\n".join(f"{k}: {v}" for k, v in req["headers"].items())
        request_txt = f"{req['method']} {req['url']}\n\n{hdrs}"
        if req.get("body"):
            request_txt += f"\n\n{req['body']}"
    else:
        request_txt = "(no request issued)"
    resp_txt = row.get("resp") or "(no response body)"
    return (
        '<details class="io"><summary>Request / Response</summary>'
        '<div class="io-grid">'
        f'<div class="io-col"><div class="io-h">Request</div><pre>{esc(request_txt)}</pre></div>'
        f'<div class="io-col"><div class="io-h">Response</div><pre>{esc(resp_txt)}</pre></div>'
        '</div></details>'
    )


def build_html(results, generated_at, placed_orders=False):
    esc = html.escape
    total_ep = sum(r["total"] for r in results)
    total_pass = sum(r["passed"] for r in results)
    total_fail = total_ep - total_pass
    labels_ok = sum(1 for r in results if r["authenticated"] and r["passed"] == r["total"])

    def status_pill(ok):
        if ok is None:
            return '<span class="pill skip">SKIP</span>'
        return ('<span class="pill pass">PASS</span>' if ok
                else '<span class="pill fail">FAIL</span>')

    cards = []
    for r in results:
        health = "ok" if (r["authenticated"] and r["passed"] == r["total"]) else \
                 ("warn" if r["authenticated"] else "bad")
        cards.append(f"""
        <div class="card {health}">
          <div class="card-name">{esc(r['name'])}</div>
          <div class="card-num">{r['passed']}/{r['total']}</div>
          <div class="card-sub">{esc(r['base'])}</div>
        </div>""")

    sections = []
    for r in results:
        # group rows by section
        groups = {}
        for row in r["rows"]:
            groups.setdefault(row["section"], []).append(row)
        body_rows = []
        for section, rws in groups.items():
            body_rows.append(f'<tr class="section-row"><td colspan="6">{esc(section)}</td></tr>')
            for row in rws:
                cls = "ok" if row["ok"] else ("skip" if row["ok"] is None else "bad")
                status = row["status"] if row["status"] is not None else "—"
                apis = esc(str(row["api_status"])) if row["api_status"] else "—"
                ms = f'{row["ms"]} ms' if row["ms"] is not None else "—"
                body_rows.append(f"""<tr class="{cls}">
                  <td>{status_pill(row['ok'])}</td>
                  <td class="name">{esc(row['name'])}</td>
                  <td><code>{esc(row['method'])}</code></td>
                  <td class="path"><code>{esc(row['path'])}</code></td>
                  <td class="mono">{status} · {apis}</td>
                  <td class="mono small">{ms}{(' · ' + esc(row['detail'])) if row['detail'] else ''}</td>
                </tr>""")
                body_rows.append(f'<tr class="io-row"><td></td><td colspan="5">{_io_block(row, esc)}</td></tr>')
        auth_badge = ('<span class="pill pass">authenticated</span>' if r["authenticated"]
                      else '<span class="pill fail">login failed</span>')
        pin_badge = '<span class="tag">PIN</span>' if r["pin_required"] else '<span class="tag muted">no PIN</span>'
        open_attr = "" if (r["passed"] == r["total"] and r["authenticated"]) else " open"
        sections.append(f"""
        <details class="wl"{open_attr}>
          <summary>
            <span class="sum-name">{esc(r['name'])}</span>
            {auth_badge} {pin_badge}
            <span class="sum-score {'ok' if r['passed']==r['total'] and r['authenticated'] else 'bad'}">{r['passed']}/{r['total']} passed</span>
            <span class="sum-meta">client {esc(r['client_id'])} · {r['elapsed_ms']} ms</span>
          </summary>
          <table>
            <thead><tr><th>Result</th><th>Endpoint</th><th>Method</th><th>Path</th><th>HTTP · API</th><th>Latency · Detail</th></tr></thead>
            <tbody>{''.join(body_rows)}</tbody>
          </table>
        </details>""")

    ref_rows = "".join(
        f"<tr><td>{esc(k)}</td><td class='mono'>{esc(v)}</td></tr>"
        for k, v in EXCHANGE_TOKENS.items())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CFD Migration Sanity Report</title>
<style>
:root {{
  --bg:#0f1115; --panel:#171a21; --panel2:#1e222b; --line:#2a2f3a;
  --text:#e6e9ef; --muted:#9aa3b2; --pass:#2ec16b; --fail:#ff5c5c;
  --warn:#f5a623; --accent:#5b8dff;
}}
@media (prefers-color-scheme: light) {{
  :root {{ --bg:#f4f6fa; --panel:#ffffff; --panel2:#f0f3f8; --line:#dde3ec;
    --text:#1a1f2b; --muted:#5a6472; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
.wrap {{ max-width:1100px; margin:0 auto; padding:28px 16px 64px; }}
h1 {{ font-size:22px; margin:0 0 4px; }}
.sub {{ color:var(--muted); margin:0 0 22px; }}
.totals {{ display:flex; gap:14px; flex-wrap:wrap; margin-bottom:24px; }}
.tot {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
  padding:14px 18px; min-width:130px; }}
.tot .n {{ font-size:26px; font-weight:700; }}
.tot .l {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
.tot.pass .n {{ color:var(--pass); }} .tot.fail .n {{ color:var(--fail); }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:12px; margin-bottom:28px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-left-width:4px;
  border-radius:10px; padding:14px; }}
.card.ok {{ border-left-color:var(--pass); }}
.card.warn {{ border-left-color:var(--warn); }}
.card.bad {{ border-left-color:var(--fail); }}
.card-name {{ font-weight:600; }}
.card-num {{ font-size:22px; font-weight:700; margin:2px 0; }}
.card-sub {{ color:var(--muted); font-size:12px; word-break:break-all; }}
details.wl {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
  margin-bottom:14px; overflow:hidden; }}
summary {{ cursor:pointer; padding:14px 18px; display:flex; align-items:center;
  gap:12px; flex-wrap:wrap; list-style:none; }}
summary::-webkit-details-marker {{ display:none; }}
.sum-name {{ font-weight:700; font-size:15px; }}
.sum-score {{ font-weight:600; }} .sum-score.ok {{ color:var(--pass); }} .sum-score.bad {{ color:var(--fail); }}
.sum-meta {{ color:var(--muted); font-size:12px; margin-left:auto; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; padding:8px 12px; border-top:1px solid var(--line); vertical-align:top; }}
th {{ background:var(--panel2); color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }}
tr.section-row td {{ background:var(--panel2); font-weight:700; font-size:12px;
  text-transform:uppercase; letter-spacing:.05em; color:var(--muted); }}
tr.bad td.name {{ color:var(--fail); }}
td.path {{ max-width:340px; overflow:hidden; text-overflow:ellipsis; }}
code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; }}
.mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.small {{ font-size:12px; color:var(--muted); }}
.pill {{ display:inline-block; padding:2px 9px; border-radius:20px; font-size:11px; font-weight:700; }}
.pill.pass {{ background:rgba(46,193,107,.15); color:var(--pass); }}
.pill.fail {{ background:rgba(255,92,92,.15); color:var(--fail); }}
.pill.skip {{ background:var(--panel2); color:var(--muted); }}
.banner {{ background:rgba(245,166,35,.12); border:1px solid var(--warn); color:var(--warn);
  border-radius:10px; padding:12px 16px; margin-bottom:20px; font-weight:600; }}
.tag {{ display:inline-block; padding:2px 8px; border-radius:6px; font-size:11px;
  background:rgba(91,141,255,.15); color:var(--accent); }}
.tag.muted {{ background:var(--panel2); color:var(--muted); }}
tr.io-row td {{ padding:0 12px 10px; border-top:none; }}
details.io {{ margin:0 0 4px; }}
details.io > summary {{ cursor:pointer; color:var(--accent); font-size:12px; padding:4px 0;
  list-style:none; display:inline-block; }}
details.io > summary::-webkit-details-marker {{ display:none; }}
details.io > summary::before {{ content:"▸ "; }}
details.io[open] > summary::before {{ content:"▾ "; }}
.io-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:6px; }}
@media (max-width:720px) {{ .io-grid {{ grid-template-columns:1fr; }} }}
.io-col {{ min-width:0; }}
.io-h {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin-bottom:4px; }}
.io-col pre {{ margin:0; background:var(--bg); border:1px solid var(--line); border-radius:8px;
  padding:10px; overflow:auto; max-height:340px; font-size:11.5px; line-height:1.45;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap; word-break:break-word; }}
.ref {{ margin-top:32px; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:18px; }}
.ref h2 {{ font-size:14px; margin:0 0 10px; }}
.ref table {{ max-width:320px; }}
footer {{ color:var(--muted); font-size:12px; margin-top:28px; text-align:center; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>CFD Migration Sanity Report</h1>
  <p class="sub">API health check across {len(results)} white labels · generated {esc(generated_at)}</p>
  {'<div class="banner">⚠ Order-placement mode was ON — real MARKET orders were sent to live accounts during this run.</div>' if placed_orders else ''}

  <div class="totals">
    <div class="tot"><div class="n">{labels_ok}/{len(results)}</div><div class="l">Labels healthy</div></div>
    <div class="tot pass"><div class="n">{total_pass}</div><div class="l">Checks passed</div></div>
    <div class="tot fail"><div class="n">{total_fail}</div><div class="l">Checks failed</div></div>
    <div class="tot"><div class="n">{total_ep}</div><div class="l">Total checks</div></div>
  </div>

  <div class="cards">{''.join(cards)}</div>

  {''.join(sections)}

  <div class="ref">
    <h2>Exchange instrument tokens (reference — from read.md)</h2>
    <table><thead><tr><th>Exchange</th><th>Instrument token</th></tr></thead>
    <tbody>{ref_rows}</tbody></table>
    <p class="small" style="margin-bottom:0">Order-placement APIs run only with the <code>--place-orders</code> flag (off by default). {'They ran in this report.' if placed_orders else 'They did not run in this report.'}</p>
  </div>

  <footer>CFD Migration Sanity · credentials and auth tokens are never written to this report.</footer>
</div>
</body>
</html>"""


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="CFD white-label API sanity checker")
    ap.add_argument("--out", default="report.html", help="output HTML path")
    ap.add_argument("--only", default="", help="comma-separated label keys to run")
    ap.add_argument("--open", action="store_true", help="open the report when done")
    ap.add_argument("--serial", action="store_true", help="run labels serially")
    ap.add_argument("--no-orders", action="store_true",
                    help="read-only run: skip live order placement")
    # Accepted for backward compatibility; placement is on by default now.
    ap.add_argument("--place-orders", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    global PLACE_ORDERS
    PLACE_ORDERS = not args.no_orders
    if PLACE_ORDERS:
        print("!! Order placement is ON — REAL MARKET orders will be sent to live accounts.")
        print("   (use --no-orders for a read-only run)")

    labels = WHITE_LABELS
    if args.only:
        want = {s.strip().lower() for s in args.only.split(",") if s.strip()}
        labels = [l for l in labels if l["key"] in want]
        if not labels:
            print("No matching labels for --only", args.only)
            return

    mode = "sanity + LIVE ORDER PLACEMENT" if PLACE_ORDERS else "read-only sanity"
    print(f"Running {mode} across {len(labels)} white label(s)...")
    if args.serial:
        results = [run_label(l) for l in labels]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(labels)) as ex:
            results = list(ex.map(run_label, labels))
    # keep configured order
    order = {l["key"]: i for i, l in enumerate(labels)}
    results.sort(key=lambda r: order[r["key"]])

    for r in results:
        state = "OK " if (r["authenticated"] and r["passed"] == r["total"]) else "!! "
        print(f"  {state}{r['name']:<12} {r['passed']}/{r['total']} passed "
              f"({'auth ok' if r['authenticated'] else 'LOGIN FAILED'}, {r['elapsed_ms']} ms)")

    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    html_out = build_html(results, generated, placed_orders=PLACE_ORDERS)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"\nReport written to {args.out}")
    if args.open:
        webbrowser.open("file://" + __import__("os").path.abspath(args.out))


if __name__ == "__main__":
    main()
