#!/usr/bin/env python3
"""
Minimal dependency-free WebSocket client (RFC 6455) for the market-data feed.

Only what we need: TLS connect, handshake (no permessage-deflate so frames are
uncompressed), send a masked text frame, read server frames, handle ping/close.

get_quote() subscribes to one instrument and returns its bid/ask/ltp.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import time
from urllib.parse import urlparse

# exchange name -> feed exchange code (from the platform's WS docs)
EXCHANGE_CODE = {
    "NSE": 1, "NFO": 2, "CDS": 3, "MCX": 4, "BSE": 6, "BFO": 7, "NSE_INDICES": 9,
    "DCSX": 19,
}

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


class WSError(Exception):
    pass


class WSClient:
    def __init__(self, url, origin=None, timeout=10):
        self.url = url
        u = urlparse(url)
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "wss" else 80)
        self.path = u.path + (("?" + u.query) if u.query else "")
        self.secure = u.scheme == "wss"
        self.origin = origin or f"https://{self.host}"
        self.timeout = timeout
        self.sock = None

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock = _SSL.wrap_socket(raw, server_hostname=self.host) if self.secure else raw
        self.sock.settimeout(self.timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Origin: {self.origin}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n"
        )
        self.sock.sendall(req.encode())
        resp = self._read_until(b"\r\n\r\n")
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if "101" not in status:
            raise WSError(f"handshake failed: {status}")

    def _read_until(self, delim):
        buf = b""
        while delim not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WSError("connection closed during handshake")
            buf += chunk
        return buf

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise WSError("connection closed")
            buf += chunk
        return buf

    def send_text(self, text):
        payload = text.encode("utf-8")
        header = bytearray([0x81])  # FIN + text
        n = len(payload)
        mask = os.urandom(4)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv_frame(self):
        """Return (opcode, payload_bytes) for one complete message (handles ping)."""
        b0, b1 = self._recv_exact(2)
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        data = self._recv_exact(length) if length else b""
        if mask:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if opcode == 0x9:            # ping -> pong
            self._send_control(0xA, data)
            return self.recv_frame()
        if opcode == 0xA:            # pong, ignore
            return self.recv_frame()
        return opcode, data

    def _send_control(self, opcode, data=b""):
        mask = os.urandom(4)
        header = bytes([0x80 | opcode, 0x80 | len(data)]) + mask
        self.sock.sendall(header + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def close(self):
        try:
            self._send_control(0x8)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def _num(*vals):
    for v in vals:
        if v is not None:
            try:
                return float(v)
            except (TypeError, ValueError):
                pass
    return None


def _extract_quote(obj, token):
    """Pull bid/ask/ltp from a feed message dict, tolerant of key variants."""
    if not isinstance(obj, dict):
        return None
    bid = _num(obj.get("bidPrice"), obj.get("bid_price"), obj.get("bid"), obj.get("bp"))
    ask = _num(obj.get("askPrice"), obj.get("ask_price"), obj.get("ask"), obj.get("ap"))
    ltp = _num(obj.get("ltp"), obj.get("last_traded_price"), obj.get("lp"))
    tok = obj.get("instrument_token") or obj.get("token") or obj.get("tk") or obj.get("it")
    if bid is None and ask is None and ltp is None:
        return None
    return {"token": tok, "bid": bid, "ask": ask, "ltp": ltp}


def _parse_binary(data):
    """Parse a compact_marketdata binary frame.

    Layout (big-endian): byte0 = mode, byte1 = exchange code, then int32[]:
      [0]=instrument_token, [1]=ltp*100, [2]=pct_change, [3]=abs_change,
      [4]=lower_circuit*100, [5]=upper_circuit*100, [6]=bid*100, [7]=ask*100, ...
    Prices are in paise (÷100). bid/ask are 0 when the market is closed.
    """
    if len(data) < 10:
        return None
    body = data[2:]
    ints = [struct.unpack(">i", body[i:i + 4])[0] for i in range(0, len(body) - 3, 4)]
    if len(ints) < 2:
        return None
    def px(i):
        return (ints[i] / 100.0) if (0 <= i < len(ints) and ints[i] > 0) else None
    # Offsets confirmed against live open-market data (prices in paise ÷100):
    #   [0]=token [1]=ltp [2]=abs_change [3]=ltt(epoch) [4]=LC [5]=UC
    #   [8]=bid [9]=ask
    return {
        "token": ints[0],
        "ltp": px(1),
        "bid": px(8),
        "ask": px(9),
        "abs_change": (ints[2] / 100.0) if len(ints) > 2 else None,
        "ltt": ints[3] if len(ints) > 3 else None,
        "exchange_code": data[1],
        "raw_ints": ints,
    }


def get_quote(base_https, login_id, token, exchange, instrument_token, timeout=9):
    """Subscribe to one instrument and return {'bid','ask','ltp'} or None.

    base_https: e.g. https://web.marketbhai.one
    exchange:   exchange NAME (NSE/NFO/...) or numeric code
    """
    code = exchange if isinstance(exchange, int) else EXCHANGE_CODE.get(str(exchange).upper())
    if code is None:
        return {"error": f"no WS exchange code for {exchange}"}
    host = urlparse(base_https).hostname
    url = (f"wss://{host}/ws/v1/feeds?login_id={login_id}"
           f"&token={token}&device=web")
    ws = WSClient(url, origin=base_https, timeout=timeout)
    try:
        ws.connect()
        sub = {"a": "subscribe", "v": [[int(code), int(instrument_token)]], "m": "compact_marketdata"}
        ws.send_text(json.dumps(sub))
        deadline = time.time() + timeout
        best = None
        while time.time() < deadline:
            try:
                opcode, data = ws.recv_frame()
            except (WSError, socket.timeout):
                break
            if opcode == 0x8:
                break
            if opcode == 0x2:                    # binary compact_marketdata
                q = _parse_binary(data)
                if q and (str(q.get("token")) == str(instrument_token) or q.get("ltp")):
                    best = q
                    if q.get("bid") and q.get("ask"):
                        return q
                continue
            if opcode == 0x1:                    # text (JSON) fallback
                try:
                    msg = json.loads(data.decode("utf-8", "replace"))
                except ValueError:
                    continue
                for c in (msg if isinstance(msg, list) else [msg]):
                    q = _extract_quote(c, instrument_token)
                    if q:
                        best = q
                        if q.get("bid") and q.get("ask"):
                            return q
        return best or {"error": "no quote received"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        ws.close()


def get_quotes(base_https, login_id, token, pairs, timeout=8):
    """Fetch several instruments over ONE WS connection.

    pairs: iterable of (exchange_name_or_code, instrument_token).
    Returns {(exchange, token_str): {'ltp','bid','ask'}}.
    """
    subs, by_token, out = [], {}, {}
    for ex, tok in pairs:
        code = ex if isinstance(ex, int) else EXCHANGE_CODE.get(str(ex).upper())
        if code is None:
            out[(ex, str(tok))] = {"error": f"no WS exchange code for {ex}"}
            continue
        subs.append([int(code), int(tok)])
        by_token[int(tok)] = (ex, str(tok))
    if not subs:
        return out
    host = urlparse(base_https).hostname
    url = f"wss://{host}/ws/v1/feeds?login_id={login_id}&token={token}&device=web"
    ws = WSClient(url, origin=base_https, timeout=timeout)
    try:
        ws.connect()
        ws.send_text(json.dumps({"a": "subscribe", "v": subs, "m": "compact_marketdata"}))
        deadline = time.time() + timeout
        while time.time() < deadline and len(out) < len(subs) + (len(pairs) - len(subs)):
            try:
                opcode, data = ws.recv_frame()
            except (WSError, socket.timeout):
                break
            if opcode == 0x8:
                break
            q = _parse_binary(data) if opcode == 0x2 else None
            if not q:
                continue
            key = by_token.get(int(q["token"])) if q.get("token") is not None else None
            if key and key not in out and q.get("ltp"):
                out[key] = {"ltp": q["ltp"], "bid": q["bid"], "ask": q["ask"]}
        for key in by_token.values():
            out.setdefault(key, {"error": "no quote received"})
        return out
    except Exception as e:  # noqa: BLE001
        for key in by_token.values():
            out.setdefault(key, {"error": f"{type(e).__name__}: {e}"})
        return out
    finally:
        ws.close()


if __name__ == "__main__":
    # Live probe: login to a label, then print the raw feed + parsed quote.
    import cfd_sanity as cfd
    lbl = next(l for l in cfd.WHITE_LABELS if l["key"] == "marketbhai")
    auth, rows = cfd.authenticate(lbl)
    print("auth ok:", bool(auth))
    if not auth:
        raise SystemExit("login failed")
    host = urlparse(lbl["base"]).hostname
    url = f"wss://{host}/ws/v1/feeds?login_id={lbl['client_id']}&token={auth}&device=web"
    ws = WSClient(url, origin=lbl["base"], timeout=9)
    ws.connect()
    print("connected")
    ws.send_text(json.dumps({"a": "subscribe", "v": [[1, 2885]], "m": "compact_marketdata"}))
    t = time.time()
    n = 0
    while time.time() - t < 8 and n < 6:
        try:
            op, data = ws.recv_frame()
        except Exception as e:  # noqa: BLE001
            print("recv err:", e); break
        print(f"[op={op}] {data[:400]!r}")
        n += 1
    ws.close()
