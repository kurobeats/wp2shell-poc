# Known Gaps

## Exploitation

### Pre-auth RCE without FILE privilege
The original Assetnote chain that achieves pre-auth RCE without MySQL `FILE`
privilege has **not been publicly disclosed**. The 6.9.5 / 7.0.2 patch adds
`is_dispatching()` guards in both `serve_request()` and `rest_api_loaded()`,
indicating the chain relied on recursive REST dispatch. Without this bypass,
the route confusion reaches admin-gated endpoints but `permission_callback`
still blocks write operations.

**Lead:** Find an admin REST endpoint with `permission_callback: true` (no auth)
that writes files or executes code. Or discover the recursive dispatch
mechanism that the `is_dispatching()` guards blocked.

### Stacked queries blocked
PHP `mysqli_query()` does not support multi-statement execution. All
INSERT/UPDATE/DELETE/DROP via the SQLi injection point is impossible.
`mysqli_multi_query()` is not used by WordPress's `wpdb` class.

**No known bypass.**

### INTO OUTFILE container mismatch
`SELECT ... INTO OUTFILE` writes to the **database server's** filesystem.
In Docker Compose, Kubernetes, or split-horizon hosting, the DB container
is separate from the web container. The webshell is written but unreachable.
The tool now detects this (HTTP verification after write) and warns.

**Mitigation:** `--outfile-dir` must point to a path that is both writable by
the DB server AND served by the web server. Only works on single-server LAMP
stacks or when DB + web share a filesystem mount.

## Tooling

### sqlmap integration unreliable
The `wp2shell_tamper.py` tamper script replaces the POST body with the
double-confusion JSON, but sqlmap (v1.9.6) parses the original `--data` as
JSON form fields and sends with wrong Content-Type. All requests return
HTTP 400.

**Workaround:** Use `wp2shell.py extract` for blind extraction (faster and
more reliable). Use `wp2shell_tamper.py` standalone mode for time-based
extraction with nonce recovery.

**Fix needed:** Custom sqlmap proxy or `--eval`-based request builder that
bypasses sqlmap's JSON parsing.

### Version detection on fresh installs
`detect_version()` probes `/wp-json/`, homepage meta tags, and RSS feeds.
On fresh Docker installs with no posts/pages, these sources often return
nothing. The tool falls back to "version unknown" and tests the 6.8.x
direct REST path as a heuristic.

**Improvement:** Check `/readme.html` (shipped with every WordPress install
and contains the version in plain text) before falling back to heuristics.

### Fast extractor endpoint dependency
The fast X-WP-Total extraction mode embeds probes in `/wp/v2/categories`
requests. If the `categories` taxonomy is removed or the endpoint is
disabled by a plugin, fast mode fails. Blind mode (`--fast` not set)
always works as a fallback.

### Marker probe on 6.8.x
The marker probe uses `/wp/v2/block-renderer/core/archives` which does
not exist on WordPress 6.8.x, causing HTTP 500 instead of the expected
error codes. The tool detects this (`internal_server_error` without
`parse_path_failed`) and correctly identifies 6.8.x-era builds, but
this is a heuristic, not a definitive detection.

## Testing Coverage

### Network configurations
All testing was done against Docker containers on the default bridge
network with `--link`. Not tested:
- Containers on custom Docker networks
- Kubernetes pods
- Targets behind reverse proxies (nginx, HAProxy, Cloudflare)
- IPv6-only targets
- HTTPS targets with self-signed or invalid certificates

### WAF / IDS evasion
Payloads are static with no obfuscation or encoding. Not tested against:
- ModSecurity with default WordPress ruleset
- Cloudflare WAF
- Wordfence / Sucuri / iThemes Security plugins
- Fail2ban or rate-limiting middleware

### Plugin / theme interference
All tests were on stock WordPress with no plugins and the default theme.
Not tested:
- Plugins that modify REST API behaviour (WooCommerce, Jetpack, etc.)
- Custom `author_exclude` sanitisation added by security plugins
- Multisite / network-mode WordPress

### Exotic MySQL configurations
- MariaDB vs MySQL differences in `INTO OUTFILE` behaviour
- `secure_file_priv` set to non-default paths
- Cloud SQL / RDS where `FILE` privilege is revoked entirely
- MySQL 8.x vs MariaDB 11.x SQL mode differences affecting the injection

### 6.7.x and earlier
Only tested back to 6.8.0. The SQLi in `WP_Query::author__not_in` may
exist in earlier versions (the vulnerable code pattern predates 6.8),
but the batch route confusion was introduced in 6.9.0. Pre-6.8 versions
are EOL and not in scope for this tool.

## Documentation

### `probe` command output
The route-shifted endpoint signatures are low-level (`200/-/list[1]` vs
`400/-/dict(code,data,message)`) and require interpretation. A guide
mapping common signatures to specific WordPress behaviours would help
researchers identify the most promising escalation endpoints.

### Password cracking guidance
The README mentions offline hash cracking but doesn't cover:
- Hash format conversion (`$wp$` phpass → hashcat mode 400)
- Recommended wordlists and rules
- GPU acceleration vs CPU-only cracking time estimates
