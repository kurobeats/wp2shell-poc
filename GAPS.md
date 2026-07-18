# Known Gaps

## Exploitation

### Pre-auth RCE without FILE privilege
The original Assetnote chain that achieves pre-auth RCE without MySQL `FILE`
privilege has **not been publicly disclosed**. The 6.9.5 / 7.0.2 patch adds
`is_dispatching()` guards in both `serve_request()` and `rest_api_loaded()`,
indicating the chain relied on recursive REST dispatch.

#### Research: Abilities API (`wp-abilities/v1`)
The Abilities API (`/wp-abilities/v1/abilities/<name>/run`) accepts ALL HTTP methods
and delegates `permission_callback` to the individual registered ability. On stock
WordPress 6.9.4, two core abilities are REST-accessible:

| Ability | Permission | Risk |
|---------|-----------|------|
| `core/get-site-info` | `manage_options` | Read-only: site title, URL, admin email, version |
| `core/get-environment-info` | `manage_options` | Read-only: env type, PHP version, DB info, WP version |

`core/get-user-info` has `show_in_rest: false` (not REST-accessible). No core
ability has a write side effect or weak `permission_callback`.

**Lead:** A plugin or theme that registers an ability with `show_in_rest: true`
and a weak or missing `permission_callback` could provide pre-auth RCE via the
abilities `/run` endpoint. The endpoint itself has no hardcoded auth — it
delegates entirely to the ability's `permission_callback`. If that callback
is missing or returns `true`, the ability executes unauthenticated.

**To research further:**
- Audit popular plugins for abilities with `permission_callback` omitted
- Test whether `permission_callback` defaults to `true` when not set
- Test whether a plugin ability with `execute_callback` that writes files or
  spawns processes can be reached via route confusion

#### Research: `secure_file_priv = NULL`
MySQL/MariaDB default to `secure_file_priv = NULL` (no restriction) in many
configurations. Combined with `INTO OUTFILE`, this means on single-server
LAMP stacks, you CAN write a webshell directly to `/var/www/html/`. The
Docker/split-hosting case is the exception — on bare metal and traditional
shared hosting, `INTO OUTFILE` RCE is viable without any filesystem tricks.

### Stacked queries blocked
PHP `mysqli_query()` does not support multi-statement execution. All
INSERT/UPDATE/DELETE/DROP via the SQLi injection point is impossible.
`mysqli_multi_query()` is not used by WordPress's `wpdb` class.

**No known bypass.**

### INTO OUTFILE container mismatch
`SELECT ... INTO OUTFILE` writes to the **database server's** filesystem.
In Docker Compose, Kubernetes, or split-horizon hosting, the DB container
is separate from the web container. The tool now detects this (HTTP
verification after write) and warns.

**Mitigation:** `--outfile-dir` must point to a path that is both writable by
the DB server AND served by the web server. `secure_file_priv = NULL` helps
— removes the MySQL-level restriction, leaving only OS-level permissions.

## Tooling

### sqlmap integration unreliable
The `wp2shell_tamper.py` tamper script replaces the POST body with the
double-confusion JSON, but sqlmap parses the original `--data` as JSON
form fields and sends with wrong Content-Type. All requests return
HTTP 400.

**Workaround:** Use `wp2shell.py extract` for blind extraction. Use
`wp2shell_tamper.py` standalone mode for time-based extraction with
nonce recovery.

**Fix:** Custom sqlmap proxy or `--eval`-based request builder that
bypasses sqlmap's JSON parsing. Alternatively, write a sqlmap
`--udf` injection module.

### Version detection on fresh installs
`detect_version()` probes `/wp-json/`, homepage meta tags, and RSS
feeds. On fresh Docker installs with no posts/pages, these often
return nothing. `/readme.html` is always present and contains the
version in plain text (`<h1>WordPress 6.9.4</h1>`) but is not
currently checked.

**Easy fix:** Add `readme.html` parsing to `detect_version()`.

### Fast extractor endpoint dependency
The fast X-WP-Total extraction mode embeds probes in `/wp/v2/categories`
requests. If the `categories` taxonomy is removed or the endpoint is
disabled, fast mode fails.

**Alternative endpoints found:** `/wp/v2/users`, `/wp/v2/pages`, and
`/wp/v2/media` all respond to GET and return `X-WP-Total`. The tool
could fall back to these if categories fails.

### Marker probe on 6.8.x
The marker probe uses `/wp/v2/block-renderer/core/archives` which does
not exist on WordPress 6.8.x, causing HTTP 500. The tool detects this
heuristic correctly but the detection could be more precise by checking
the route existence first.

## Testing Coverage

### Network configurations
All testing done against Docker containers on default bridge network
with `--link`. Not tested:
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
All tests on stock WordPress with no plugins and the default theme.
Not tested:
- Plugins that modify REST API behaviour (WooCommerce, Jetpack, etc.)
- Custom `author_exclude` sanitisation added by security plugins
- Multisite / network-mode WordPress
- Plugins that register Abilities API endpoints with weak permissions

## Documentation

### Password cracking guidance
The README mentions offline hash cracking but doesn't cover:
- Hash format conversion (`$wp$` phpass → hashcat mode 400)
- Recommended wordlists and rules
- GPU acceleration vs CPU-only cracking time estimates
