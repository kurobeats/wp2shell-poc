# Known Gaps

## Exploitation

### ~~Pre-auth RCE without FILE privilege~~ **RESOLVED**

Implemented as `--escalate` mode (sergiointel PoC integration). Full chain:
**route confusion → SQLi → oEmbed cache poisoning → UNION SELECT post recast
→ changeset escalation → admin creation → plugin upload → RCE**

No FILE privilege. No password cracking. No credentials.

Tested on all 6 available Docker Hub images (6.9.0, 6.9.1, 6.9.2, 6.9.4, 7.0.0, 7.0.1):
100% RCE.

#### Original Assetnote chain (recursive REST dispatch)

The 6.9.5 / 7.0.2 patch adds `is_dispatching()` guards in both `serve_request()`
and `rest_api_loaded()`, indicating the discoverer's original chain relied on
recursive REST dispatch. This path remains **not publicly disclosed** — the
`--escalate` chain is an independent technique (oEmbed poisoning + UNION SELECT
post recast), not the recursive-dispatch path.

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
and a `permission_callback` that returns `true` could provide pre-auth RCE via
the abilities `/run` endpoint. The endpoint itself has no hardcoded auth — it
delegates entirely to the ability's `permission_callback`.

**Researched:** `WP_Ability::check_permissions()` returns `WP_Error` when
`permission_callback` is not callable (missing/null). It does NOT default to
`true`. Stock WordPress is secure — this is only exploitable via a vulnerable
plugin that explicitly sets `permission_callback` to return `true`.

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


