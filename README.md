# php2shell-scanner

Non-destructive scanner (with opt-in probe) for **CVE-2026-109618** (RCE via
OOM corruption) and **CVE-2026-109619** (RCE via stale global state) — core
PHP bugs fixed in `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`.

> ✅ **Verified against the official php-src advisories (2026-10-21, Critical).**
> The CVE IDs and the fixed-version table below match upstream exactly.
>
> - CVE-2026-109618 — [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
> - CVE-2026-109619 — [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

### Affected / fixed versions

| Branch | Affected | Fixed |
|--------|----------|-------|
| 8.2 | < 8.2.35 | 8.2.35 |
| 8.3 | < 8.3.36 | 8.3.36 |
| 8.4 | < 8.4.27 | 8.4.27 |
| 8.5 | < 8.5.12 | 8.5.12 |
| < 8.2 | EOL — no upstream patch | check distro/OSV backport |

## Strategies

| Mode      | What it does |
|-----------|--------------|
| `LOCAL`   | `php -r` for exact runtime version, SAPI, `memory_limit`, `post_max_size` |
| `REMOTE`  | Version fingerprint via `X-Powered-By` / `Server` headers and exposed `phpinfo()` |
| `PRESENCE`| PHP detection without version (PHPSESSID, `.php` refs, redirects) |
| `BANNER`  | Robust raw-socket banner grab — HEAD/GET/OPTIONS + malformed probe, http/https, error-page disclosure |
| `RECON`   | Subdomain enumeration via **crt.sh** (Certificate Transparency) with **subfinder** fallback/merge, then fan-out scan resolving hosts |
| `PROBE`   | *(opt-in)* Large multipart requests to observe worker instability — **may cause DoS** |

## Install

```bash
git clone https://github.com/JoasASantos/php2shell-scanner.git
cd php2shell-scanner
# stdlib only — no pip deps.
# Optional recon fallback: ProjectDiscovery subfinder
#   brew install subfinder   (or: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
```

## Usage

```bash
# Local runtime check
python3 php2shell_scan.py --local

# Single remote target, look for exposed phpinfo()
python3 php2shell_scan.py https://example.com --phpinfo-paths

# Subdomain recon (crt.sh + subfinder) then scan, 10 threads, JSON out
python3 php2shell_scan.py example.com --recon --threads 10 -o out.json

# Recon only, no scanning
python3 php2shell_scan.py example.com --recon-only

# Target list + forced robust banner grab
python3 php2shell_scan.py -f targets.txt --banner

# OPT-IN load probe (authorized use only — DoS risk)
python3 php2shell_scan.py https://example.com --probe --probe-count 5
```

### Flags

| Flag | Meaning |
|------|---------|
| `--local` | Local scan via the `php` binary |
| `--recon` | Expand each domain into subdomains (crt.sh + subfinder), then scan resolving hosts |
| `--recon-only` | Enumerate subdomains only, no scanning |
| `--banner` | Force robust raw-socket banner grab on every target |
| `--phpinfo-paths` | Probe common exposed `phpinfo()` paths |
| `--deep-version` | Extra version techniques: PHP easter eggs + version-leak files (`composer.json`, `.env`, …) |
| `--origin-scan` | Reach the PHP origin behind Cloudflare/WAF — direct-to-IP request with the real Host header |
| `--probe` | Multipart load probe — **DoS risk**, authorized only |
| `--probe-count N` | Number of probe requests (default 5) |
| `--threads N` / `--timeout N` | Concurrency / per-request timeout |
| `--insecure` | Do not validate TLS |
| `-o FILE` / `--csv FILE` | Save JSON / CSV report |

## Passive enrichment (no exploitation)

Beyond the version check, each target is enriched with passive signals that
refine the verdict and cut false positives — all from normal responses, no
exploit attempt:

- **SAPI / worker model** — `fpm`, `mod_php`, `cgi`. Persistent workers reuse
  request state, so they are the ones exposed to **CVE-2026-109619** (stale
  global state); plain CGI is far less exposed.
- **CDN / WAF / proxy** (Cloudflare, Akamai, CloudFront, Fastly, Sucuri, …) —
  a banner may reflect the edge, not the PHP origin, so the version reading is
  flagged lower-confidence.
- **Distro-packaged build** (`ubuntu`, `+deb`, `.el8`, …) — distros backport
  fixes **without** bumping the upstream number, so a version-only match may be
  a false positive; verdict confidence is reduced with a "verify the changelog"
  note.
- **Deep phpinfo parse** (when exposed) — Server API, build date,
  `memory_limit` / `post_max_size` / `max_input_vars` (OOM surface for
  **CVE-2026-109618**), and `disable_functions` (mitigation).

### Extra version techniques (`--deep-version`)

When the version is not in a banner, the scanner also tries:

- **PHP easter eggs** — the classic `?=PHPE9568F34-...` query strings. On
  `expose_php=On` they return a characteristic GIF / credits page, confirming
  PHP (and sometimes a version) even when headers are stripped.
- **Version-leak files** — `composer.json` / `composer.lock` /
  `vendor/composer/installed.json` / `.env`. A `"php": ">=8.2"` constraint
  *narrows the branch* (declared requirement, not the live patch level); a
  `PHP_VERSION=8.3.1` in `.env` is treated as an exact version.

### Origin / WAF bypass (`--origin-scan`)

Cloudflare and similar WAFs hide the PHP origin, so a header read only reflects
the edge. With `--origin-scan` the scanner, using passive DNS only:

1. resolves the apex, `www`, and common non-proxied prefixes
   (`origin.*`, `cpanel.*`, `mail.*`, `dev.*`, …) plus any recon subdomains;
2. drops every IP inside the published **Cloudflare / Imperva / Sucuri** edge
   ranges (IPv4 **and** IPv6);
3. connects to each remaining **origin IP directly** with the real `Host`
   header and SNI, then banner-grabs — reading `Server` / `X-Powered-By` /
   error pages straight from the origin, bypassing the CDN.

No exploitation, no edge-evasion payloads — just a direct request to an IP the
DNS surface already exposed. Authorized targets only.

Each verdict carries a **confidence** grade:

| Confidence | Meaning |
|-----------|---------|
| `HIGH`   | version from exposed phpinfo() or a PHP error page |
| `MEDIUM` | version from an HTTP banner (`expose_php=On`) |
| `LOW`    | inference only, or behind a proxy, or a distro backport may apply |

The consolidated output groups targets by severity, sorts VULNERABLE by
confidence (HIGH first), and flags LOW/MEDIUM results to re-check before
reporting.

## Detection logic

Version comparison per branch against the `FIXED` table:

- `< fixed` on a supported branch → **VULNERABLE**
- `>= fixed` → **PATCHED**
- `< 8.2` (EOL) → **VULNERABLE_EOL** (no upstream patch; check distro/OSV backport)
- branch above advisory range or no version → **UNKNOWN** / **SUSPECTED**

## Authorization

Run only against assets you own or are **explicitly permitted** to test. The
`--probe` mode can disrupt fragile workers. You are responsible for your use.

## License

MIT
