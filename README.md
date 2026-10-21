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
| `--shodan-key` | Shodan API key for origin intel (or env `SHODAN_API_KEY`); implies `--origin-scan` |
| `--censys-id` / `--censys-secret` | Censys API creds (or env `CENSYS_API_ID` / `CENSYS_API_SECRET`); imply `--origin-scan` |
| `--probe` | Multipart load probe — **DoS risk**, authorized only |
| `--probe-count N` | Number of probe requests (default 5) |
| `--threads N` / `--timeout N` | Concurrency / per-request timeout |
| `--insecure` | Do not validate TLS |
| `-o FILE` / `--csv FILE` | Save JSON / CSV report |

## Passive enrichment

Beyond the version check, each target is enriched with passive signals (from
normal responses) that refine the verdict and cut false positives:

- **SAPI / worker model** — persistent workers (`fpm`, `mod_php`) reuse request
  state → exposed to **CVE-2026-109619**; plain `cgi` far less.
- **CDN / WAF / proxy** (Cloudflare, Akamai, Fastly, Sucuri…) — banner may be
  the edge, not the origin → confidence lowered.
- **Distro build** (`ubuntu`, `+deb`, `.el8`…) — backport may fix without a
  version bump → confidence lowered, "verify the changelog" note.
- **Deep phpinfo** (when exposed) — Server API, `post_max_size` /
  `max_input_vars` (OOM surface for **CVE-2026-109618**), `disable_functions`.

### More version techniques (`--deep-version`)

When no banner version: **PHP easter eggs** (`?=PHPE9568F34-...` → GIF/credits
on `expose_php=On`) and **version-leak files** (`composer.json`, `.env`, …;
`.env` `PHP_VERSION` = exact, a `"php": ">=8.2"` constraint only narrows branch).

### Origin / WAF bypass (`--origin-scan`)

CDNs hide the origin, so a header read only shows the edge. `--origin-scan`:

1. resolves apex, `www`, non-proxied prefixes (`origin.*`, `cpanel.*`, `mail.*`…)
   and recon subdomains;
2. drops IPs in **Cloudflare / Imperva / Sucuri** edge ranges (IPv4 + IPv6);
3. requests each remaining **origin IP directly** with the real `Host` + SNI,
   reading `Server` / `X-Powered-By` / error pages straight from the origin.

A direct request to an already-exposed IP. Authorized targets only.

Credentialed intel adds IPs DNS never exposes, plus a PHP version from the
indexed banner (flagged intel — may be stale):

- `--shodan-key` / env `SHODAN_API_KEY` — hosts by `hostname:<domain>`.
- `--censys-id` + `--censys-secret` / env `CENSYS_API_ID` + `CENSYS_API_SECRET`
  — hosts by TLS-cert / DNS name.
- Any credential auto-enables `--origin-scan`.

```bash
export SHODAN_API_KEY=xxx CENSYS_API_ID=xxx CENSYS_API_SECRET=xxx
python3 php2shell_scan.py hackersec.com --origin-scan
```

### Confidence grade

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
