# php2shell-scanner

Non-destructive scanner (with opt-in probe) for **CVE-2026-109618** (RCE via
OOM corruption) and **CVE-2026-109619** (RCE via stale global state) — core
PHP bugs reportedly fixed in `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`.

> ⚠️ **UNVERIFIED ADVISORY.** As of 2026-10-21 these CVE IDs, the "php2shell"
> name, and the listed fixed versions are **not** corroborated on
> NVD / cve.org / OSV, and the fixed versions sit one patch *above* the real
> Sep-2026 PHP release (`8.2.34 / 8.3.35 / 8.4.26 / 8.5.11`). Treat every
> `VULNERABLE` verdict as **unverified** until the upstream PHP security
> advisory is published. Update the `FIXED` table when it lands.

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
| `--probe` | Multipart load probe — **DoS risk**, authorized only |
| `--probe-count N` | Number of probe requests (default 5) |
| `--threads N` / `--timeout N` | Concurrency / per-request timeout |
| `--insecure` | Do not validate TLS |
| `-o FILE` / `--csv FILE` | Save JSON / CSV report |

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
