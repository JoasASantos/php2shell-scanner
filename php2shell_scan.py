#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_scan.py — Non-destructive scanner (with opt-in probe) for
CVE-2026-109618 (RCE via OOM corruption — longjmp on OOM leaves invalid
request memory at shutdown) and CVE-2026-109619 (RCE via stale global
state — global state from a previous request reused by a persistent
worker). Core PHP bugs, fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

Official advisories (published 2026-10-21, Critical, by bukka):
  CVE-2026-109618 — GHSA-w8hw-w9fx-j79w
    https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
  CVE-2026-109619 — GHSA-6wmf-4rv5-p3rp
    https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
Fixed-version table below matches the advisories exactly (verified 2026-10-21).

Strategies:
  1. LOCAL    : php -v / php -i (max precision — exact runtime version).
  2. REMOTE   : version fingerprint via headers (X-Powered-By, Server) and
                exposed phpinfo() files (phpinfo.php, info.php, ...).
  3. PRESENCE : PHP detection without version (PHPSESSID, .php, redirects).
  4. BANNER   : robust banner grabbing — raw socket HEAD/GET/OPTIONS across
                http/https, all header variants, error-page disclosure.
  5. RECON    : subdomain enumeration via crt.sh (Certificate Transparency),
                with ProjectDiscovery subfinder as fallback/merge source,
                then fan-out scan each resolved host.
  6. PROBE    : (--probe) large multipart requests to observe worker
                instability. Low-confidence heuristic; MAY cause DoS in
                production. Authorized use only.

Usage:
  python3 php2shell_scan.py --local
  python3 php2shell_scan.py https://example.com --phpinfo-paths
  python3 php2shell_scan.py example.com --recon --threads 10 -o out.json
  python3 php2shell_scan.py -f targets.txt --banner
  python3 php2shell_scan.py https://example.com --probe --probe-count 5

Authorization: run only against assets you own or are explicitly
permitted to test.
"""

import argparse
import concurrent.futures
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# Vulnerability data (GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp, 2026-10-21)
# ---------------------------------------------------------------------------
CVES = {
    "CVE-2026-109618": "RCE via OOM corruption (longjmp on OOM leaves invalid request memory at shutdown)",
    "CVE-2026-109619": "RCE via stale global state (prior-request global state reused by a persistent worker)",
}

# Official advisory references (verified against php-src 2026-10-21)
ADVISORIES = {
    "CVE-2026-109618": "GHSA-w8hw-w9fx-j79w",
    "CVE-2026-109619": "GHSA-6wmf-4rv5-p3rp",
}

# Minimum FIXED version per branch (matches both advisories exactly)
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
SUPPORTED_BRANCHES = sorted(FIXED)          # 8.2..8.5
EOL_CEILING = (8, 2, 0)                     # < 8.2 => EOL, no official patch
FIRST_REPORTED = (5, 4, 0)                  # reports: PHP >= 5.4 affected

UA = "php2shell-scan/2.0 (authorized-security-assessment)"

print_lock = threading.Lock()


def say(msg):
    with print_lock:
        print(msg, flush=True)


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------
def parse_version(s):
    """'8.3.14' -> (8,3,14). '8.1' -> (8,1,0). None if non-numeric."""
    if not s:
        return None
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def version_tuple(vstr):
    return parse_version(vstr)


def classify(version):
    """
    Return a dict with a per-CVE verdict for a PHP version.
    verdicts: VULNERABLE / PATCHED / VULNERABLE_EOL / UNKNOWN
    """
    out = {
        "version": version,
        "status": None,
        "detail": "",
        "cves": {},
    }
    if version is None:
        out["status"] = "UNKNOWN"
        out["detail"] = "PHP detected, version not disclosed"
        for c in CVES:
            out["cves"][c] = "SUSPECTED (no version)"
        return out

    t = version_tuple(version)
    if t is None:
        out["status"] = "UNKNOWN"
        for c in CVES:
            out["cves"][c] = "UNKNOWN"
        return out

    major, minor, patch = t
    branch = (major, minor)

    if major < 8 or (major == 8 and minor < 2):
        out["status"] = "VULNERABLE_EOL"
        out["detail"] = (
            "PHP %s is EOL (< 8.2) — no official PHP Group patch; "
            "check distro/OSV backport" % version
        )
        for c in CVES:
            out["cves"][c] = "VULNERABLE (EOL, no upstream fix)"
        return out

    if branch in FIXED:
        fixed = FIXED[branch]
        if t < fixed:
            out["status"] = "VULNERABLE"
            out["detail"] = "PHP %s < fixed %s" % (version, ".".join(map(str, fixed)))
            for c in CVES:
                out["cves"][c] = "VULNERABLE"
        else:
            out["status"] = "PATCHED"
            out["detail"] = "PHP %s >= fixed %s" % (version, ".".join(map(str, fixed)))
            for c in CVES:
                out["cves"][c] = "PATCHED"
        return out

    if branch > SUPPORTED_BRANCHES[-1]:
        out["status"] = "UNKNOWN"
        out["detail"] = "Branch %d.%d above advisory range — check vendor changelog" % (major, minor)
        for c in CVES:
            out["cves"][c] = "UNKNOWN"
        return out

    # 8.6+ handled above; 5.x/7.x handled above. Extra safety:
    out["status"] = "UNKNOWN"
    for c in CVES:
        out["cves"][c] = "UNKNOWN"
    return out


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def make_opener(insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(),
    )
    return opener


def http_get(opener, url, timeout=10, max_bytes=200_000, method="GET"):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Connection": "close",
    }, method=method)
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(max_bytes)
        headers = dict(resp.headers.items())
        return {"status": resp.status, "headers": headers, "body": body.decode("utf-8", "replace"), "url": resp.geturl()}
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(20_000)
        except Exception:
            pass
        return {"status": e.code, "headers": dict(e.headers.items()) if e.headers else {}, "body": body.decode("utf-8", "replace"), "url": url}
    except Exception as e:
        return {"status": None, "error": str(e), "url": url}


# ---------------------------------------------------------------------------
# Remote version fingerprint
# ---------------------------------------------------------------------------
VER_PATTERNS = [
    # X-Powered-By: PHP/8.3.14
    re.compile(r"PHP[/ ](\d+\.\d+(?:\.\d+)?)", re.I),
    # Server: Apache/2.4.58 (Unix) PHP/8.2.20
    re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I),
]
PHPINFO_PATTERNS = [
    re.compile(r"PHP Version\s*</?b?[^>]*>?\s*([578]\.\d+\.\d+)"),
    re.compile(r"php-version[^0-9]*([578]\.\d+\.\d+)", re.I),
    re.compile(r"PHP Version ([578]\.\d+\.\d+)"),
]

DEFAULT_PHPINFO_PATHS = [
    "/phpinfo.php", "/phpinfo().php", "/info.php", "/php_info.php",
    "/test.php", "/p.php", "/pi.php", "/phpversion.php", "/version.php",
    "/server-info.php", "/phpinfo.txt",
]


def fingerprint_headers(res):
    """Return (version, source) from a response's headers."""
    for h in ("x-powered-by", "server", "x-php-version"):
        val = None
        for k, v in res.get("headers", {}).items():
            if k.lower() == h:
                val = v
                break
        if not val:
            continue
        for pat in VER_PATTERNS:
            m = pat.search(val)
            if m:
                return m.group(1), "header:%s" % h
    return None, None


def fingerprint_phpinfo(opener, base, paths):
    """Look for exposed phpinfo(); return (version, path) or (None, None)."""
    for p in paths:
        url = urllib.parse.urljoin(base + "/", p.lstrip("/"))
        res = http_get(opener, url)
        if res.get("status") == 200 and res.get("body"):
            body = res["body"]
            if "phpinfo()" in body or "PHP Version" in body or "php-core" in body:
                for pat in PHPINFO_PATTERNS:
                    m = pat.search(body)
                    if m:
                        return m.group(1), p
    return None, None


def detect_php_presence(opener, base):
    """Heuristics for PHP presence without version disclosure."""
    signals = []
    res = http_get(opener, base + "/")
    if res.get("status") is None:
        return signals, res
    hdrs = {k.lower(): v for k, v in res.get("headers", {}).items()}
    cookie = hdrs.get("set-cookie", "")
    if "PHPSESSID" in cookie:
        signals.append("cookie:PHPSESSID")
    if "x-powered-by" in hdrs and "php" in hdrs["x-powered-by"].lower():
        signals.append("header:X-Powered-By")
    body = res.get("body", "")
    if ".php" in body:
        signals.append("body:.php refs")
    # redirect to index.php is a classic PHP-app tell
    loc = hdrs.get("location", "")
    if loc.endswith(".php"):
        signals.append("redirect:%s" % loc)
    # 404 page of WordPress/Drupal etc.
    if "wp-content" in body:
        signals.append("body:wp-content")
    return signals, res


# ---------------------------------------------------------------------------
# Robust PHP banner grabbing
# ---------------------------------------------------------------------------
# Headers that may carry a PHP version string.
PHP_HINT_HEADERS = (
    "server", "x-powered-by", "x-php-version",
    "x-generator", "x-drupal-cache", "x-redirect-by",
)
# Only these headers count as a "PHP present" signal when they mention php
# (avoids false positives from a 'php' substring inside a URL, e.g. Link).
PHP_SIGNAL_HEADERS = ("server", "x-powered-by", "x-php-version")
# Error strings PHP/SAPI stacks tend to emit on malformed input.
PHP_ERROR_MARKERS = [
    re.compile(r"\bPHP (?:Notice|Warning|Fatal error|Parse error|Deprecated)\b", re.I),
    re.compile(r"Call Stack", re.I),
    re.compile(r"on line \d+", re.I),
    re.compile(r"Xdebug", re.I),
    re.compile(r"\.php on line", re.I),
]


def _raw_http(host, port, use_tls, request_line, extra_headers, insecure, timeout=8, read_bytes=65536):
    """
    Single raw-socket HTTP exchange. Returns (status_line, headers_dict,
    body_text, error). Keeps the full raw header block so odd casing /
    duplicate headers survive (urllib folds those).
    """
    raw_headers = {}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        hdr_lines = ["%s HTTP/1.1" % request_line,
                     "Host: %s" % host,
                     "User-Agent: %s" % UA,
                     "Accept: */*",
                     "Connection: close"]
        hdr_lines += list(extra_headers)
        payload = ("\r\n".join(hdr_lines) + "\r\n\r\n").encode()
        sock.sendall(payload)
        chunks = []
        got = 0
        while got < read_bytes:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
            got += len(data)
        raw = b"".join(chunks)
    except Exception as e:
        return None, {}, "", str(e)
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    text = raw.decode("iso-8859-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            v = v.strip()
            # keep multiple Set-Cookie etc.
            if k in raw_headers:
                raw_headers[k] += "; " + v
            else:
                raw_headers[k] = v
    return status_line, raw_headers, body, None


def banner_grab(host, insecure=False, timeout=8):
    """
    Robust multi-probe banner grab. Tries https:443 and http:80, with
    HEAD / GET / OPTIONS and a deliberately malformed request, to surface:
      - Server / X-Powered-By version banners (even when urllib hides them),
      - PHPSESSID and other PHP-tell headers,
      - PHP error disclosure on malformed input.
    Returns a dict: {version, version_source, php_signals, probes:[...]}.
    Non-destructive: tiny requests only.
    """
    result = {"version": None, "version_source": None, "php_signals": [], "probes": []}
    schemes = [("https", 443, True), ("http", 80, False)]
    # request_line, extra_headers, label
    probes = [
        ("HEAD / HTTP/1.1".replace(" HTTP/1.1", ""), [], "HEAD /"),
        ("GET / HTTP/1.1".replace(" HTTP/1.1", ""), [], "GET /"),
        ("OPTIONS / HTTP/1.1".replace(" HTTP/1.1", ""), [], "OPTIONS /"),
        # malformed path to coax an error page from the SAPI
        ("GET /%ff%fe/..%00.php HTTP/1.1".replace(" HTTP/1.1", ""),
         ["X-Probe: malformed"], "GET malformed"),
    ]

    for scheme, port, use_tls in schemes:
        reachable = False
        for request_line, extra, label in probes:
            status, hdrs, body, err = _raw_http(
                host, port, use_tls, request_line, extra, insecure, timeout=timeout)
            probe_rec = {"scheme": scheme, "probe": label, "status": None, "error": err}
            if err:
                result["probes"].append(probe_rec)
                continue
            reachable = True
            probe_rec["status"] = status
            # header-based version
            for h in PHP_HINT_HEADERS:
                if h in hdrs:
                    val = hdrs[h]
                    for pat in VER_PATTERNS:
                        m = pat.search(val)
                        if m and not result["version"]:
                            result["version"] = m.group(1)
                            result["version_source"] = "banner:%s:%s" % (scheme, h)
                    if h in PHP_SIGNAL_HEADERS and "php" in val.lower():
                        sig = "header:%s=%s" % (h, val[:80])
                        if sig not in result["php_signals"]:
                            result["php_signals"].append(sig)
            if "set-cookie" in hdrs and "PHPSESSID" in hdrs["set-cookie"]:
                if "cookie:PHPSESSID" not in result["php_signals"]:
                    result["php_signals"].append("cookie:PHPSESSID")
            # error-page disclosure
            if body:
                for pat in PHP_ERROR_MARKERS:
                    m = pat.search(body)
                    if m:
                        snip = "error:%s" % m.group(0)
                        if snip not in result["php_signals"]:
                            result["php_signals"].append(snip)
                        # grab a version from the error page if present
                        if not result["version"]:
                            vm = re.search(r"PHP/?(\d+\.\d+\.\d+)", body)
                            if vm:
                                result["version"] = vm.group(1)
                                result["version_source"] = "banner:%s:errorpage" % scheme
                        break
            probe_rec["server"] = hdrs.get("server")
            probe_rec["x_powered_by"] = hdrs.get("x-powered-by")
            # skip duplicate probe records (same scheme/server/x-powered-by)
            key = (probe_rec["scheme"], probe_rec.get("server"), probe_rec.get("x_powered_by"))
            if key not in {(p["scheme"], p.get("server"), p.get("x_powered_by")) for p in result["probes"]}:
                result["probes"].append(probe_rec)
            # once we have a version from headers, no need to hammer more probes
            if result["version"] and label != "GET malformed":
                break
        if reachable and result["version"]:
            break
    return result


# ---------------------------------------------------------------------------
# Subdomain recon via crt.sh (Certificate Transparency)
# ---------------------------------------------------------------------------
def crtsh_subdomains(domain, timeout=25, insecure=False):
    """
    Query crt.sh Certificate Transparency logs for subdomains of `domain`.
    Returns a sorted list of unique hostnames (wildcards stripped).
    Passive recon: no traffic to the target itself.
    """
    domain = domain.strip().lower().lstrip(".")
    # strip scheme/path if a URL was passed
    if "://" in domain:
        domain = urllib.parse.urlparse(domain if "//" in domain else "//" + domain).netloc
    domain = domain.split("/")[0].split(":")[0]
    found = set()
    url = "https://crt.sh/?q=%s&output=json" % urllib.parse.quote("%." + domain)
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    data = None
    last_err = None
    # crt.sh frequently returns 502/timeout under load — retry a few times.
    for attempt in range(4):
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            data = resp.read()
            break
        except Exception as e:
            last_err = e
            time.sleep(2 * (attempt + 1))
    if data is None:
        return [], "crt.sh error after retries: %s" % last_err
    try:
        rows = json.loads(data.decode("utf-8", "replace"))
    except Exception:
        # crt.sh sometimes returns concatenated JSON objects; normalize
        txt = data.decode("utf-8", "replace").strip()
        try:
            rows = json.loads("[" + txt.replace("}\n{", "},{") + "]")
        except Exception as e:
            return [], "crt.sh parse error: %s" % e
    for row in rows:
        name = (row.get("name_value") or "") + "\n" + (row.get("common_name") or "")
        for n in name.split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and n.endswith(domain) and all(ch.isprintable() for ch in n):
                found.add(n)
    return sorted(found), None


def _normalize_domain(domain):
    domain = domain.strip().lower().lstrip(".")
    if "://" in domain:
        domain = urllib.parse.urlparse(domain if "//" in domain else "//" + domain).netloc
    return domain.split("/")[0].split(":")[0]


def subfinder_subdomains(domain, timeout=120):
    """
    Fallback enumeration via ProjectDiscovery subfinder (passive).
    Returns (sorted_hosts, error). error is set if subfinder is missing or
    fails; an empty list with no error means subfinder ran but found none.
    """
    domain = _normalize_domain(domain)
    if not shutil.which("subfinder"):
        return [], "subfinder not installed"
    try:
        p = subprocess.run(
            ["subfinder", "-silent", "-all", "-d", domain],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], "subfinder timeout"
    except Exception as e:
        return [], "subfinder error: %s" % e
    if p.returncode != 0 and not p.stdout.strip():
        return [], "subfinder exit %s: %s" % (p.returncode, (p.stderr or "").strip()[:200])
    found = set()
    for line in p.stdout.splitlines():
        n = line.strip().lower().lstrip("*.")
        if n and n.endswith(domain) and all(ch.isprintable() for ch in n):
            found.add(n)
    return sorted(found), None


def enumerate_subdomains(domain, insecure=False):
    """
    Enumerate subdomains: crt.sh first, subfinder as fallback.
    If crt.sh succeeds, subfinder still runs and results are merged (union)
    when available — broader coverage, fallback-safe when crt.sh is down.
    Returns (sorted_hosts, sources_used:list, note:str|None).
    """
    hosts = set()
    sources = []
    note = None
    subs, err = crtsh_subdomains(domain, insecure=insecure)
    if err:
        note = err
    else:
        sources.append("crt.sh")
        hosts.update(subs)
    # subfinder: fallback when crt.sh failed, or as a merge source otherwise
    sf, sf_err = subfinder_subdomains(domain)
    if sf_err:
        if note:
            note += " | subfinder: %s" % sf_err
    else:
        sources.append("subfinder")
        hosts.update(sf)
    return sorted(hosts), sources, note


def resolves(host):
    """True if host resolves to an A/AAAA record."""
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Behavior probe (OPT-IN — may cause DoS)
# ---------------------------------------------------------------------------
def build_multipart_payload(n_parts=1500, part_size=4096):
    """
    multipart/form-data with many parts -> memory pressure in the parser.
    Vector cited in the advisory (CVE-2026-109618): multipart that reaches
    OOM within PHP's apparent limits.
    """
    boundary = "----php2shellProbe"
    lines = []
    for i in range(n_parts):
        lines.append("--" + boundary)
        lines.append('Content-Disposition: form-data; name="field_%d"' % i)
        lines.append("Content-Type: text/plain")
        lines.append("")
        lines.append("A" * part_size)
    lines.append("--" + boundary + "--")
    lines.append("")
    return ("\r\n".join(lines)).encode(), boundary


def probe_request(opener, url, timeout=25):
    """Huge multipart POST; returns (status, elapsed, error)."""
    payload, boundary = build_multipart_payload()
    req = urllib.request.Request(url, data=payload, headers={
        "User-Agent": UA,
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "Connection": "close",
        "Expect": "",
    }, method="POST")
    t0 = time.time()
    try:
        resp = opener.open(req, timeout=timeout)
        resp.read(10_000)
        return resp.status, time.time() - t0, None
    except urllib.error.HTTPError as e:
        return e.code, time.time() - t0, None
    except Exception as e:
        return None, time.time() - t0, str(e)


def run_probe(opener, base, count=5):
    """
    Heuristic: baseline GET ok + N large multipart POSTs.
    If 5xx/timeouts/refused connections appear that the baseline did not
    show, mark SUSPECTED. Does NOT confirm RCE — only flags instability.
    """
    results = []
    target = base.rstrip("/") + "/"
    b = http_get(opener, target)
    baseline_ok = b.get("status") is not None and b.get("status") < 500

    for i in range(count):
        st, el, err = probe_request(opener, target)
        results.append({"iter": i + 1, "status": st, "elapsed": round(el, 2), "error": err})
        time.sleep(1.0)  # rate-limit: 1 req/s

    anomalies = [r for r in results if r["status"] is None or (r["status"] and r["status"] >= 500)]
    verdict = "NO_ANOMALY"
    if baseline_ok and len(anomalies) >= max(1, count // 2):
        verdict = "SUSPECTED (instability under multipart load — worker may have restarted)"
    elif anomalies:
        verdict = "INCONCLUSIVE (%d/%d anomalous responses)" % (len(anomalies), count)
    return {"verdict": verdict, "baseline_ok": baseline_ok, "iterations": results}


# ---------------------------------------------------------------------------
# Local scan
# ---------------------------------------------------------------------------
def scan_local(php_bin="php"):
    out = {"mode": "local", "php_bin": php_bin}
    path = shutil.which(php_bin)
    if not path:
        out["error"] = "php binary not found in PATH"
        return out
    try:
        v = subprocess.run([php_bin, "-r", "echo PHP_VERSION;"], capture_output=True, text=True, timeout=10)
        version = v.stdout.strip()
        out["php_version"] = version or None
        try:
            si = subprocess.run([php_bin, "-r", "echo php_sapi_name().'|'.@(ini_get('memory_limit')).'|'.@(ini_get('post_max_size'));"],
                                capture_output=True, text=True, timeout=10)
            parts = si.stdout.strip().split("|")
            if len(parts) == 3:
                out["sapi"] = parts[0]
                out["memory_limit"] = parts[1]
                out["post_max_size"] = parts[2]
        except Exception:
            pass
    except Exception as e:
        out["error"] = str(e)
        return out
    return out


# ---------------------------------------------------------------------------
# Scan one remote target
# ---------------------------------------------------------------------------
@dataclass
class TargetResult:
    target: str
    php_detected: bool = False
    version: str = None
    version_source: str = None
    status: str = None
    detail: str = ""
    cves: dict = field(default_factory=dict)
    presence_signals: list = field(default_factory=list)
    banner: dict = None
    probe: dict = None
    error: str = None


def scan_target(target, opts):
    r = TargetResult(target=target)
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https"):
        target = "http://" + target
        parsed = urllib.parse.urlparse(target)
    base = "%s://%s" % (parsed.scheme, parsed.netloc)
    host = parsed.hostname

    opener = make_opener(insecure=opts.insecure)

    # 1) root-page headers
    root = http_get(opener, base + "/")
    if root.get("status") is None:
        # try without trailing slash
        alt = http_get(opener, base)
        if alt.get("status") is None:
            r.error = "unreachable: %s" % alt.get("error")
            return r
        root = alt

    ver, src = fingerprint_headers(root)
    if ver:
        r.php_detected, r.version, r.version_source = True, ver, src
    r.presence_signals += [s for s in detect_php_signals(root)]

    # 2) presence fingerprint if no version
    if not r.php_detected:
        sigs, _ = detect_php_presence(opener, base)
        if sigs:
            r.php_detected = True
            r.presence_signals += sigs

    # 3) robust banner grab (always, unless disabled) — fills gaps urllib misses
    if opts.banner or not r.version:
        b = banner_grab(host, insecure=opts.insecure, timeout=opts.timeout)
        r.banner = b
        if b.get("php_signals"):
            r.php_detected = True
            for s in b["php_signals"]:
                if s not in r.presence_signals:
                    r.presence_signals.append(s)
        if b.get("version") and not r.version:
            r.php_detected, r.version, r.version_source = True, b["version"], b["version_source"]

    # 4) exposed phpinfo
    if opts.phpinfo_paths and (not r.version):
        ver, p = fingerprint_phpinfo(opener, base, DEFAULT_PHPINFO_PATHS)
        if ver:
            r.php_detected, r.version, r.version_source = True, ver, "phpinfo:%s" % p

    # 5) classification
    if r.php_detected:
        c = classify(r.version)
        r.status = c["status"]
        r.detail = c["detail"]
        r.cves = c["cves"]
    else:
        r.status = "NO_PHP_DETECTED"
        r.detail = "no PHP signal on the HTTP surface"

    # 6) opt-in probe
    if opts.probe and r.php_detected:
        r.probe = run_probe(opener, base, count=opts.probe_count)

    return r


def detect_php_signals(res):
    out = []
    hdrs = {k.lower(): v for k, v in res.get("headers", {}).items()}
    if "x-powered-by" in hdrs and "php" in hdrs["x-powered-by"].lower():
        out.append("header:X-Powered-By")
    if "PHPSESSID" in hdrs.get("set-cookie", ""):
        out.append("cookie:PHPSESSID")
    return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def fmt_result(r):
    lines = []
    lines.append("─" * 62)
    lines.append("TARGET: %s" % r.target)
    if r.error:
        lines.append("  ERROR: %s" % r.error)
        return "\n".join(lines)
    lines.append("  PHP detected  : %s" % ("YES" if r.php_detected else "NO"))
    if r.version:
        lines.append("  Version       : %s  (source: %s)" % (r.version, r.version_source))
    if r.presence_signals:
        lines.append("  Signals       : %s" % ", ".join(r.presence_signals))
    lines.append("  STATUS        : %s" % (r.status or "-"))
    if r.detail:
        lines.append("  Detail        : %s" % r.detail)
    for cve, desc in CVES.items():
        v = (r.cves or {}).get(cve, "-")
        ghsa = ADVISORIES.get(cve, "")
        lines.append("    %s (%s) [%s] -> %s" % (cve, ghsa, desc.split("(")[0].strip(), v))
    if r.banner and r.banner.get("probes"):
        srv = next((p.get("server") for p in r.banner["probes"] if p.get("server")), None)
        xpb = next((p.get("x_powered_by") for p in r.banner["probes"] if p.get("x_powered_by")), None)
        if srv or xpb:
            lines.append("  BANNER        : Server=%s X-Powered-By=%s" % (srv, xpb))
    if r.probe:
        lines.append("  PROBE         : %s" % r.probe["verdict"])
        for it in r.probe["iterations"]:
            lines.append("    #%d status=%s elapsed=%ss %s" % (
                it["iter"], it["status"], it["elapsed"], ("err=" + it["error"]) if it["error"] else ""))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="php2shell scanner (CVE-2026-109618 / CVE-2026-109619)")
    ap.add_argument("targets", nargs="*", help="URLs/hosts to test")
    ap.add_argument("-f", "--file", help="file with one target per line")
    ap.add_argument("--local", action="store_true", help="local scan via the php binary")
    ap.add_argument("--recon", action="store_true", help="expand each target domain into subdomains via crt.sh, then scan the ones that resolve")
    ap.add_argument("--recon-only", action="store_true", help="only enumerate subdomains (crt.sh), do not scan")
    ap.add_argument("--banner", action="store_true", help="force robust raw-socket banner grab on every target")
    ap.add_argument("--phpinfo-paths", action="store_true", help="look for exposed phpinfo() (more requests)")
    ap.add_argument("--probe", action="store_true", help="WARNING: multipart load probe (may cause DoS; authorized use only)")
    ap.add_argument("--probe-count", type=int, default=5, help="number of probe requests (default 5)")
    ap.add_argument("--threads", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--insecure", action="store_true", help="do not validate TLS")
    ap.add_argument("-o", "--output", help="save JSON to path")
    ap.add_argument("--csv", help="save CSV to path")
    opts = ap.parse_args()

    targets = list(opts.targets)
    if opts.file:
        with open(opts.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]

    if opts.local:
        loc = scan_local()
        if "error" in loc:
            say("[local] %s" % loc["error"])
        else:
            c = classify(loc.get("php_version"))
            say("[local] php=%s sapi=%s memory_limit=%s post_max_size=%s" % (
                loc.get("php_version"), loc.get("sapi"), loc.get("memory_limit"), loc.get("post_max_size")))
            say("[local] STATUS: %s — %s" % (c["status"], c["detail"]))
            for k, v in c["cves"].items():
                say("  %s -> %s" % (k, v))
            loc["classification"] = c
        if not targets:
            if opts.output:
                with open(opts.output, "w") as fh:
                    json.dump([loc], fh, indent=2)
            return 0 if ("error" in loc or loc["classification"]["status"] != "VULNERABLE") else 1

    # --- subdomain recon via crt.sh ---
    if opts.recon or opts.recon_only:
        expanded = []
        seen = set(targets)
        for t in list(targets):
            subs, sources, note = enumerate_subdomains(t, insecure=opts.insecure)
            if note:
                say("[recon] %s: %s" % (t, note))
            if not subs:
                say("[recon] %s: no subdomains (sources tried: crt.sh, subfinder)" % t)
                continue
            say("[recon] %s: %d subdomain(s) via %s" % (t, len(subs), "+".join(sources) or "none"))
            for s in subs:
                if s in seen:
                    continue
                seen.add(s)
                if resolves(s):
                    expanded.append(s)
                    say("   + %s (resolves)" % s)
                else:
                    say("   - %s (no DNS)" % s)
        if opts.recon_only:
            if opts.output:
                with open(opts.output, "w") as fh:
                    json.dump({"recon_only": True, "hosts": sorted(seen)}, fh, indent=2)
            say("[recon] %d host(s) total" % len(seen))
            return 0
        targets += expanded

    if opts.probe:
        say("[!] PROBE active: sending multipart load. DoS risk on fragile workers. Confirm you are authorized.")
        time.sleep(3)

    if not targets:
        ap.print_help()
        return 2

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts.threads) as ex:
        futs = {ex.submit(scan_target, t, opts): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            results.append(r)
            say(fmt_result(r))

    # summary
    say("─" * 62)
    counts = {}
    for r in results:
        counts[r.status or "ERROR"] = counts.get(r.status or "ERROR", 0) + 1
    say("SUMMARY: %d target(s) — %s" % (len(results), ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    vulns = [r for r in results if r.status in ("VULNERABLE", "VULNERABLE_EOL")]
    if vulns:
        say("VULNERABLE TARGETS (CVE-2026-109618/109619):")
        for r in vulns:
            say("  %s  (%s)" % (r.target, r.version or "no version"))

    if opts.output:
        with open(opts.output, "w") as fh:
            json.dump([asdict(r) for r in results], fh, indent=2, default=str)
        say("JSON saved to %s" % opts.output)
    if opts.csv:
        import csv as _csv
        with open(opts.csv, "w", newline="") as fh:
            w = _csv.writer(fh)
            w.writerow(["target", "php_detected", "version", "source", "status", "cve-2026-109618", "cve-2026-109619", "detail", "error"])
            for r in results:
                w.writerow([r.target, r.php_detected, r.version, r.version_source, r.status,
                            (r.cves or {}).get("CVE-2026-109618", ""), (r.cves or {}).get("CVE-2026-109619", ""),
                            r.detail, r.error])
        say("CSV saved to %s" % opts.csv)

    return 1 if vulns else 0


if __name__ == "__main__":
    sys.exit(main())
