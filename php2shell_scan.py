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
  python3 php2shell_scan.py example.com --deep-version --origin-scan
  python3 php2shell_scan.py https://example.com --probe --probe-count 5

Authorization: run only against assets you own or are explicitly
permitted to test.
"""

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import os
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
    """Look for exposed phpinfo(); return (version, path, body) or (None, None, None)."""
    for p in paths:
        url = urllib.parse.urljoin(base + "/", p.lstrip("/"))
        res = http_get(opener, url)
        if res.get("status") == 200 and res.get("body"):
            body = res["body"]
            if "phpinfo()" in body or "PHP Version" in body or "php-core" in body:
                for pat in PHPINFO_PATTERNS:
                    m = pat.search(body)
                    if m:
                        return m.group(1), p, body
    return None, None, None


# ---------------------------------------------------------------------------
# Passive enrichment — extra signals to judge exposure WITHOUT exploitation
# ---------------------------------------------------------------------------
# Persistent-worker SAPIs reuse request state across requests => directly
# relevant to CVE-2026-109619 (stale global state). Per-request SAPIs (plain
# CGI) spin a fresh process per request and are far less exposed to it.
PERSISTENT_SAPIS = ("fpm", "fpm-fcgi", "apache2handler", "mod_php", "litespeed", "phpdbg", "cli-server")
PERREQUEST_SAPIS = ("cgi", "cgi-fcgi")

PROXY_MARKERS = [
    ("Cloudflare", ("server:cloudflare", "cf-ray", "cf-cache-status")),
    ("Akamai", ("server:akamaighost", "x-akamai", "akamai")),
    ("AWS CloudFront", ("x-amz-cf-id", "via:cloudfront", "server:cloudfront")),
    ("Fastly", ("x-served-by", "x-fastly", "fastly")),
    ("Sucuri WAF", ("x-sucuri-id", "server:sucuri")),
    ("Imperva/Incapsula", ("x-iinfo", "incap_ses", "visid_incap")),
    ("Varnish", ("x-varnish", "via:varnish")),
    ("nginx proxy", ("via:nginx",)),
]
# Distro build suffixes: version looks upstream-vulnerable but the distro may
# have backported the fix without bumping the upstream number => reduce
# confidence, do not report a hard VULNERABLE from version alone.
DISTRO_RX = re.compile(r"(ubuntu|debian|deb\d|\+deb|\.el\d|~dfsg|\.fc\d|suse|amzn|alpine)", re.I)


def _header(hdrs_lower, name):
    return hdrs_lower.get(name.lower(), "")


def detect_sapi(hdrs_lower, phpinfo=None):
    """
    Infer the PHP SAPI / worker model from headers and phpinfo.
    Returns (sapi_label, persistent: bool|None). Passive only.
    """
    if phpinfo and phpinfo.get("sapi"):
        s = phpinfo["sapi"].lower()
        if any(k in s for k in PERSISTENT_SAPIS):
            return phpinfo["sapi"], True
        if any(k in s for k in PERREQUEST_SAPIS):
            return phpinfo["sapi"], False
        return phpinfo["sapi"], None
    xpb = _header(hdrs_lower, "x-powered-by").lower()
    server = _header(hdrs_lower, "server").lower()
    if "php-fpm" in xpb or "fpm" in xpb:
        return "fpm", True
    if "mod_php" in server or ("apache" in server and "php/" in server):
        return "apache2handler (mod_php)", True
    if "litespeed" in server:
        return "litespeed", True
    if "php-cgi" in xpb or "cgi" in xpb:
        return "cgi", False
    # nginx + PHP almost always means php-fpm in practice
    if "nginx" in server:
        return "fpm (inferred: nginx)", True
    return None, None


def detect_proxy(hdrs_lower):
    """Identify a CDN/WAF/proxy in front; its banner may not be the origin's."""
    blob = " ".join("%s:%s" % (k, v) for k, v in hdrs_lower.items()).lower()
    hits = []
    for name, markers in PROXY_MARKERS:
        for mk in markers:
            if mk in blob:
                hits.append(name)
                break
    return ", ".join(dict.fromkeys(hits)) or None


def parse_phpinfo_deep(body):
    """
    Extract non-exploit config fields from an exposed phpinfo() page. These
    refine exposure: memory_limit/post_max_size/max_input_vars size the OOM
    attack surface (CVE-2026-109618); Server API gives the real SAPI;
    disable_functions is a mitigation signal.
    """
    out = {}
    def grab(label, rx):
        m = re.search(rx, body, re.I)
        if m:
            out[label] = m.group(1).strip()
    grab("sapi", r"Server API\s*</td>\s*<td[^>]*>\s*([^<]+)")
    grab("build_date", r"Build Date\s*</td>\s*<td[^>]*>\s*([^<]+)")
    grab("zend", r"Zend Engine\s*v?([\d.]+)")
    grab("memory_limit", r"memory_limit\s*</td>\s*<td[^>]*>\s*([^<]+)")
    grab("post_max_size", r"post_max_size\s*</td>\s*<td[^>]*>\s*([^<]+)")
    grab("max_input_vars", r"max_input_vars\s*</td>\s*<td[^>]*>\s*([^<]+)")
    grab("disable_functions", r"disable_functions\s*</td>\s*<td[^>]*>\s*([^<]+)")
    # plain-text phpinfo (CLI) fallbacks
    if "sapi" not in out:
        grab("sapi", r"Server API\s*=>\s*(.+)")
    if "build_date" not in out:
        grab("build_date", r"Build Date\s*=>\s*(.+)")
    return out


def assess_confidence(r):
    """
    Grade how trustworthy the version-based verdict is, and attach caveats.
    Pure reasoning over already-collected passive signals — no new requests.
    """
    notes = []
    conf = "LOW"
    src = r.version_source or ""

    if r.version:
        if src.startswith("phpinfo"):
            conf = "HIGH"
            notes.append("version from exposed phpinfo() (authoritative)")
        elif "errorpage" in src:
            conf = "HIGH"
            notes.append("version from PHP error page (authoritative)")
        elif src.startswith("origin:"):
            conf = "HIGH"
            notes.append("version read directly from the origin (CDN/WAF bypassed)")
        elif src.startswith(("header:", "banner:")):
            conf = "MEDIUM"
            notes.append("version from HTTP banner (expose_php=On)")
        elif src.startswith(("shodan:", "censys:")):
            conf = "MEDIUM"
            notes.append("version from %s scan data (intel — may be stale, re-verify live)" % src.split(":")[0])
        elif src.startswith("egg:"):
            conf = "MEDIUM"
            notes.append("version from PHP easter-egg credits page")
    else:
        notes.append("no version disclosed — verdict is inference-only")

    # distro backport caveat (big false-positive source)
    if r.distro_build:
        notes.append("distro-packaged build (%s): fix may be BACKPORTED without a version bump — verify the package changelog, not just the number" % r.distro_build)
        if conf == "HIGH":
            conf = "MEDIUM"
        elif conf == "MEDIUM":
            conf = "LOW"

    # proxy/CDN caveat (banner may be the edge, not the origin)
    if r.proxy:
        notes.append("%s in front: banner may reflect the proxy, not the PHP origin" % r.proxy)
        if r.version and src.startswith(("header:", "banner:")) and conf != "LOW":
            conf = "LOW"

    # SAPI relevance to CVE-2026-109619
    if r.worker_persistent is True:
        notes.append("persistent worker (%s): exposed to CVE-2026-109619 stale-state reuse" % (r.sapi or "?"))
    elif r.worker_persistent is False:
        notes.append("per-request SAPI (%s): reduced exposure to CVE-2026-109619" % (r.sapi or "cgi"))

    # OOM surface from phpinfo (CVE-2026-109618)
    pi = r.phpinfo or {}
    if pi.get("post_max_size") or pi.get("max_input_vars"):
        notes.append("OOM surface: post_max_size=%s max_input_vars=%s memory_limit=%s" % (
            pi.get("post_max_size", "?"), pi.get("max_input_vars", "?"), pi.get("memory_limit", "?")))
    if pi.get("disable_functions") and pi["disable_functions"] not in ("no value", "", "none"):
        notes.append("disable_functions set (post-exploit mitigation present)")

    r.confidence = conf
    r.notes = notes
    return r


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
# Extra PHP version-fingerprinting techniques (passive / non-exploit)
# ---------------------------------------------------------------------------
# Classic PHP "easter egg" query strings. On expose_php=On they return a
# characteristic GIF (or the credits page), confirming PHP and its era.
PHP_EGGS = {
    "logo":    "PHPE9568F34-D428-11d2-A769-00AA001ACF42",   # PHP logo
    "zend":    "PHPE9568F35-D428-11d2-A769-00AA001ACF42",   # Zend logo
    "credits": "PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",   # credits page
    "egg":     "PHPE9568F36-D428-11d2-A769-00AA001ACF42",   # easter egg logo
}
# Files that may DECLARE a PHP version constraint (not the live runtime).
VERSION_LEAK_FILES = [
    "/composer.json", "/composer.lock", "/vendor/composer/installed.json",
    "/.env", "/phpunit.xml", "/phpunit.xml.dist",
]


def probe_php_eggs(opener, base, hostpath="/"):
    """
    Request the PHP easter-egg query strings. Returns (confirmed, era) where
    confirmed means PHP presence was proven, and era is a coarse version hint.
    Non-destructive GETs. Works only when expose_php=On.
    """
    target = base.rstrip("/") + (hostpath if hostpath.startswith("/") else "/" + hostpath)
    for name, egg in PHP_EGGS.items():
        url = "%s?=%s" % (target, egg)
        res = http_get(opener, url, max_bytes=40_000)
        if res.get("status") != 200:
            continue
        hdrs = {k.lower(): v for k, v in res.get("headers", {}).items()}
        ctype = hdrs.get("content-type", "")
        body = res.get("body", "")
        # GIF response to a logo egg = PHP with expose_php On
        if "image/gif" in ctype or body[:6] in ("GIF87a", "GIF89a"):
            return True, "egg:%s (expose_php=On)" % name
        # credits page leaks build/version strings
        if name == "credits" and ("PHP Credits" in body or "PHP Group" in body):
            m = re.search(r"PHP\s*(\d+\.\d+\.\d+)", body)
            return True, ("egg:credits %s" % m.group(1)) if m else "egg:credits"
    return False, None


def probe_version_files(opener, base):
    """
    Fetch files that may declare a required PHP version. Returns (constraint,
    source) — a DECLARED requirement (e.g. '>=8.1'), not the live runtime, so
    it only narrows the branch, never confirms the patch level.
    """
    for p in VERSION_LEAK_FILES:
        url = urllib.parse.urljoin(base + "/", p.lstrip("/"))
        res = http_get(opener, url, max_bytes=60_000)
        if res.get("status") != 200 or not res.get("body"):
            continue
        body = res["body"]
        # composer: "php": ">=8.1" or "require": {"php": "^8.2"}
        m = re.search(r'"php"\s*:\s*"([^"]+)"', body)
        if m:
            return m.group(1), "file:%s" % p
        # .env sometimes carries PHP_VERSION=8.3.1
        m = re.search(r'PHP_VERSION\s*=\s*["\']?(\d+\.\d+\.\d+)', body)
        if m:
            return m.group(1), "file:%s" % p
    return None, None


# ---------------------------------------------------------------------------
# Origin discovery — reach the PHP origin behind Cloudflare / other WAFs
# ---------------------------------------------------------------------------
# Published Cloudflare IPv4 ranges (https://www.cloudflare.com/ips/).
CLOUDFLARE_CIDRS = [ipaddress.ip_network(c) for c in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Cloudflare IPv6 ranges
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)]
# A few other common edge providers whose IPs are NOT the origin either.
OTHER_EDGE_CIDRS = [ipaddress.ip_network(c) for c in (
    "199.83.128.0/21", "198.143.32.0/19",            # Imperva/Incapsula
    "192.230.64.0/18",                               # Sucuri
)]
# Subdomain prefixes that commonly point straight at the origin (not proxied).
ORIGIN_HINT_PREFIXES = [
    "origin", "direct", "direct-connect", "cpanel", "whm", "webmail", "mail",
    "ftp", "sftp", "ssh", "server", "web", "dev", "staging", "stage", "test",
    "vpn", "remote", "portal", "admin", "api", "autodiscover", "ns1", "ns2",
    "mx", "smtp", "backup", "old", "beta",
]


def _is_edge_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in CLOUDFLARE_CIDRS) or any(addr in n for n in OTHER_EDGE_CIDRS)


def _a_records(host):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return []
    out = []
    for fam, _, _, _, sa in infos:
        ip = sa[0]
        if ip not in out:
            out.append(ip)
    return out


def discover_origin_ips(domain, extra_hosts=None, insecure=False, max_candidates=12):
    """
    Find candidate origin IPs that are NOT behind Cloudflare/WAF edge ranges.
    Strategy (passive DNS only):
      1. resolve the apex and www,
      2. resolve common non-proxied prefixes (origin.*, cpanel.*, mail.*, ...),
      3. resolve any extra hosts handed in (e.g. crt.sh/subfinder output),
      4. keep only IPs outside known edge CIDRs.
    Returns (origin_ips, notes).
    """
    domain = _normalize_domain(domain)
    notes = []
    candidate_hosts = {domain, "www." + domain}
    candidate_hosts.update("%s.%s" % (p, domain) for p in ORIGIN_HINT_PREFIXES)
    if extra_hosts:
        candidate_hosts.update(h for h in extra_hosts if h.endswith(domain))

    edge_ips, origin_ips = set(), {}
    for h in sorted(candidate_hosts):
        for ip in _a_records(h):
            if _is_edge_ip(ip):
                edge_ips.add(ip)
            else:
                origin_ips.setdefault(ip, h)   # ip -> first host that revealed it
    if edge_ips and not origin_ips:
        notes.append("all resolved IPs are behind the edge (%d) — no direct origin found via DNS" % len(edge_ips))
    ranked = list(origin_ips.items())[:max_candidates]
    return ranked, notes


def _raw_http_to_ip(ip, host, port, use_tls, request_line, insecure, timeout=8, read_bytes=65536):
    """
    Same as _raw_http but connects to a specific IP while presenting the real
    Host header and TLS SNI — this is how we reach the origin behind a CDN.
    """
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            # origin cert often will not match when hit by IP; be lenient here
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        hdr = ["%s HTTP/1.1" % request_line,
               "Host: %s" % host,
               "User-Agent: %s" % UA,
               "Accept: */*",
               "Connection: close"]
        sock.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode())
        chunks, got = [], 0
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
    hdrs = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            hdrs[k.strip().lower()] = v.strip()
    return status_line, hdrs, body, None


def origin_banner(host, origin_ip, insecure=False, timeout=8):
    """
    Hit a candidate origin IP directly (bypassing the CDN) with the real Host
    header, over https then http. Returns a dict with any PHP version/signals
    found straight from the origin.
    """
    out = {"origin_ip": origin_ip, "version": None, "version_source": None,
           "server": None, "x_powered_by": None, "reachable": False, "php_signals": []}
    for scheme, port, tls in (("https", 443, True), ("http", 80, False)):
        status, hdrs, body, err = _raw_http_to_ip(origin_ip, host, port, tls, "GET /", insecure, timeout=timeout)
        if err:
            continue
        out["reachable"] = True
        srv = hdrs.get("server")
        xpb = hdrs.get("x-powered-by")
        if srv and not out["server"]:
            out["server"] = srv
        if xpb and not out["x_powered_by"]:
            out["x_powered_by"] = xpb
        # a CF-origin that is itself Cloudflare means we did not escape it
        if srv and "cloudflare" in srv.lower():
            continue
        for blob in (xpb or "", srv or ""):
            for pat in VER_PATTERNS:
                m = pat.search(blob)
                if m:
                    out["version"] = m.group(1)
                    out["version_source"] = "origin:%s:%s" % (origin_ip, scheme)
        if hdrs.get("set-cookie") and "PHPSESSID" in hdrs["set-cookie"]:
            out["php_signals"].append("cookie:PHPSESSID")
        if body:
            for pat in PHP_ERROR_MARKERS:
                if pat.search(body):
                    out["php_signals"].append("error-disclosure")
                    if not out["version"]:
                        vm = re.search(r"PHP/?(\d+\.\d+\.\d+)", body)
                        if vm:
                            out["version"] = vm.group(1)
                            out["version_source"] = "origin:%s:errorpage" % origin_ip
                    break
        if out["version"]:
            break
    return out


# ---------------------------------------------------------------------------
# Threat-intel origin discovery — Shodan / Censys (optional, API key needed)
# ---------------------------------------------------------------------------
def _http_json(url, headers=None, timeout=20):
    """GET a URL and parse JSON. Returns (data, error)."""
    req = urllib.request.Request(url, headers=headers or {"User-Agent": UA})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read(500).decode("utf-8", "replace")
        except Exception:
            pass
        return None, "HTTP %s %s" % (e.code, detail[:200])
    except Exception as e:
        return None, str(e)


def shodan_lookup(domain, key, timeout=20):
    """
    Query Shodan for hosts tied to `domain`. Returns (ip_via, banners, notes):
      ip_via  : {ip: "shodan:<reason>"} candidate origin IPs
      banners : [(ip, php_version, "shodan:<ip>")] versions seen in banners
    Shodan indexes real origin banners, so a PHP version may come back directly
    even when the live host sits behind a CDN.
    """
    ip_via, banners, notes = {}, [], []
    q = urllib.parse.quote('hostname:%s' % domain)
    url = "https://api.shodan.io/shodan/host/search?key=%s&query=%s" % (urllib.parse.quote(key), q)
    data, err = _http_json(url, timeout=timeout)
    if err:
        notes.append("shodan: %s" % err)
        return ip_via, banners, notes
    for m in data.get("matches", []):
        ip = m.get("ip_str")
        if not ip:
            continue
        ip_via.setdefault(ip, "shodan:hostname")
        # pull a PHP version from anywhere in this match's banner data
        blob = " ".join(str(m.get(k, "")) for k in ("data", "product", "version", "http"))
        vm = re.search(r"PHP/?(\d+\.\d+\.\d+)", blob)
        if vm:
            banners.append((ip, vm.group(1), "shodan:%s" % ip))
    if not ip_via:
        notes.append("shodan: no hosts for hostname:%s" % domain)
    return ip_via, banners, notes


def censys_lookup(domain, api_id, api_secret, timeout=20):
    """
    Query the Censys Hosts Search API (v2) for hosts whose DNS names or TLS
    certificate names match `domain`. Returns (ip_via, banners, notes).
    """
    ip_via, banners, notes = {}, [], []
    q = ('dns.names: %s or services.tls.certificates.leaf_data.names: %s' % (domain, domain))
    url = "https://search.censys.io/api/v2/hosts/search?q=%s&per_page=50" % urllib.parse.quote(q)
    token = base64.b64encode(("%s:%s" % (api_id, api_secret)).encode()).decode()
    data, err = _http_json(url, headers={"User-Agent": UA, "Authorization": "Basic %s" % token}, timeout=timeout)
    if err:
        notes.append("censys: %s" % err)
        return ip_via, banners, notes
    for h in (data.get("result", {}).get("hits", []) or []):
        ip = h.get("ip")
        if not ip:
            continue
        ip_via.setdefault(ip, "censys:cert/dns")
        blob = json.dumps(h.get("services", []))
        vm = re.search(r"PHP/?(\d+\.\d+\.\d+)", blob)
        if vm:
            banners.append((ip, vm.group(1), "censys:%s" % ip))
    if not ip_via:
        notes.append("censys: no hosts for %s" % domain)
    return ip_via, banners, notes


def intel_lookup(domain, opts, timeout=20):
    """
    Aggregate Shodan + Censys origin intel. Returns (ip_via, banners, notes).
    Only runs the providers whose credentials are present.
    """
    ip_via, banners, notes = {}, [], []
    if getattr(opts, "shodan_key", None):
        iv, bn, nt = shodan_lookup(domain, opts.shodan_key, timeout)
        ip_via.update(iv); banners += bn; notes += nt
    if getattr(opts, "censys_id", None) and getattr(opts, "censys_secret", None):
        iv, bn, nt = censys_lookup(domain, opts.censys_id, opts.censys_secret, timeout)
        for k, v in iv.items():
            ip_via.setdefault(k, v)
        banners += bn; notes += nt
    return ip_via, banners, notes


def try_origin_bypass(domain, host, extra_hosts, insecure, timeout, opts=None):
    """
    Full origin-bypass flow: gather candidate origin IPs (passive DNS +
    optional Shodan/Censys intel), then banner-grab each directly. Returns
    (best_result|None, all_attempts, notes).
    """
    ips, notes = discover_origin_ips(domain, extra_hosts=extra_hosts, insecure=insecure)
    seen = {ip for ip, _ in ips}

    # fold in Shodan/Censys intel IPs (bypass DNS entirely) + inline versions
    intel_banners = []
    if opts is not None:
        iv, intel_banners, inotes = intel_lookup(domain, opts, timeout)
        notes += inotes
        for ip, via in iv.items():
            if ip in seen:
                continue
            seen.add(ip)
            if _is_edge_ip(ip):
                continue  # intel can return the CDN edge too — skip it
            ips.append((ip, via))

    attempts = []
    best = None
    for ip, via in ips:
        ob = origin_banner(host, ip, insecure=insecure, timeout=timeout)
        ob["via_host"] = via
        attempts.append(ob)
        if ob.get("version") and not best:
            best = ob
        elif ob.get("reachable") and (ob.get("x_powered_by") or ob.get("php_signals")) and not best:
            best = ob

    # if the live grab found no version but an intel banner carried one, use it
    if (not best or not best.get("version")) and intel_banners:
        ip, ver, src = intel_banners[0]
        best = {"origin_ip": ip, "version": ver, "version_source": src,
                "server": None, "x_powered_by": None, "reachable": False,
                "php_signals": [], "via_host": "intel-banner"}
        notes.append("PHP version %s from %s banner (intel; host may sit behind a CDN)" % (ver, src.split(":")[0]))

    if ips and not attempts:
        notes.append("origin candidates found but none answered a direct request")
    elif not ips and not notes:
        notes.append("no non-edge origin IP discovered (passive DNS; add --shodan/--censys for more)")
    return best, attempts, notes


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
    # passive enrichment (no exploitation) — refines the version verdict
    server: str = None            # full Server header
    sapi: str = None              # worker model: fpm / mod_php / cgi / unknown
    worker_persistent: bool = None  # persistent worker? (relevant to CVE-2026-109619)
    proxy: str = None             # CDN/WAF/proxy in front (banner may be masked)
    distro_build: str = None      # distro package marker (backport may have fixed)
    phpinfo: dict = field(default_factory=dict)  # deep-parsed phpinfo fields
    php_era: str = None           # coarse version hint from easter eggs
    declared_php: str = None      # declared PHP constraint from a leaked file
    origin: dict = None           # origin-bypass result (direct-to-IP banner)
    confidence: str = None        # HIGH / MEDIUM / LOW for the verdict
    notes: list = field(default_factory=list)    # human-readable caveats
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

    # passive enrichment from root headers (no exploitation)
    hdrs_lower = {k.lower(): v for k, v in root.get("headers", {}).items()}
    r.server = hdrs_lower.get("server")
    r.proxy = detect_proxy(hdrs_lower)
    r.sapi, r.worker_persistent = detect_sapi(hdrs_lower)
    ver_blob = " ".join(filter(None, [r.server, hdrs_lower.get("x-powered-by"), r.version or ""]))
    dm = DISTRO_RX.search(ver_blob)
    if dm:
        r.distro_build = dm.group(1).lower()

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

    # 4) exposed phpinfo (deep-parse for extra passive signals)
    if opts.phpinfo_paths:
        ver, p, body = fingerprint_phpinfo(opener, base, DEFAULT_PHPINFO_PATHS)
        if body:
            r.phpinfo = parse_phpinfo_deep(body)
            if ver and not (r.version and r.version_source.startswith("phpinfo")):
                r.php_detected, r.version, r.version_source = True, ver, "phpinfo:%s" % p
            # phpinfo SAPI overrides header-inferred SAPI (authoritative)
            if r.phpinfo.get("sapi"):
                r.sapi, r.worker_persistent = detect_sapi({}, r.phpinfo)
            # distro marker from phpinfo build string too
            if not r.distro_build:
                dm = DISTRO_RX.search(" ".join(r.phpinfo.values()))
                if dm:
                    r.distro_build = dm.group(1).lower()

    # 4b) extra version techniques when still no exact version
    if not r.version or opts.deep_version:
        confirmed, era = probe_php_eggs(opener, base)
        if confirmed:
            r.php_detected = True
            r.php_era = era
            if era and era.startswith("egg:credits ") and not r.version:
                r.version, r.version_source = era.split()[-1], "egg:credits"
        dver, dsrc = probe_version_files(opener, base)
        if dver:
            r.php_detected = True
            # exact X.Y.Z from a file is usable; a constraint only narrows branch
            if re.fullmatch(r"\d+\.\d+\.\d+", dver) and not r.version:
                r.version, r.version_source = dver, dsrc
            else:
                r.declared_php = "%s (%s)" % (dver, dsrc)

    # 4c) origin-bypass: if behind an edge/WAF and still no version, go direct
    if opts.origin_scan and not r.version and (r.proxy or not r.version):
        extra = getattr(opts, "_recon_hosts", None)
        best, attempts, onotes = try_origin_bypass(
            host.split(".", 1)[-1] if host and host.count(".") >= 2 else host,
            host, extra, opts.insecure, opts.timeout, opts=opts)
        r.origin = {"best": best, "attempts": attempts, "notes": onotes}
        if best and best.get("version"):
            r.php_detected, r.version, r.version_source = True, best["version"], best["version_source"]
            r.notes.append("origin reached directly at %s — CDN/WAF bypassed" % best["origin_ip"])
        elif best and best.get("x_powered_by"):
            r.php_detected = True
            r.notes.append("origin %s leaked X-Powered-By: %s (CDN bypassed, no exact version)" % (best["origin_ip"], best["x_powered_by"]))

    # 5) classification
    if r.php_detected:
        c = classify(r.version)
        r.status = c["status"]
        r.detail = c["detail"]
        r.cves = c["cves"]
    else:
        r.status = "NO_PHP_DETECTED"
        r.detail = "no PHP signal on the HTTP surface"

    # 6) grade confidence + attach caveats (pure reasoning, no new requests)
    assess_confidence(r)
    if r.php_era and "expose_php=On" in (r.php_era or ""):
        r.notes.append("PHP confirmed via easter egg (%s)" % r.php_era)
    if r.declared_php:
        r.notes.append("declared PHP requirement %s — narrows branch, not the patch level" % r.declared_php)

    # 7) opt-in probe
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
    conf = (" [confidence: %s]" % r.confidence) if r.confidence else ""
    lines.append("  STATUS        : %s%s" % (r.status or "-", conf))
    if r.detail:
        lines.append("  Detail        : %s" % r.detail)
    # passive-signal block
    if r.server:
        lines.append("  Server        : %s" % r.server)
    if r.sapi:
        wp = {True: "persistent worker", False: "per-request", None: "worker model unknown"}[r.worker_persistent]
        lines.append("  SAPI          : %s (%s)" % (r.sapi, wp))
    if r.proxy:
        lines.append("  Proxy/WAF     : %s" % r.proxy)
    if r.distro_build:
        lines.append("  Build         : distro-packaged (%s) — backport possible" % r.distro_build)
    if r.php_era:
        lines.append("  Easter egg    : %s" % r.php_era)
    if r.declared_php:
        lines.append("  Declared PHP  : %s" % r.declared_php)
    if r.origin and r.origin.get("best"):
        ob = r.origin["best"]
        lines.append("  ORIGIN BYPASS : %s (via %s) Server=%s X-Powered-By=%s" % (
            ob.get("origin_ip"), ob.get("via_host"), ob.get("server"), ob.get("x_powered_by")))
    elif r.origin and r.origin.get("notes"):
        lines.append("  Origin bypass : %s" % "; ".join(r.origin["notes"]))
    if r.phpinfo:
        pi = r.phpinfo
        kv = [("%s=%s" % (k, pi[k])) for k in ("build_date", "memory_limit", "post_max_size", "max_input_vars") if pi.get(k)]
        if kv:
            lines.append("  phpinfo       : %s" % ", ".join(kv))
    for cve, desc in CVES.items():
        v = (r.cves or {}).get(cve, "-")
        ghsa = ADVISORIES.get(cve, "")
        lines.append("    %s (%s) [%s] -> %s" % (cve, ghsa, desc.split("(")[0].strip(), v))
    if r.notes:
        lines.append("  Notes:")
        for n in r.notes:
            lines.append("    - %s" % n)
    if r.banner and r.banner.get("probes"):
        srv = next((p.get("server") for p in r.banner["probes"] if p.get("server")), None)
        xpb = next((p.get("x_powered_by") for p in r.banner["probes"] if p.get("x_powered_by")), None)
        if (srv or xpb) and not r.server:
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
    ap.add_argument("--deep-version", action="store_true", help="extra version techniques: PHP easter eggs + version-leak files (composer.json, .env, ...)")
    ap.add_argument("--origin-scan", action="store_true", help="try to reach the PHP origin behind Cloudflare/WAF (direct-to-IP request with real Host header)")
    ap.add_argument("--shodan-key", help="Shodan API key for origin intel (or env SHODAN_API_KEY); implies --origin-scan")
    ap.add_argument("--censys-id", help="Censys API ID (or env CENSYS_API_ID)")
    ap.add_argument("--censys-secret", help="Censys API secret (or env CENSYS_API_SECRET); id+secret imply --origin-scan")
    ap.add_argument("--probe", action="store_true", help="WARNING: multipart load probe (may cause DoS; authorized use only)")
    ap.add_argument("--probe-count", type=int, default=5, help="number of probe requests (default 5)")
    ap.add_argument("--threads", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--insecure", action="store_true", help="do not validate TLS")
    ap.add_argument("-o", "--output", help="save JSON to path")
    ap.add_argument("--csv", help="save CSV to path")
    opts = ap.parse_args()

    # resolve API creds from flags or environment
    opts.shodan_key = opts.shodan_key or os.environ.get("SHODAN_API_KEY")
    opts.censys_id = opts.censys_id or os.environ.get("CENSYS_API_ID")
    opts.censys_secret = opts.censys_secret or os.environ.get("CENSYS_API_SECRET")
    # providing credentials turns on the origin-bypass flow automatically
    if opts.shodan_key or (opts.censys_id and opts.censys_secret):
        opts.origin_scan = True

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
        # share all discovered hosts with origin discovery (more A-records to test)
        opts._recon_hosts = sorted(seen)

    if opts.origin_scan:
        prov = []
        if opts.shodan_key:
            prov.append("Shodan")
        if opts.censys_id and opts.censys_secret:
            prov.append("Censys")
        intel = (" + intel: %s" % ", ".join(prov)) if prov else ""
        say("[i] ORIGIN-SCAN active: probing non-edge IPs directly with the real Host header to bypass CDN/WAF%s. Authorized targets only." % intel)

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

    # ----------------------------- SUMMARY -----------------------------
    say("")
    say("╔" + "═" * 60 + "╗")
    say("║ php2shell-scanner — CONSOLIDATED RESULTS".ljust(61) + "║")
    say("╚" + "═" * 60 + "╝")
    say("Advisories: CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) · "
        "CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)")

    counts = {}
    for r in results:
        counts[r.status or "ERROR"] = counts.get(r.status or "ERROR", 0) + 1
    order = ["VULNERABLE", "VULNERABLE_EOL", "UNKNOWN", "PATCHED", "NO_PHP_DETECTED", "ERROR"]
    tally = " ".join("%s=%d" % (k, counts[k]) for k in order if k in counts)
    extra = " ".join("%s=%d" % (k, v) for k, v in counts.items() if k not in order)
    say(("Scanned %d target(s): %s %s" % (len(results), tally, extra)).rstrip())

    def _row(r):
        bits = [r.version or "no-version"]
        if r.confidence:
            bits.append("conf=%s" % r.confidence)
        if r.worker_persistent is True:
            bits.append("persistent-worker")
        if r.proxy:
            bits.append("behind:%s" % r.proxy)
        if r.distro_build:
            bits.append("distro:%s" % r.distro_build)
        return "  %-45s  %s" % (r.target, "  ".join(bits))

    vuln = [r for r in results if r.status == "VULNERABLE"]
    eol = [r for r in results if r.status == "VULNERABLE_EOL"]
    unknown = [r for r in results if r.status == "UNKNOWN"]

    if vuln:
        say("")
        say("[!] VULNERABLE — PHP < fixed version (patch available):")
        for r in sorted(vuln, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x.confidence, 3)):
            say(_row(r))
    if eol:
        say("")
        say("[!] VULNERABLE (EOL) — no upstream patch; check distro backport:")
        for r in eol:
            say(_row(r))
    if unknown:
        say("")
        say("[?] UNKNOWN — PHP present, version undisclosed (manual check):")
        for r in unknown:
            say(_row(r))

    # actionable pointers
    review = [r for r in (vuln + eol) if r.confidence in ("LOW", "MEDIUM")]
    if review:
        say("")
        say("[i] %d result(s) are LOW/MEDIUM confidence — verify before reporting "
            "(proxy banner or distro backport may change the verdict)." % len(review))

    vulns = vuln + eol
    if opts.output:
        with open(opts.output, "w") as fh:
            json.dump([asdict(r) for r in results], fh, indent=2, default=str)
        say("JSON saved to %s" % opts.output)
    if opts.csv:
        import csv as _csv
        with open(opts.csv, "w", newline="") as fh:
            w = _csv.writer(fh)
            w.writerow(["target", "php_detected", "version", "source", "status", "confidence",
                        "sapi", "persistent_worker", "proxy", "distro_build",
                        "cve-2026-109618", "cve-2026-109619", "detail", "error"])
            for r in results:
                w.writerow([r.target, r.php_detected, r.version, r.version_source, r.status, r.confidence,
                            r.sapi, r.worker_persistent, r.proxy, r.distro_build,
                            (r.cves or {}).get("CVE-2026-109618", ""), (r.cves or {}).get("CVE-2026-109619", ""),
                            r.detail, r.error])
        say("CSV saved to %s" % opts.csv)

    return 1 if vulns else 0


if __name__ == "__main__":
    sys.exit(main())
