#!/usr/bin/env python3
"""External exposure check of hosts YOU OWN / are authorised to test (QA, UAT, your own staging; never someone else's systems).
Standard library only; safe requests only (GET, TCP connect, TLS handshake), a few dozen per target, identified by User-Agent.

  exposure.py --targets https://qa.example.com,10.0.0.5 --out exposure.json [--no-ports] [--timeout 6]

Checks: plain HTTP / TLS certificate problems / http->https redirect / security headers / CORS misconfiguration / server version banner /
well-known sensitive paths (.git, .env, actuator, metrics, pprof, OTLP endpoints, API docs, backups) / risky ports reachable from where this runs
(databases, Docker API, OTLP 4317/4318, Prometheus, ...). A result means 'reachable from the scanner', so run it from the network an attacker would use."""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "secscan-exposure/1 (authorised security check)"
PORTS = {2375: ("Docker API", "HIGH"), 2379: ("etcd", "HIGH"), 6379: ("Redis", "HIGH"), 5432: ("PostgreSQL", "HIGH"), 3306: ("MySQL", "HIGH"), 27017: ("MongoDB", "HIGH"),
         9200: ("Elasticsearch", "HIGH"), 11211: ("Memcached", "HIGH"), 5601: ("Kibana", "MEDIUM"), 8500: ("Consul", "MEDIUM"), 4317: ("OpenTelemetry OTLP/gRPC", "MEDIUM"),
         4318: ("OpenTelemetry OTLP/HTTP", "MEDIUM"), 9090: ("Prometheus", "MEDIUM"), 9100: ("node_exporter", "MEDIUM"), 15672: ("RabbitMQ management", "MEDIUM")}


def has(body, *needles):
    b = body.lower()
    return any(n.lower() in b for n in needles)


# path -> (severity, rule, title, detector(status, headers, body) -> bool)
PATHS = [
    ("/.git/HEAD", "HIGH", "EXP-GIT", "Git repository metadata is downloadable (/.git exposes the source and history)", lambda s, h, b: s == 200 and b.startswith("ref:")),
    ("/.env", "HIGH", "EXP-ENV", "Environment file is downloadable (/.env usually holds secrets)", lambda s, h, b: s == 200 and has(b, "password=", "secret", "token=", "key=") and "<html" not in b[:200].lower()),
    ("/actuator/env", "HIGH", "EXP-ACTUATOR-ENV", "Spring actuator /env is open (configuration and secrets)", lambda s, h, b: s == 200 and has(b, "propertySources")),
    ("/actuator/heapdump", "HIGH", "EXP-HEAPDUMP", "Spring actuator heap dump is open", lambda s, h, b: s == 200 and "octet-stream" in h.get("content-type", "")),
    ("/actuator", "MEDIUM", "EXP-ACTUATOR", "Spring actuator index is open", lambda s, h, b: s == 200 and has(b, '"_links"')),
    ("/debug/pprof/", "HIGH", "EXP-PPROF", "Go pprof debug endpoint is open", lambda s, h, b: s == 200 and has(b, "goroutine", "pprof")),
    ("/phpinfo.php", "HIGH", "EXP-PHPINFO", "phpinfo() page is open", lambda s, h, b: s == 200 and has(b, "php version")),
    ("/server-status", "MEDIUM", "EXP-SERVERSTATUS", "Apache server-status is open", lambda s, h, b: s == 200 and has(b, "apache server status")),
    ("/metrics", "MEDIUM", "EXP-METRICS", "Prometheus metrics are readable without authentication (internal names, traffic, versions)", lambda s, h, b: s == 200 and has(b, "# HELP", "# TYPE")),
    ("/v1/traces", "MEDIUM", "EXP-OTLP", "OpenTelemetry OTLP/HTTP trace endpoint answers on the public interface", lambda s, h, b: s in (200, 400, 405, 415) and "html" not in h.get("content-type", "")),
    ("/v1/metrics", "MEDIUM", "EXP-OTLP", "OpenTelemetry OTLP/HTTP metrics endpoint answers on the public interface", lambda s, h, b: s in (200, 400, 405, 415) and "html" not in h.get("content-type", "")),
    ("/openapi.json", "LOW", "EXP-APIDOCS", "API specification is public (maps every endpoint for an attacker)", lambda s, h, b: s == 200 and has(b, '"openapi"', '"swagger"')),
    ("/swagger.json", "LOW", "EXP-APIDOCS", "API specification is public", lambda s, h, b: s == 200 and has(b, '"swagger"', '"openapi"')),
    ("/docs", "LOW", "EXP-APIDOCS", "Interactive API docs (Swagger UI) are public", lambda s, h, b: s == 200 and has(b, "swagger-ui", "redoc")),
    ("/backup.zip", "HIGH", "EXP-BACKUP", "A backup archive is downloadable", lambda s, h, b: s == 200 and ("zip" in h.get("content-type", "") or b.startswith("PK"))),
    ("/dump.sql", "HIGH", "EXP-BACKUP", "A database dump is downloadable", lambda s, h, b: s == 200 and has(b, "create table", "insert into")),
]


def fetch(url, timeout, headers=None, context=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(60000).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(60000).decode("utf-8", "replace"), None
    except Exception as e:  # noqa: BLE001 - network errors are reported, never fatal
        return 0, {}, "", e


def add(out, sev, rule, title, loc, fix=""):
    if not any(x["rule"] == rule and x["location"] == loc for x in out):
        out.append(dict(severity=sev, rule=rule, title=title, location=loc, fix=fix))


def tls_checks(host, port, out, timeout):
    loc = f"{host}:{port}"
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert()
            left = (dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z") - dt.datetime.utcnow()).days
            if left < 0:
                add(out, "HIGH", "EXP-TLS-EXPIRED", f"TLS certificate expired {-left} days ago", loc, "Renew the certificate")
            elif left < 14:
                add(out, "MEDIUM", "EXP-TLS-EXPIRING", f"TLS certificate expires in {left} days", loc, "Renew the certificate (automate with ACME)")
            if t.version() in ("TLSv1", "TLSv1.1", "SSLv3"):
                add(out, "HIGH", "EXP-TLS-PROTOCOL", f"Server negotiated the obsolete protocol {t.version()}", loc, "Allow TLS 1.2 and 1.3 only")
    except ssl.SSLCertVerificationError as e:
        reason = (e.verify_message or str(e)).lower()
        kind = "self-signed certificate" if "self" in reason else "expired certificate" if "expired" in reason else "hostname mismatch" if "hostname" in reason or "doesn't match" in reason else "certificate not trusted"
        add(out, "HIGH", "EXP-TLS-CERT", f"TLS certificate cannot be verified ({kind}): {e.verify_message or e}", loc, "Install a certificate from a trusted CA that matches the host name")
    except (ssl.SSLError, OSError):
        pass  # not a TLS port or unreachable: reported by the other checks


def check_target(raw, timeout, ports, out):
    t = raw if "://" in raw else f"https://{raw}"
    u = urllib.parse.urlparse(t)
    host, scheme = u.hostname, u.scheme
    port = u.port or (443 if scheme == "https" else 80)
    base = f"{scheme}://{u.netloc}"
    status, hdr, body, err = fetch(base + "/", timeout)
    if err and "://" not in raw and scheme == "https":  # bare host: fall back to plain http
        base, scheme, port = f"http://{u.netloc}", "http", 80
        status, hdr, body, err = fetch(base + "/", timeout)
    if err:
        add(out, "INFO", "EXP-UNREACHABLE", f"Target did not answer from here: {err}", base, "")
        return
    if scheme == "http":
        add(out, "MEDIUM", "EXP-HTTP", "Served over plain HTTP: logins, tokens and data travel in clear text", base, "Serve over HTTPS and redirect HTTP to it")
    else:
        tls_checks(host, port, out, timeout)
        ps, ph, _, perr = fetch(f"http://{host}/", timeout) if port == 443 else (0, {}, "", True)
        if not perr and ps == 200:
            add(out, "MEDIUM", "EXP-NO-REDIRECT", "Plain HTTP on port 80 serves content instead of redirecting to HTTPS", f"http://{host}/", "Redirect all HTTP to HTTPS")
    need = {"x-content-type-options": ("LOW", "EXP-HDR-XCTO", "X-Content-Type-Options header missing", "Send X-Content-Type-Options: nosniff"),
            "content-security-policy": ("LOW", "EXP-HDR-CSP", "Content-Security-Policy header missing", "Define a Content-Security-Policy")}
    if "html" in hdr.get("content-type", ""):
        need["x-frame-options"] = ("LOW", "EXP-HDR-XFO", "Clickjacking protection missing (X-Frame-Options / frame-ancestors)", "Send X-Frame-Options: DENY or CSP frame-ancestors")
    if scheme == "https":
        need["strict-transport-security"] = ("MEDIUM", "EXP-HDR-HSTS", "Strict-Transport-Security header missing", "Send Strict-Transport-Security with a long max-age")
    for k, (sev, rule, title, fix) in need.items():
        if k not in hdr and not (k == "x-frame-options" and "frame-ancestors" in hdr.get("content-security-policy", "")):
            add(out, sev, rule, title, base + "/", fix)
    srv = hdr.get("server", "")
    if any(c.isdigit() for c in srv) and "/" in srv:
        add(out, "LOW", "EXP-BANNER", f"Server header discloses the product and version ({srv})", base + "/", "Hide version numbers")
    _, ch, _, _ = fetch(base + "/", timeout, headers={"Origin": "https://evil.example"})
    acao, acac = ch.get("access-control-allow-origin", ""), ch.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "https://evil.example" and acac:
        add(out, "HIGH", "EXP-CORS-REFLECT", "CORS reflects any Origin and allows credentials: any website can read authenticated responses", base + "/", "Allow-list specific origins")
    elif acao == "*" and acac:
        add(out, "HIGH", "EXP-CORS-WILDCARD", "CORS allows every origin together with credentials", base + "/", "Never combine * with credentials")
    elif acao == "*":
        add(out, "LOW", "EXP-CORS-OPEN", "CORS allows every origin (fine for public data only)", base + "/", "Restrict to the origins that need access")
    rnd = hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]
    s404, _, b404, _ = fetch(f"{base}/{rnd}-not-there", timeout)
    catch_all = s404 == 200
    for path, sev, rule, title, det in PATHS:
        s, h, b, e = fetch(base + path, timeout)
        if e or (catch_all and rule in ("EXP-APIDOCS", "EXP-OTLP", "EXP-METRICS") and b == b404):
            continue
        if det(s, h, b):
            add(out, sev, rule, title, base + path, "Remove it from the public interface or require authentication")
        time.sleep(0.05)
    if ports:
        def probe(p):
            try:
                with socket.create_connection((host, p), timeout=min(timeout, 3)):
                    return p
            except OSError:
                return None
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            for p in filter(None, ex.map(probe, [p for p in PORTS if p != port])):
                name, sev = PORTS[p]
                add(out, sev, f"EXP-PORT-{p}", f"{name} port {p} is reachable from the scanner", f"{host}:{p}", "Close it to the internet / restrict by firewall or private networking")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=6)
    ap.add_argument("--no-ports", action="store_true")
    a = ap.parse_args()
    out = []
    targets = [t.strip() for t in a.targets.split(",") if t.strip()]
    for t in targets:
        check_target(t, a.timeout, not a.no_ports, out)
    json.dump({"targets": targets, "findings": out}, open(a.out, "w"), indent=1)
    print(f"exposure: {len(targets)} target(s), {len([x for x in out if x['severity'] != 'INFO'])} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
