"""P4 Egress control: agents may only reach approved destinations. Blocks private/loopback/link-local/metadata addresses (SSRF),
re-validates every redirect, pins the connection to the validated IP (no DNS rebinding between check and use), caps the response size."""
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlsplit


class EgressViolation(ValueError):
    pass


def _host_allowed(host, allow_hosts):
    """'api.example.com' matches exactly; '.example.com' matches subdomains (not the bare apex)."""
    host = host.lower().rstrip(".")
    for a in (h.lower() for h in allow_hosts):
        if a.startswith("."):
            if host.endswith(a):
                return True
        elif host == a:
            return True
    return False


def _check_ip(ip_s):
    ip = ipaddress.ip_address(ip_s)
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast:
        raise EgressViolation(f"destination {ip} is not a public address")
    return str(ip)


def validate_url(url, *, allow_hosts, allow_schemes=("https",), allow_ports=(None, 443)):
    """Return (scheme, host, port, path_with_query, [validated ips]). allow_hosts is REQUIRED: 'example.com' or '.example.com' (subdomains)."""
    if not allow_hosts:
        raise EgressViolation("an explicit allow_hosts list is required (default deny)")
    p = urlsplit(url)
    if p.scheme not in allow_schemes:
        raise EgressViolation(f"scheme {p.scheme!r} is not allowed")
    if p.username or p.password:
        raise EgressViolation("credentials in URLs are not allowed")
    host = (p.hostname or "").lower()
    if not host or not _host_allowed(host, allow_hosts):
        raise EgressViolation(f"host {host!r} is not on the egress allow-list")
    port = p.port or (443 if p.scheme == "https" else 80)
    if p.port is not None and p.port not in allow_ports and port not in allow_ports:
        raise EgressViolation(f"port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise EgressViolation(f"cannot resolve {host}: {e}") from None
    ips = sorted({_check_ip(i[4][0]) for i in infos})
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    return p.scheme, host, port, path, ips


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def safe_fetch(url, *, allow_hosts, allow_schemes=("https",), allow_ports=(None, 443), timeout=5.0, max_bytes=1_000_000, max_redirects=3):
    """GET url under the egress policy. Returns (status, body_bytes). TLS verification is always on."""
    for _ in range(max_redirects + 1):
        scheme, host, port, path, ips = validate_url(url, allow_hosts=allow_hosts, allow_schemes=allow_schemes, allow_ports=allow_ports)
        conn = (_PinnedHTTPS if scheme == "https" else _PinnedHTTP)(host, ips[0], port, timeout)
        try:
            conn.request("GET", path, headers={"Host": host, "User-Agent": "agentsec-fetch/1"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                url = urljoin(url, r.getheader("Location"))  # re-validated on the next loop iteration
                continue
            body = r.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise EgressViolation("response too large")
            return r.status, body
        finally:
            conn.close()
    raise EgressViolation("too many redirects")
