"""BestCF endpoint parser for Gate. Parsing does not prove proxy reachability."""
import ipaddress
import re
import requests

DEFAULT_URL = "https://bestcf.pages.dev/tiancheng/kr.txt"
# Cloudflare commonly supported TLS proxy ports; other ports may be ordinary relays.
TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
LINE_RE = re.compile(r"^\s*((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?=\s|#|$)")

def parse_endpoints(raw, allowed_ports=TLS_PORTS):
    """Parse one IP:port per line with optional #comment; dedupe, preserve order."""
    results, seen = [], set()
    for line in raw.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        ip, port_raw = match.groups()
        try:
            ipaddress.IPv4Address(ip)
            port = int(port_raw)
        except (ipaddress.AddressValueError, ValueError):
            continue
        if not 1 <= port <= 65535 or (allowed_ports is not None and port not in allowed_ports):
            continue
        item = f"{ip}:{port}"
        if item not in seen:
            seen.add(item)
            results.append(item)
    return results

def fetch_endpoints(url=DEFAULT_URL, timeout=15):
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "gate-bestcf-fetch/1.0"})
    response.raise_for_status()
    return parse_endpoints(response.text)
