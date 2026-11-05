import ipaddress
import re
import socket
from urllib.parse import urlparse, urljoin
from typing import Tuple, List, Optional, Dict, Any
import dns.resolver
from app.config import settings

# Blocked hostname patterns
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

# Known Cloud Metadata IP strings
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack
    "169.254.169.253",   # AWS DNS
    "100.100.100.200",   # Alibaba Cloud
    "fd00:ec2::254",     # AWS IPv6 IMDS
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "tiny.cc"
}


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, Optional[str]]:
    """
    Checks if an IP address belongs to private, loopback, link-local,
    multicast, reserved, or cloud metadata ranges.
    """
    ip_str = str(ip)

    if ip_str in CLOUD_METADATA_IPS:
        return True, f"Blocked cloud metadata address: {ip_str}"

    if ip.is_loopback:
        return True, f"Blocked loopback address: {ip_str}"

    if ip.is_private:
        return True, f"Blocked private network address: {ip_str}"

    if ip.is_link_local:
        return True, f"Blocked link-local address: {ip_str}"

    if ip.is_multicast:
        return True, f"Blocked multicast address: {ip_str}"

    if ip.is_reserved:
        return True, f"Blocked reserved address: {ip_str}"

    if ip.is_unspecified:
        return True, f"Blocked unspecified address: {ip_str}"

    # Check 6to4 or IPv4-mapped IPv6 addresses
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_ip_blocked(ip.ipv4_mapped)

    # Carrier-grade NAT (100.64.0.0/10)
    cgnat_net = ipaddress.ip_network("100.64.0.0/10")
    if ip.version == 4 and ip in cgnat_net:
        return True, f"Blocked Shared Address Space (CGNAT): {ip_str}"

    return False, None


def resolve_hostname_ips(hostname: str) -> Tuple[bool, List[str], Optional[str]]:
    """
    Safely resolves a hostname to IPv4 and IPv6 addresses.
    Rejects any resolution that contains a blocked or private IP.
    """
    hostname_clean = hostname.lower().strip().rstrip(".")

    if hostname_clean in BLOCKED_HOSTNAMES or hostname_clean.endswith(".local") or hostname_clean.endswith(".internal"):
        return False, [], f"Blocked internal or local hostname: {hostname}"

    resolved_ips: List[str] = []

    # Check if hostname itself is already an IP literal
    try:
        parsed_ip = ipaddress.ip_address(hostname_clean)
        is_blocked, reason = is_ip_blocked(parsed_ip)
        if is_blocked:
            return False, [], reason
        return True, [str(parsed_ip)], None
    except ValueError:
        pass  # It's a domain name, proceed with DNS resolution

    # Perform DNS lookups safely
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0

    # Try A (IPv4)
    try:
        answers_a = resolver.resolve(hostname_clean, "A")
        for rdata in answers_a:
            ip_obj = ipaddress.ip_address(rdata.address)
            is_blocked, reason = is_ip_blocked(ip_obj)
            if is_blocked:
                return False, [], f"DNS resolved to blocked IP ({rdata.address}): {reason}"
            resolved_ips.append(rdata.address)
    except Exception:
        pass

    # Try AAAA (IPv6)
    try:
        answers_aaaa = resolver.resolve(hostname_clean, "AAAA")
        for rdata in answers_aaaa:
            ip_obj = ipaddress.ip_address(rdata.address)
            is_blocked, reason = is_ip_blocked(ip_obj)
            if is_blocked:
                return False, [], f"DNS resolved to blocked IPv6 ({rdata.address}): {reason}"
            resolved_ips.append(rdata.address)
    except Exception:
        pass

    # Fallback to standard socket.getaddrinfo if dnspython returned nothing
    if not resolved_ips:
        try:
            addr_info = socket.getaddrinfo(hostname_clean, None)
            for item in addr_info:
                sock_ip = item[4][0]
                ip_obj = ipaddress.ip_address(sock_ip)
                is_blocked, reason = is_ip_blocked(ip_obj)
                if is_blocked:
                    return False, [], f"DNS resolved to blocked address ({sock_ip}): {reason}"
                if sock_ip not in resolved_ips:
                    resolved_ips.append(sock_ip)
        except socket.gaierror as e:
            return False, [], f"Could not resolve hostname '{hostname}': {str(e)}"

    if not resolved_ips:
        return False, [], f"DNS resolution failed for hostname '{hostname}'"

    return True, resolved_ips, None


def validate_url_security(url_str: str) -> Tuple[bool, Optional[str], Optional[dict]]:
    """
    Validates a URL for SSRF vulnerabilities and security hygiene.
    Returns (is_safe, error_message, metadata).
    """
    if not url_str or not isinstance(url_str, str):
        return False, "URL is empty or invalid type", None

    url_clean = url_str.strip()

    try:
        parsed = urlparse(url_clean)
    except Exception as e:
        return False, f"Malformed URL: {str(e)}", None

    # Scheme check: only http and https allowed
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only http:// and https:// are permitted.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname.", None

    # DNS and SSRF validation FIRST (catches localhost, 127.0.0.1, private IPs immediately)
    is_safe, resolved_ips, block_reason = resolve_hostname_ips(hostname)
    if not is_safe:
        return False, f"SSRF Blocked: {block_reason}", None

    # Port restriction: allow standard web ports (80, 443, 8000, 8080, 8443, 8888)
    port = parsed.port
    if port and port not in (80, 443, 8000, 8080, 8443, 8888):
        return False, f"Port {port} is restricted. Only standard web ports are allowed.", None

    # Check for credentials in URL (e.g. http://user:pass@example.com)
    has_credentials = bool(parsed.username or parsed.password)

    # Check for punycode / homograph
    is_punycode = "xn--" in hostname.lower()

    # Check if domain is a URL shortener
    is_shortener = hostname.lower() in SHORTENER_DOMAINS

    # Check if host is direct IP address
    is_ip_host = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_host = True
    except ValueError:
        pass

    meta = {
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "path": parsed.path or "/",
        "resolved_ips": resolved_ips,
        "is_punycode": is_punycode,
        "is_shortener": is_shortener,
        "is_ip_host": is_ip_host,
        "has_credentials": has_credentials
    }

    return True, None, meta
