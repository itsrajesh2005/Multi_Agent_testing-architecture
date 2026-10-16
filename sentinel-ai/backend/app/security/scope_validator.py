"""Scope validation — deterministic backend checks for target authorization."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple
from urllib.parse import urlparse

from app.core.config import get_settings


# Private/reserved ranges that are blocked by default
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Dangerous schemes
_BLOCKED_SCHEMES = {"file", "ftp", "gopher", "data", "javascript"}

# Pattern for DNS rebinding attempts
_SUSPICIOUS_HOSTNAME_RE = re.compile(
    r"(^|\.)0x[0-9a-f]+\.|"  # hex-encoded octets
    r"\d{10,}|"               # very long numeric strings
    r"\\|"                    # backslash in hostname
    r"%[0-9a-fA-F]{2}",      # URL-encoded chars in hostname
    re.IGNORECASE,
)


def _is_ip_in_allowed_ranges(ip_str: str, allowed: List[str]) -> bool:
    """Check if an IP address falls within any of the allowed CIDR ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for allowed_target in allowed:
        try:
            network = ipaddress.ip_network(allowed_target, strict=False)
            if addr in network:
                return True
        except ValueError:
            # Not a CIDR range, skip
            continue
    return False


def _is_hostname_allowed(hostname: str, allowed: List[str]) -> bool:
    """Check if a hostname matches an allowed target."""
    hostname = hostname.lower().strip(".")
    for allowed_target in allowed:
        target = allowed_target.lower().strip(".")
        try:
            # Check if it's a network range — skip for hostname matching
            ipaddress.ip_network(target, strict=False)
            continue
        except ValueError:
            pass
        # Direct match or subdomain match
        if hostname == target or hostname.endswith("." + target):
            return True
    return False


def validate_target(target: str, allowed_targets: List[str] | None = None) -> Tuple[bool, str]:
    """
    Validate a single target string against the allowlist.

    Returns (is_valid, reason).
    """
    settings = get_settings()
    if allowed_targets is None:
        allowed_targets = settings.allowed_targets_list

    if not target or not target.strip():
        return False, "Empty target"

    target = target.strip()

    # Block dangerous URL schemes
    if "://" in target:
        parsed = urlparse(target)
        scheme = parsed.scheme.lower()
        if scheme in _BLOCKED_SCHEMES:
            return False, f"Blocked scheme: {scheme}"
        hostname = parsed.hostname or ""
    else:
        hostname = target.split(":")[0].split("/")[0]

    # Check for suspicious patterns (DNS rebinding, encoding tricks)
    if _SUSPICIOUS_HOSTNAME_RE.search(hostname):
        return False, f"Suspicious hostname pattern detected: {hostname}"

    # Try parsing as IP address
    try:
        addr = ipaddress.ip_address(hostname)
        # Check if it's in allowed ranges
        if _is_ip_in_allowed_ranges(hostname, allowed_targets):
            return True, "IP in allowed range"
        # Block arbitrary IPs
        return False, f"IP address {hostname} is not in the allowed target list"
    except ValueError:
        pass

    # It's a hostname — check against the allowlist
    if _is_hostname_allowed(hostname, allowed_targets):
        return True, "Hostname in allowed list"

    # In demo mode, allow synthetic targets
    if settings.is_demo_mode and hostname in ("demo.lab.local", "app.lab.local", "db.lab.local", "api.lab.local"):
        return True, "Demo target allowed in demo mode"

    return False, f"Target '{hostname}' is not in the allowed target list"


def validate_scope(targets: List[str], allowed_targets: List[str] | None = None) -> Tuple[bool, List[str]]:
    """
    Validate all targets in a scope. Returns (all_valid, list_of_errors).
    """
    errors = []
    for target in targets:
        is_valid, reason = validate_target(target, allowed_targets)
        if not is_valid:
            errors.append(f"Target '{target}': {reason}")
    return len(errors) == 0, errors


def check_ssrf_protection(url: str) -> Tuple[bool, str]:
    """
    Additional SSRF protection checks for any URL the system might access.
    """
    if not url:
        return False, "Empty URL"

    parsed = urlparse(url)

    if parsed.scheme.lower() in _BLOCKED_SCHEMES:
        return False, f"Blocked scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname in URL"

    # Block localhost variants
    localhost_patterns = ["localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"]
    if hostname.lower() in localhost_patterns:
        return False, "Localhost access blocked"

    # Block private IPs
    try:
        addr = ipaddress.ip_address(hostname)
        for private_range in _PRIVATE_RANGES:
            if addr in private_range:
                return False, f"Private/reserved IP blocked: {hostname}"
    except ValueError:
        pass

    # Check for suspicious patterns
    if _SUSPICIOUS_HOSTNAME_RE.search(hostname):
        return False, f"Suspicious hostname: {hostname}"

    return True, "URL passed SSRF checks"
