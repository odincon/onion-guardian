"""
onion_guardian.layer3_gateway.network_policy - network policy enforcement.

Layer 3 network access control.

Protection goals:
- block proxy and tunnel setup plus host IP leakage
- keep container networking isolated and prevent internal network discovery
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from onion_guardian.defaults import (
    DEFAULT_ALLOWED_DOMAINS,
    DEFAULT_ALLOWED_PORTS,
    DEFAULT_BLOCKED_NETWORKS,
    DEFAULT_MAX_CONCURRENT_CONNECTIONS,
    DEFAULT_MAX_DOWNLOAD_SIZE_MB,
    DEFAULT_NETWORK_MODE,
)


@dataclass
class NetworkPolicyConfig:
    """Network policy configuration."""
    mode: str = DEFAULT_NETWORK_MODE

    allowed_domains: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_DOMAINS))

    allowed_ports: list[int] = field(default_factory=lambda: list(DEFAULT_ALLOWED_PORTS))

    # IP ranges that are always blocked.
    blocked_networks: list[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_NETWORKS))

    # Secondary checks after DNS resolution to reduce rebinding risk.
    enable_dns_rebinding_protection: bool = True

    # Maximum number of concurrent connections.
    max_concurrent_connections: int = DEFAULT_MAX_CONCURRENT_CONNECTIONS

    # Maximum size for a single download.
    max_download_size_mb: int = DEFAULT_MAX_DOWNLOAD_SIZE_MB


class NetworkPolicy:
    """
    Network policy enforcer.

    Modes:
    1. `none`: block all network access
    2. `restricted`: allow only whitelisted domains and ports
    3. `open`: allow external access but still block internal networks
    """

    def __init__(self, config: NetworkPolicyConfig | None = None):
        self.config = config or NetworkPolicyConfig()
        self._blocked_nets = [
            ipaddress.ip_network(net) for net in self.config.blocked_networks
        ]
        self._active_connections: dict[str, int] = {}  # session_id → count

    def check_url(self, url: str, session_id: str = "") -> tuple[bool, str]:
        """
        Check whether a URL is allowed.

        Returns:
            (allowed, reason)
        """
        # Mode `none`: deny everything.
        if self.config.mode == "none":
            return False, "Network access is disabled (mode=none)"

        # Parse the URL.
        try:
            parsed = urlparse(url)
        except Exception:
            return False, f"Invalid URL: {url}"

        # Allow only HTTP(S).
        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported scheme: {parsed.scheme} (only http/https is allowed)"

        hostname = parsed.hostname or ""
        if not hostname:
            return False, f"Invalid URL hostname: {url}"

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Direct IP access needs an IP policy check.
        if self._is_ip_address(hostname):
            allowed, reason = self._check_ip(hostname)
            if not allowed:
                return False, reason
        else:
            allowed, reason = self._check_hostname(hostname)
            if not allowed:
                return False, reason

        # In restricted mode the hostname must be explicitly allowed.
        if self.config.mode == "restricted":
            if not self._is_domain_allowed(hostname):
                return False, (
                    f"Domain is not in the allowlist: {hostname}. "
                    f"Allowed domains: {', '.join(self.config.allowed_domains)}"
                )

        # Port checks apply in restricted mode.
        if self.config.mode == "restricted":
            if port not in self.config.allowed_ports:
                return False, f"Port is not in the allowlist: {port}"

        # Enforce concurrent connection limits per session.
        if session_id:
            current = self._active_connections.get(session_id, 0)
            if current >= self.config.max_concurrent_connections:
                return False, (
                    "Concurrent connection limit exceeded: "
                    f"{current}/{self.config.max_concurrent_connections}"
                )

        return True, "Network access allowed"

    def check_ip(self, ip_str: str) -> tuple[bool, str]:
        """Check whether an IP address is allowed."""
        return self._check_ip(ip_str)

    def acquire_connection(self, session_id: str) -> bool:
        """Acquire a connection slot."""
        current = self._active_connections.get(session_id, 0)
        if current >= self.config.max_concurrent_connections:
            return False
        self._active_connections[session_id] = current + 1
        return True

    def release_connection(self, session_id: str) -> None:
        """Release a connection slot."""
        current = self._active_connections.get(session_id, 0)
        self._active_connections[session_id] = max(0, current - 1)

    # Internal helpers.

    def _check_ip(self, ip_str: str) -> tuple[bool, str]:
        """Check whether an IP falls into a blocked range."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"

        for net in self._blocked_nets:
            if ip in net:
                return False, (
                    f"IP address {ip_str} is inside the blocked range {net}. "
                    "Internal and reserved addresses are not allowed."
                )

        return True, "IP address allowed"

    def _is_ip_address(self, hostname: str) -> bool:
        """Return whether the hostname is an IP literal."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _is_domain_allowed(self, hostname: str) -> bool:
        """Return whether the hostname is in the allowlist."""
        hostname = hostname.lower().rstrip(".")

        for allowed in self.config.allowed_domains:
            allowed = allowed.lower().rstrip(".")

            # Exact match.
            if hostname == allowed:
                return True

            # Subdomain match: *.example.com
            if hostname.endswith("." + allowed):
                return True

        return False

    def _check_hostname(self, hostname: str) -> tuple[bool, str]:
        normalized = hostname.lower().rstrip(".")
        labels = tuple(part for part in normalized.split(".") if part)

        if normalized == "localhost" or normalized.endswith(".localhost"):
            return False, "Localhost access is not allowed"

        if self._looks_like_metadata_host(labels):
            return False, "Metadata hosts are not allowed"

        if not self.config.enable_dns_rebinding_protection:
            return True, "Hostname allowed"

        try:
            resolved_ips = {
                addr[0]
                for *_prefix, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                for addr in (sockaddr,)
                if addr and addr[0]
            }
        except OSError:
            # Fall back to static hostname rules when DNS is unavailable.
            return True, "Hostname allowed"

        for ip_str in resolved_ips:
            allowed, reason = self._check_ip(ip_str)
            if not allowed:
                return False, (
                    f"Hostname resolves to a blocked address: {ip_str}. {reason}"
                )

        return True, "Hostname allowed"

    def _looks_like_metadata_host(self, labels: tuple[str, ...]) -> bool:
        if not labels:
            return False

        if labels[0] in {"metadata", "instance-data"}:
            return True

        return "metadata" in labels and "internal" in labels

    def generate_firewall_rules(self) -> list[str]:
        """
        Generate iptables firewall rules.

        These rules are meant to be applied by the surrounding infrastructure,
        for example when a container starts.
        """
        rules = [
            "# === Onion Guardian network policy ===",
            "# deny outbound traffic by default",
            "iptables -P OUTPUT DROP",
            "",
            "# allow loopback",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "",
            "# allow established connections",
            "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "",
        ]

        if self.config.mode == "none":
            rules.append("# mode: none - block all outbound traffic")
            return rules

        # Block internal networks.
        rules.append("# block internal networks")
        for net in self.config.blocked_networks:
            rules.append(f"iptables -A OUTPUT -d {net} -j DROP")
        rules.append("")

        if self.config.mode == "restricted":
            # Allow DNS.
            rules.extend([
                "# allow DNS",
                "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
                "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
                "",
            ])

            # Allow listed ports.
            ports = ",".join(str(p) for p in self.config.allowed_ports)
            rules.extend([
                f"# allow listed ports: {ports}",
                f"iptables -A OUTPUT -p tcp -m multiport --dports {ports} -j ACCEPT",
                "",
            ])

        elif self.config.mode == "open":
            # Allow external traffic after internal networks are dropped above.
            rules.extend([
                "# mode: open - allow external traffic",
                "iptables -A OUTPUT -j ACCEPT",
            ])

        return rules
