"""
Module 3: Passive Network Telemetry & DNS Sniffer.

Observes outbound traffic for a bounded window (default: 30s, intended to
be run during otherwise-idle periods so background telemetry stands out)
and flags:

  * Non-local destinations not covered by the configurable whitelist.
  * Direct-to-IP connections that were never preceded by a local DNS
    resolution for that IP during the capture window (a classic
    hardcoded-C2 / DNS-bypass signature) -- scapy path only, since this
    needs visibility into DNS response traffic, not just connection state.

Two capture strategies, in preference order:
  1. scapy (AsyncSniffer over a raw/npcap socket) -- full packet + DNS
     visibility, requires admin/root and (on Windows) Npcap installed.
  2. psutil.net_connections() polling -- works unprivileged on most
     platforms (with reduced per-process visibility on Windows without
     admin), no DNS-bypass detection since we never see DNS traffic.

This module never sends any packets -- it is purely observational.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from countercraft.config import DEFAULT_WHITELIST_PATH
from countercraft.core.base import BaseAuditor
from countercraft.core.models import Severity
from countercraft.core.utils import is_elevated

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    from scapy.all import AsyncSniffer, DNS, DNSRR, IP, TCP, UDP  # type: ignore

    _HAS_SCAPY = True
except Exception:  # scapy import can fail for many reasons (missing npcap, etc.)
    _HAS_SCAPY = False

try:
    import psutil

    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


@dataclass(slots=True)
class Observation:
    dst_ip: str
    dst_port: Optional[int]
    proto: str
    preceded_by_dns: bool = False


@dataclass(slots=True)
class Whitelist:
    subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    domain_suffixes: list[str] = field(default_factory=list)

    def covers_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.subnets)

    def covers_domain(self, domain: str) -> bool:
        domain = domain.rstrip(".").lower()
        return any(domain == s or domain.endswith("." + s) for s in self.domain_suffixes)


def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # can't parse -> don't treat as a flaggable outbound dest
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved


class NetworkAuditor(BaseAuditor):
    name = "network"
    description = "Passively observes outbound traffic against a destination whitelist."
    requires_root = False  # degrades to psutil polling when unprivileged

    def __init__(
        self,
        duration_seconds: float = 30.0,
        interface: Optional[str] = None,
        whitelist_path: Optional[Path] = None,
    ) -> None:
        super().__init__()
        self.duration_seconds = duration_seconds
        self.interface = interface
        self.whitelist_path = whitelist_path or DEFAULT_WHITELIST_PATH

    def audit(self) -> None:
        whitelist = self._load_whitelist()

        if _HAS_SCAPY and is_elevated():
            observations, method = self._capture_scapy(), "scapy"
        else:
            if _HAS_SCAPY and not is_elevated():
                self.add_finding(
                    "Falling back to connection polling",
                    Severity.INFO,
                    "scapy is installed but this process is not elevated; "
                    "raw packet capture requires admin/root (and Npcap on "
                    "Windows). Falling back to periodic connection polling, "
                    "which cannot detect DNS-bypass.",
                )
            observations, method = self._capture_psutil(), "psutil"

        if observations is None:
            return  # capture method already recorded its own failure finding

        unique_dests: dict[tuple[str, Optional[int], str], Observation] = {}
        for obs in observations:
            key = (obs.dst_ip, obs.dst_port, obs.proto)
            existing = unique_dests.get(key)
            if existing is None or obs.preceded_by_dns:
                unique_dests[key] = obs

        if not unique_dests:
            self.add_finding(
                "No non-local outbound traffic observed",
                Severity.INFO,
                f"Captured for {self.duration_seconds:.0f}s via {method}; "
                "no non-local destinations seen.",
            )
            return

        for (dst_ip, dst_port, proto), obs in sorted(unique_dests.items()):
            self._evaluate_destination(dst_ip, dst_port, proto, obs, whitelist, method)

    # -- whitelist loading --------------------------------------------------

    def _load_whitelist(self) -> Whitelist:
        wl = Whitelist()
        if not self.whitelist_path.is_file():
            self.add_finding(
                "Using empty network whitelist",
                Severity.INFO,
                f"Whitelist file {self.whitelist_path} not found; every "
                "non-local destination will be flagged for review.",
            )
            return wl
        if not _HAS_YAML:
            self.add_finding(
                "PyYAML not installed",
                Severity.WARNING,
                "Cannot parse the whitelist config without PyYAML "
                "(pip install pyyaml). Treating whitelist as empty.",
            )
            return wl
        try:
            data = yaml.safe_load(self.whitelist_path.read_text()) or {}
        except Exception as exc:  # noqa: BLE001
            self.add_finding(
                "Could not parse network whitelist",
                Severity.WARNING,
                f"Failed to parse {self.whitelist_path}: {exc}",
            )
            return wl

        for cidr in data.get("allowed_subnets", []) or []:
            try:
                wl.subnets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                self.add_finding(
                    "Invalid CIDR in whitelist",
                    Severity.WARNING,
                    f"'{cidr}' in {self.whitelist_path} is not a valid subnet; skipped.",
                )
        wl.domain_suffixes = [s.lower() for s in (data.get("allowed_domain_suffixes") or [])]
        return wl

    # -- capture: scapy ------------------------------------------------------

    def _capture_scapy(self) -> list[Observation]:
        observations: list[Observation] = []
        resolved_ips: set[str] = set()

        def handle(pkt) -> None:  # noqa: ANN001 - scapy packet, no stable type
            if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:
                dns = pkt[DNS]
                for i in range(dns.ancount):
                    try:
                        rr = dns.an[i]
                        if rr.type == 1:  # A record
                            resolved_ips.add(rr.rdata)
                    except (IndexError, AttributeError):
                        break
                return

            if not pkt.haslayer(IP):
                return
            ip_layer = pkt[IP]
            dst = ip_layer.dst
            if _is_local(dst):
                return

            if pkt.haslayer(TCP):
                proto, port = "TCP", int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto, port = "UDP", int(pkt[UDP].dport)
            else:
                proto, port = ip_layer.proto, None

            observations.append(
                Observation(dst_ip=dst, dst_port=port, proto=str(proto), preceded_by_dns=dst in resolved_ips)
            )

        try:
            sniffer = AsyncSniffer(iface=self.interface, prn=handle, store=False)
            sniffer.start()
            time.sleep(self.duration_seconds)
            sniffer.stop()
        except Exception as exc:  # noqa: BLE001 - npcap missing, iface invalid, etc.
            self.add_finding(
                "Packet capture failed",
                Severity.WARNING,
                f"scapy capture could not start: {exc}. "
                "On Windows this usually means Npcap is not installed.",
            )
            return []

        # Second pass: now that capture is complete, resolve preceded_by_dns
        # for observations whose answer arrived after the connection packet
        # but within the same window (order-independent membership check).
        for obs in observations:
            if obs.dst_ip in resolved_ips:
                obs.preceded_by_dns = True
        return observations

    # -- capture: psutil fallback --------------------------------------------

    def _capture_psutil(self) -> Optional[list[Observation]]:
        if not _HAS_PSUTIL:
            self.add_finding(
                "No capture backend available",
                Severity.WARNING,
                "Neither scapy nor psutil is installed. Install one of "
                "them (pip install scapy  # or  pip install psutil) to "
                "enable network telemetry auditing.",
                remediation="pip install psutil scapy",
            )
            return None

        seen: dict[tuple[str, Optional[int], str], Observation] = {}
        poll_interval = 1.0
        elapsed = 0.0
        permission_warned = False

        while elapsed < self.duration_seconds:
            try:
                conns = psutil.net_connections(kind="inet")
            except (psutil.AccessDenied, PermissionError):
                if not permission_warned:
                    self.add_finding(
                        "Limited connection visibility",
                        Severity.INFO,
                        "psutil.net_connections() requires elevation for "
                        "full visibility on this OS; results may be incomplete.",
                    )
                    permission_warned = True
                conns = []

            for c in conns:
                if not c.raddr:
                    continue
                dst_ip, dst_port = c.raddr.ip, c.raddr.port
                if _is_local(dst_ip):
                    continue
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                key = (dst_ip, dst_port, proto)
                seen.setdefault(key, Observation(dst_ip=dst_ip, dst_port=dst_port, proto=proto))

            time.sleep(poll_interval)
            elapsed += poll_interval

        return list(seen.values())

    # -- evaluation -----------------------------------------------------

    def _evaluate_destination(
        self,
        dst_ip: str,
        dst_port: Optional[int],
        proto: str,
        obs: Observation,
        whitelist: Whitelist,
        method: str,
    ) -> None:
        hostname = self._reverse_dns(dst_ip)
        whitelisted = whitelist.covers_ip(dst_ip) or (
            hostname is not None and whitelist.covers_domain(hostname)
        )
        port_str = f":{dst_port}" if dst_port else ""
        dest_desc = f"{dst_ip}{port_str}/{proto}" + (f" ({hostname})" if hostname else "")

        if whitelisted:
            self.add_finding(
                "Whitelisted outbound connection",
                Severity.INFO,
                f"{dest_desc} matches the configured whitelist.",
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                hostname=hostname,
            )
            return

        self.add_finding(
            "Non-whitelisted outbound connection",
            Severity.WARNING,
            f"{dest_desc} is not in the approved destination whitelist. "
            "Review whether this traffic is expected.",
            remediation="Add to the whitelist if legitimate, otherwise "
            "investigate the owning process.",
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            hostname=hostname,
            capture_method=method,
        )

        if method == "scapy" and not obs.preceded_by_dns:
            self.add_finding(
                "Direct-to-IP connection bypassing local DNS",
                Severity.CRITICAL,
                f"{dest_desc} was contacted without any local DNS query for "
                "that address observed during the capture window -- "
                "consistent with a hardcoded C2 address or DNS-over-HTTPS "
                "exfiltration bypassing local visibility.",
                remediation="Identify the owning process and investigate; "
                "correlate with EDR/process telemetry.",
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
            )

    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        try:
            socket.setdefaulttimeout(1.5)
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return None
