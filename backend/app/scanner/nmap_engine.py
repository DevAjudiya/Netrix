# ─────────────────────────────────────────
# Netrix — nmap_engine.py
# Purpose: Core Nmap scanning engine with configurable scan profiles,
#          result parsing, risk scoring, and database persistence.
# ─────────────────────────────────────────

import dataclasses
import json
import logging
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import nmap

logger = logging.getLogger("netrix")


# ─────────────────────────────────────────
# Enums
# ─────────────────────────────────────────
class ScanType(str, Enum):
    """Supported Nmap scan profiles."""

    QUICK = "quick"
    STEALTH = "stealth"
    FULL = "full"
    AGGRESSIVE = "aggressive"
    VULNERABILITY = "vulnerability"
    CUSTOM = "custom"


# ─────────────────────────────────────────
# Constants
# ─────────────────────────────────────────
CRITICAL_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017,
]

SCAN_PROFILES: Dict[str, Dict[str, str]] = {
    ScanType.QUICK: {
        "args": "-sV -T4 -F --open",
        "description": "Quick scan — service version detection on top 100 ports",
        "estimated_time": "1-3 minutes",
        "ports": "Top 100 ports",
    },
    ScanType.STEALTH: {
        "args": "-sS -sV -T2 -p- --open",
        "description": "Stealth SYN scan — low profile, all ports",
        "estimated_time": "15-30 minutes",
        "ports": "All 65535 ports",
    },
    ScanType.FULL: {
        "args": "-sS -sV -sC -O -A -T4 -p- --open",
        "description": "Full scan — service detection, OS fingerprint, scripts, all ports",
        "estimated_time": "20-45 minutes",
        "ports": "All 65535 ports",
    },
    ScanType.AGGRESSIVE: {
        "args": "-A -T4 -p- --open --traceroute",
        "description": "Aggressive scan — full detection with traceroute",
        "estimated_time": "30-60 minutes",
        "ports": "All 65535 ports",
    },
    ScanType.VULNERABILITY: {
        "args": (
            "-sV -T4 --script=vuln,exploit,auth,default,banner,"
            "http-headers,http-title,http-methods,ftp-anon,"
            "ssh-hostkey,ssh-auth-methods,smtp-commands,"
            "dns-recursion,smb-vuln-ms17-010,smb-vuln-ms08-067,"
            "http-shellshock,ssl-heartbleed,ssl-poodle,"
            "rdp-vuln-ms12-020,ftp-vsftpd-backdoor -p-"
        ),
        "description": "Vulnerability scan — full NSE scripts for known CVEs",
        "estimated_time": "45-90 minutes",
        "ports": "All 65535 ports",
    },
}


# ─────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────
@dataclass
class ServiceInfo:
    """Represents a single service discovered on a port."""

    port: int
    protocol: str
    state: str
    service_name: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    nse_scripts: Dict[str, str] = field(default_factory=dict)
    is_critical_port: bool = False
    is_vulnerable: bool = False


@dataclass
class OSInfo:
    """Represents the detected operating system of a host."""

    name: str = ""
    accuracy: int = 0
    os_family: str = ""
    os_generation: str = ""
    cpe: str = ""
    type: str = ""


@dataclass
class TracerouteHop:
    """A single hop in a traceroute path."""

    hop: int
    ip: str
    hostname: str = ""
    rtt: str = ""


@dataclass
class HostScanResult:
    """Complete scan results for a single host."""

    ip: str
    hostname: str = ""
    status: str = "unknown"
    mac_address: str = ""
    mac_vendor: str = ""
    os_info: OSInfo = field(default_factory=OSInfo)
    services: List[ServiceInfo] = field(default_factory=list)
    traceroute: List[TracerouteHop] = field(default_factory=list)
    uptime: str = ""
    tcp_sequence: str = ""
    risk_score: int = 0
    risk_level: str = "info"
    open_ports_count: int = 0
    critical_ports_open: List[int] = field(default_factory=list)
    vulnerabilities_found: List[str] = field(default_factory=list)
    scan_duration: float = 0.0


@dataclass
class ScanSummary:
    """Aggregated results for an entire scan execution."""

    scan_id: str
    target: str
    scan_type: str
    scan_profile: str
    nmap_command: str
    nmap_version: str
    started_at: str
    completed_at: str
    duration_seconds: float
    total_hosts: int
    hosts_up: int
    hosts_down: int
    hosts: List[HostScanResult] = field(default_factory=list)
    total_open_ports: int = 0
    total_vulnerabilities: int = 0
    critical_hosts: int = 0
    high_risk_hosts: int = 0
    scan_args_used: str = ""


# ─────────────────────────────────────────
# NmapEngine
# ─────────────────────────────────────────
class NmapEngine:
    """
    Core Nmap scanning engine for the Netrix platform.

    Wraps `python-nmap` and provides structured parsing of scan
    results into typed dataclasses, risk scoring, and database
    persistence.
    """

    def __init__(self) -> None:
        """
        Initialise the engine, verify that nmap is installed, and
        prepare internal tracking structures.

        Raises:
            RuntimeError: If the ``nmap`` binary cannot be found.
        """
        self.scan_progress: Dict[str, Dict[str, Any]] = {}

        try:
            self.nm = nmap.PortScanner()
            logger.info("[NETRIX] Nmap Engine initialised — nmap found")
        except nmap.PortScannerError as init_error:
            logger.error(
                "[NETRIX] Nmap is not installed or not in PATH: %s",
                str(init_error),
            )
            raise RuntimeError(
                "Nmap is not installed or not accessible. "
                "Install it with: apt install nmap"
            ) from init_error

    # ─────────────────────────────────────
    # Scan ID generator
    # ─────────────────────────────────────
    @staticmethod
    def _generate_scan_id() -> str:
        """Generate a unique scan identifier in ``NETRIX_XXXXXX`` format."""
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"NETRIX_{suffix}"

    # ─────────────────────────────────────
    # Progress helpers
    # ─────────────────────────────────────
    def _update_progress(
        self,
        scan_id: str,
        progress: int,
        status: str,
        message: str = "",
        callback: Optional[Callable] = None,
    ) -> None:
        """Update internal progress tracker and invoke callback if set."""
        self.scan_progress[scan_id] = {
            "progress": min(progress, 100),
            "status": status,
            "message": message,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(
            "[NETRIX] %s | %s — %d%% — %s",
            datetime.now(timezone.utc).isoformat(),
            scan_id,
            progress,
            message or status,
        )
        if callback:
            try:
                callback(scan_id, progress, status, message)
            except Exception as cb_err:
                logger.warning("[NETRIX] Progress callback error: %s", str(cb_err))

    # ─────────────────────────────────────
    # Main scan entry point
    # ─────────────────────────────────────
    def run_scan(
        self,
        target: str,
        scan_type: ScanType = ScanType.FULL,
        custom_args: str = "",
        custom_ports: str = "",
        scan_id: Optional[str] = None,
        callback: Optional[Callable] = None,
    ) -> ScanSummary:
        """
        Execute a complete Nmap scan against the specified target.

        Args:
            target:       IP address, CIDR range, or domain name.
            scan_type:    One of the ``ScanType`` enum values.
            custom_args:  Custom nmap argument string (used when
                          ``scan_type`` is ``CUSTOM``).
            custom_ports: Custom port specification (e.g. ``"22,80,443"``
                          or ``"1-1024"``).
            scan_id:      Optional pre-assigned identifier. Generated
                          automatically if not provided.
            callback:     Optional progress callback ``(scan_id, progress,
                          status, message) -> None``.

        Returns:
            ScanSummary: Structured results covering every discovered host.

        Raises:
            RuntimeError: If the nmap binary fails or results cannot be
                          parsed.
        """
        if scan_id is None:
            scan_id = self._generate_scan_id()

        started_at = datetime.now(timezone.utc)

        # ── Determine nmap arguments ─────────────────────────────
        if scan_type == ScanType.CUSTOM:
            args = custom_args if custom_args else "-sV -T4 --open"
        else:
            profile = SCAN_PROFILES.get(scan_type, SCAN_PROFILES[ScanType.FULL])
            args = profile["args"]

        if custom_ports:
            # Remove any existing -p flag and append custom ports
            args_parts = args.split()
            args_parts = [p for p in args_parts if not p.startswith("-p")]
            args = " ".join(args_parts) + f" -p {custom_ports}"

        self._update_progress(
            scan_id, 5, "starting",
            f"Preparing {scan_type.value} scan on {target}",
            callback,
        )

        logger.info("[NETRIX] %s | Starting %s scan on %s", datetime.now(timezone.utc).isoformat(), scan_type.value, target)
        logger.info("[NETRIX] %s | Command: nmap %s %s", datetime.now(timezone.utc).isoformat(), args, target)

        # ── Execute nmap ─────────────────────────────────────────
        self._update_progress(
            scan_id, 10, "running",
            "Nmap scan in progress — waiting for results",
            callback,
        )

        try:
            self.nm.scan(hosts=target, arguments=args)
        except nmap.PortScannerError as scan_error:
            self._update_progress(scan_id, 100, "failed", str(scan_error), callback)
            logger.error("[NETRIX] Nmap scan failed: %s", str(scan_error))
            raise RuntimeError(f"Nmap scan failed: {scan_error}") from scan_error
        except Exception as unexpected_error:
            self._update_progress(scan_id, 100, "failed", str(unexpected_error), callback)
            logger.error("[NETRIX] Unexpected scan error: %s", str(unexpected_error))
            raise RuntimeError(f"Scan error: {unexpected_error}") from unexpected_error

        self._update_progress(
            scan_id, 70, "running",
            "Nmap scan complete — parsing results",
            callback,
        )

        # ── Parse results ────────────────────────────────────────
        hosts = self._parse_results(scan_id)

        self._update_progress(
            scan_id, 90, "running",
            f"Parsed {len(hosts)} host(s) — calculating risk scores",
            callback,
        )

        completed_at = datetime.now(timezone.utc)
        duration = (completed_at - started_at).total_seconds()

        # ── Retrieve nmap metadata ───────────────────────────────
        nmap_command = self.nm.command_line() if hasattr(self.nm, "command_line") else f"nmap {args} {target}"

        try:
            nmap_version = self.nm.nmap_version()
            nmap_version_str = ".".join(str(v) for v in nmap_version) if isinstance(nmap_version, tuple) else str(nmap_version)
        except Exception:
            nmap_version_str = "unknown"

        # ── Build summary ────────────────────────────────────────
        hosts_up = sum(1 for h in hosts if h.status == "up")
        hosts_down = len(hosts) - hosts_up
        total_open_ports = sum(h.open_ports_count for h in hosts)
        total_vulns = sum(len(h.vulnerabilities_found) for h in hosts)
        critical_hosts = sum(1 for h in hosts if h.risk_level == "critical")
        high_risk_hosts = sum(1 for h in hosts if h.risk_level == "high")

        profile_desc = ""
        if scan_type != ScanType.CUSTOM:
            prof = SCAN_PROFILES.get(scan_type)
            profile_desc = prof["description"] if prof else ""

        summary = ScanSummary(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type.value,
            scan_profile=profile_desc,
            nmap_command=nmap_command,
            nmap_version=nmap_version_str,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            duration_seconds=round(duration, 2),
            total_hosts=len(hosts),
            hosts_up=hosts_up,
            hosts_down=hosts_down,
            hosts=hosts,
            total_open_ports=total_open_ports,
            total_vulnerabilities=total_vulns,
            critical_hosts=critical_hosts,
            high_risk_hosts=high_risk_hosts,
            scan_args_used=args,
        )

        self._update_progress(
            scan_id, 100, "completed",
            f"Scan complete — {hosts_up} host(s) up, "
            f"{total_open_ports} open port(s), {total_vulns} vuln(s)",
            callback,
        )

        logger.info(
            "[NETRIX] %s | Scan %s complete — %d host(s), %d port(s), %d vuln(s) in %.1fs",
            datetime.now(timezone.utc).isoformat(),
            scan_id, len(hosts), total_open_ports, total_vulns, duration,
        )

        return summary

    # ─────────────────────────────────────
    # Result parsing
    # ─────────────────────────────────────
    def _parse_results(self, scan_id: str) -> List[HostScanResult]:
        """
        Iterate over every host in the nmap results and produce
        a list of fully-parsed ``HostScanResult`` objects.
        """
        hosts: List[HostScanResult] = []

        try:
            all_hosts = self.nm.all_hosts()
        except Exception as parse_err:
            logger.warning("[NETRIX] No hosts in scan results: %s", str(parse_err))
            return hosts

        for host_ip in all_hosts:
            try:
                host_result = self._parse_host(host_ip)
                hosts.append(host_result)
            except Exception as host_err:
                logger.warning(
                    "[NETRIX] Error parsing host %s: %s",
                    host_ip, str(host_err),
                )

        return hosts

    def _parse_host(self, host_ip: str) -> HostScanResult:
        """
        Deep-parse a single host, extracting every available piece
        of information from the nmap result tree.
        """
        host_data = self.nm[host_ip]

        # ── Basic identity ───────────────────────────────────────
        hostname = ""
        try:
            hostname = host_data.hostname()
        except Exception:
            pass

        status = "unknown"
        try:
            status = host_data.state()
        except Exception:
            pass

        # ── MAC address ──────────────────────────────────────────
        mac_address = ""
        mac_vendor = ""
        try:
            addresses = host_data.get("addresses", {})
            mac_address = addresses.get("mac", "")
        except Exception:
            pass

        try:
            vendor = host_data.get("vendor", {})
            if mac_address and vendor:
                mac_vendor = vendor.get(mac_address, "")
        except Exception:
            pass

        # ── Uptime & TCP sequence ────────────────────────────────
        uptime = ""
        try:
            uptime_data = host_data.get("uptime", {})
            if uptime_data:
                seconds = uptime_data.get("seconds", "")
                last_boot = uptime_data.get("lastboot", "")
                if seconds:
                    uptime = f"{seconds}s (last boot: {last_boot})"
        except Exception:
            pass

        tcp_sequence = ""
        try:
            tcp_seq_data = host_data.get("tcp_sequence", {})
            if tcp_seq_data:
                tcp_sequence = tcp_seq_data.get("difficulty", "")
        except Exception:
            pass

        # ── Delegate sub-parsing ─────────────────────────────────
        os_info = self._parse_os(host_ip)
        services = self._parse_services(host_ip)
        traceroute = self._parse_traceroute(host_ip)

        # ── Derived metrics ──────────────────────────────────────
        open_ports = [s for s in services if s.state == "open"]
        critical_open = [s.port for s in open_ports if s.is_critical_port]
        vulns_found = []
        for svc in services:
            for script_name, script_output in svc.nse_scripts.items():
                if self._is_vulnerable_output(script_output):
                    vulns_found.append(script_name)

        result = HostScanResult(
            ip=host_ip,
            hostname=hostname,
            status=status,
            mac_address=mac_address,
            mac_vendor=mac_vendor,
            os_info=os_info,
            services=services,
            traceroute=traceroute,
            uptime=uptime,
            tcp_sequence=tcp_sequence,
            open_ports_count=len(open_ports),
            critical_ports_open=critical_open,
            vulnerabilities_found=vulns_found,
        )

        # ── Risk assessment ──────────────────────────────────────
        score, level = self._calculate_risk_score(result)
        result.risk_score = score
        result.risk_level = level

        return result

    # ─────────────────────────────────────
    # OS detection
    # ─────────────────────────────────────
    def _parse_os(self, host_ip: str) -> OSInfo:
        """
        Extract the best OS match from nmap's fingerprint engine.

        Returns an empty ``OSInfo`` if no match is available.
        """
        try:
            host_data = self.nm[host_ip]
            os_matches = host_data.get("osmatch", [])

            if not os_matches:
                return OSInfo()

            # Best match = highest accuracy
            best = max(os_matches, key=lambda m: int(m.get("accuracy", 0)))

            os_family = ""
            os_generation = ""
            cpe = ""
            os_type = ""

            os_classes = best.get("osclass", [])
            if os_classes:
                top_class = os_classes[0]
                os_family = top_class.get("osfamily", "")
                os_generation = top_class.get("osgen", "")
                os_type = top_class.get("type", "")
                cpe_list = top_class.get("cpe", [])
                cpe = cpe_list[0] if cpe_list else ""

            return OSInfo(
                name=best.get("name", ""),
                accuracy=int(best.get("accuracy", 0)),
                os_family=os_family,
                os_generation=os_generation,
                cpe=cpe,
                type=os_type,
            )
        except Exception as os_err:
            logger.debug("[NETRIX] OS detection parse error for %s: %s", host_ip, str(os_err))
            return OSInfo()

    # ─────────────────────────────────────
    # Service / port parsing
    # ─────────────────────────────────────
    def _parse_services(self, host_ip: str) -> List[ServiceInfo]:
        """
        Extract every discovered port and its service fingerprint.

        Iterates over TCP and UDP protocols and returns results
        sorted by port number.
        """
        services: List[ServiceInfo] = []

        try:
            host_data = self.nm[host_ip]
        except KeyError:
            return services

        for protocol in ("tcp", "udp"):
            try:
                ports = host_data.get(protocol, {})
            except Exception:
                continue

            if not isinstance(ports, dict):
                continue

            for port_number, port_data in ports.items():
                try:
                    state = port_data.get("state", "unknown")
                    service_name = port_data.get("name", "unknown")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    extra_info = port_data.get("extrainfo", "")
                    cpe = port_data.get("cpe", "")

                    # NSE script output
                    nse_scripts = self._parse_nse_scripts(port_data)

                    # Flags
                    is_critical = int(port_number) in CRITICAL_PORTS
                    is_vuln = any(
                        self._is_vulnerable_output(output)
                        for output in nse_scripts.values()
                    )

                    svc = ServiceInfo(
                        port=int(port_number),
                        protocol=protocol,
                        state=state,
                        service_name=service_name,
                        product=product,
                        version=version,
                        extra_info=extra_info,
                        cpe=cpe,
                        nse_scripts=nse_scripts,
                        is_critical_port=is_critical,
                        is_vulnerable=is_vuln,
                    )
                    services.append(svc)

                except Exception as svc_err:
                    logger.debug(
                        "[NETRIX] Error parsing port %s/%s on %s: %s",
                        port_number, protocol, host_ip, str(svc_err),
                    )

        services.sort(key=lambda s: s.port)
        return services

    # ─────────────────────────────────────
    # NSE script output
    # ─────────────────────────────────────
    def _parse_nse_scripts(self, port_data: dict) -> Dict[str, str]:
        """
        Extract NSE script names and their output from a port's
        result dictionary.
        """
        scripts: Dict[str, str] = {}

        try:
            script_data = port_data.get("script", {})
            if not isinstance(script_data, dict):
                return scripts

            for script_name, output in script_data.items():
                cleaned = " ".join(str(output).split()) if output else ""
                scripts[script_name] = cleaned

        except Exception as nse_err:
            logger.debug("[NETRIX] NSE parse error: %s", str(nse_err))

        return scripts

    @staticmethod
    def _is_vulnerable_output(output: str) -> bool:
        """Check whether NSE output indicates a vulnerability."""
        if not output:
            return False
        upper = output.upper()
        indicators = [
            "VULNERABLE",
            "STATE: VULNERABLE",
            "RISK FACTOR:",
            "EXPLOIT AVAILABLE",
        ]
        return any(kw in upper for kw in indicators)

    # ─────────────────────────────────────
    # Traceroute
    # ─────────────────────────────────────
    def _parse_traceroute(self, host_ip: str) -> List[TracerouteHop]:
        """
        Extract traceroute hops when available.

        Returns an empty list if the scan profile did not include
        ``--traceroute``.
        """
        hops: List[TracerouteHop] = []

        try:
            host_data = self.nm[host_ip]
            trace = host_data.get("trace", {})

            if not trace:
                return hops

            for hop_data in trace.get("hops", []):
                hop = TracerouteHop(
                    hop=int(hop_data.get("ttl", 0)),
                    ip=hop_data.get("ipaddr", ""),
                    hostname=hop_data.get("host", ""),
                    rtt=hop_data.get("rtt", ""),
                )
                hops.append(hop)

        except Exception as trace_err:
            logger.debug("[NETRIX] Traceroute parse error for %s: %s", host_ip, str(trace_err))

        return hops

    # ─────────────────────────────────────
    # Risk scoring
    # ─────────────────────────────────────
    def _calculate_risk_score(self, host: HostScanResult) -> Tuple[int, str]:
        """
        Calculate a risk score (0–100) and level for a host.

        Scoring breakdown:
            - Critical ports open (weighted per port)
            - NSE vulnerability detections (+20 each)
            - Open-port count tiers
            - Outdated-service keyword detection

        Risk levels:
            - 0–20  → info
            - 21–40 → low
            - 41–60 → medium
            - 61–80 → high
            - 81–100 → critical

        Returns:
            Tuple of ``(score, level)``.
        """
        score = 0

        # ── Critical port weights ────────────────────────────────
        port_weights: Dict[int, int] = {
            23: 20,    # Telnet
            3389: 15,  # RDP
            445: 15,   # SMB
            21: 10,    # FTP
            22: 5,     # SSH
        }

        for port_num in host.critical_ports_open:
            score += port_weights.get(port_num, 5)

        # ── NSE vulnerability hits ───────────────────────────────
        score += len(host.vulnerabilities_found) * 20

        # ── Open-port tiers ──────────────────────────────────────
        open_count = host.open_ports_count
        if open_count >= 16:
            score += 15
        elif open_count >= 6:
            score += 10
        elif open_count >= 1:
            score += 5

        # ── Outdated service detection ───────────────────────────
        outdated_keywords = ("old", "1.0", "1.1", "1.x", "2.0", "2.x", "eol", "deprecated")
        for svc in host.services:
            version = f"{svc.product} {svc.version} {svc.extra_info}".lower()
            if any(kw in version for kw in outdated_keywords):
                score += 10
                break  # Only penalise once

        # ── Cap at 100 ───────────────────────────────────────────
        score = min(score, 100)

        # ── Map to risk level ────────────────────────────────────
        if score >= 81:
            level = "critical"
        elif score >= 61:
            level = "high"
        elif score >= 41:
            level = "medium"
        elif score >= 21:
            level = "low"
        else:
            level = "info"

        return score, level

    # ─────────────────────────────────────
    # Progress query
    # ─────────────────────────────────────
    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """
        Return the current progress for the given scan.

        Returns a default dict with ``progress=0`` if the scan ID is
        not tracked.
        """
        return self.scan_progress.get(scan_id, {
            "progress": 0,
            "status": "unknown",
            "message": "No progress data available",
            "updated_at": None,
        })

    # ─────────────────────────────────────
    # Serialisation helpers
    # ─────────────────────────────────────
    def to_dict(self, summary: ScanSummary) -> Dict[str, Any]:
        """
        Convert a ``ScanSummary`` (and all nested dataclasses)
        to a plain dictionary.
        """
        try:
            return dataclasses.asdict(summary)
        except Exception as conv_err:
            logger.warning("[NETRIX] Serialisation fallback: %s", str(conv_err))
            return {"error": str(conv_err)}

    def to_json(self, summary: ScanSummary) -> str:
        """
        Serialise a ``ScanSummary`` to a formatted JSON string.
        """
        try:
            return json.dumps(self.to_dict(summary), indent=2, default=str)
        except Exception as json_err:
            logger.error("[NETRIX] JSON serialisation error: %s", str(json_err))
            return json.dumps({"error": str(json_err)})

    # ─────────────────────────────────────
    # Database persistence
    # ─────────────────────────────────────
    def save_to_database(
        self,
        summary: ScanSummary,
        db_session,
        user_id: int,
    ) -> int:
        """
        Persist a complete ``ScanSummary`` into MySQL.

        Process:
            1. Look up / create the ``Scan`` record.
            2. For each ``HostScanResult`` → ``Host`` row.
            3. For each ``ServiceInfo`` → ``Port`` row.
            4. For each NSE vulnerability → ``Vulnerability`` row.
            5. Update the ``Scan`` record with final stats.

        Args:
            summary:    The completed ``ScanSummary``.
            db_session: Active SQLAlchemy ``Session``.
            user_id:    ID of the user who initiated the scan.

        Returns:
            int: The database primary-key ID of the ``Scan`` record.

        Raises:
            RuntimeError: On any database error (rolls back first).
        """
        from app.models.host import Host
        from app.models.port import Port
        from app.models.scan import Scan
        from app.models.vulnerability import Vulnerability

        try:
            # ── Step 1: Scan record ──────────────────────────────
            scan = (
                db_session.query(Scan)
                .filter(Scan.scan_id == summary.scan_id)
                .first()
            )

            if scan is None:
                scan = Scan(
                    scan_id=summary.scan_id,
                    user_id=user_id,
                    target=summary.target,
                    target_type=self._detect_target_type(summary.target),
                    scan_type=summary.scan_type,
                    scan_args=summary.scan_args_used,
                    status="running",
                    nmap_version=summary.nmap_version,
                )
                db_session.add(scan)
                db_session.flush()

            scan.status = "running"
            scan.started_at = datetime.fromisoformat(summary.started_at)
            db_session.flush()

            logger.info(
                "[NETRIX] %s | Saving scan %s to database (Scan.id=%d)",
                datetime.now(timezone.utc).isoformat(),
                summary.scan_id, scan.id,
            )

            # ── Step 2: Host records ─────────────────────────────
            for host_data in summary.hosts:
                host = Host(
                    scan_id=scan.id,
                    ip_address=host_data.ip,
                    hostname=host_data.hostname,
                    status=host_data.status,
                    os_name=host_data.os_info.name,
                    os_accuracy=host_data.os_info.accuracy,
                    os_family=host_data.os_info.os_family,
                    os_generation=host_data.os_info.os_generation,
                    os_cpe=host_data.os_info.cpe,
                    mac_address=host_data.mac_address,
                    mac_vendor=host_data.mac_vendor,
                    uptime=host_data.uptime,
                    tcp_sequence=host_data.tcp_sequence,
                    risk_score=host_data.risk_score,
                    risk_level=host_data.risk_level,
                )
                db_session.add(host)
                db_session.flush()

                logger.info(
                    "[NETRIX] %s | Saved host %s (Host.id=%d, risk=%d/%s)",
                    datetime.now(timezone.utc).isoformat(),
                    host_data.ip, host.id,
                    host_data.risk_score, host_data.risk_level,
                )

                # ── Step 3: Port records ─────────────────────────
                for svc in host_data.services:
                    port = Port(
                        host_id=host.id,
                        port_number=svc.port,
                        protocol=svc.protocol,
                        state=svc.state,
                        service_name=svc.service_name,
                        product=svc.product,
                        version=svc.version,
                        extra_info=svc.extra_info,
                        cpe=svc.cpe,
                        nse_output=svc.nse_scripts if svc.nse_scripts else None,
                        is_critical_port=svc.is_critical_port,
                    )
                    db_session.add(port)
                    db_session.flush()

                    # ── Step 4: Vulnerability records ────────────
                    for script_name, script_output in svc.nse_scripts.items():
                        if self._is_vulnerable_output(script_output):
                            vuln = Vulnerability(
                                port_id=port.id,
                                scan_id=scan.id,
                                host_id=host.id,
                                title=f"NSE: {script_name}",
                                description=script_output[:2000],
                                severity=self._severity_from_script(script_name),
                                source="nse_script",
                                nse_script_name=script_name,
                                nse_output=script_output,
                                is_confirmed=True,
                            )
                            db_session.add(vuln)

                            logger.info(
                                "[NETRIX] %s | Vulnerability: %s on %s:%d",
                                datetime.now(timezone.utc).isoformat(),
                                script_name, host_data.ip, svc.port,
                            )

            # ── Step 5: Finalise scan record ─────────────────────
            scan.status = "completed"
            scan.progress = 100
            scan.total_hosts = summary.total_hosts
            scan.hosts_up = summary.hosts_up
            scan.hosts_down = summary.hosts_down
            scan.completed_at = datetime.fromisoformat(summary.completed_at)

            db_session.commit()

            logger.info(
                "[NETRIX] %s | Scan %s saved successfully — "
                "%d host(s), %d vuln(s)",
                datetime.now(timezone.utc).isoformat(),
                summary.scan_id, summary.total_hosts,
                summary.total_vulnerabilities,
            )

            return scan.id

        except Exception as db_err:
            db_session.rollback()
            logger.error(
                "[NETRIX] Database save failed for scan %s: %s",
                summary.scan_id, str(db_err),
            )
            raise RuntimeError(
                f"Failed to save scan results: {db_err}"
            ) from db_err

    # ─────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────
    @staticmethod
    def _detect_target_type(target: str) -> str:
        """Infer the target type from the target string."""
        if "/" in target:
            return "cidr"
        parts = target.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return "ip"
        return "domain"

    @staticmethod
    def _severity_from_script(script_name: str) -> str:
        """
        Map well-known NSE script names to a severity level.

        Falls back to ``"medium"`` for unrecognised scripts.
        """
        critical_scripts = {
            "smb-vuln-ms17-010", "smb-vuln-ms08-067",
            "ftp-vsftpd-backdoor", "http-shellshock",
        }
        high_scripts = {
            "ssl-heartbleed", "ssl-poodle",
            "rdp-vuln-ms12-020", "http-sql-injection",
            "http-vuln-cve2014-3704", "http-vuln-cve2017-5638",
        }
        medium_scripts = {
            "http-csrf", "http-dombased-xss",
            "http-methods", "dns-recursion",
        }

        name_lower = script_name.lower()
        if name_lower in critical_scripts:
            return "critical"
        if name_lower in high_scripts:
            return "high"
        if name_lower in medium_scripts:
            return "medium"
        return "medium"
