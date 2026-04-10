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
import threading
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

# ─────────────────────────────────────────
# Scan profile definitions
# Each profile drives two separate nmap passes:
#   phase1 = fast SYN sweep to discover which ports are open
#   phase2 = version/OS/script detection ONLY on the discovered open ports
#
# Splitting the passes is critical: running -sV against 65 535 ports is
# 100x slower than running it against the 10-30 typically-open ones.
# ─────────────────────────────────────────
SCAN_PROFILES = {
    # ── Quick ─────────────────────────────────────────────────────
    # Top-1000 ports, moderate speed, version + key banners.
    # Good for a first look at a host without being too noisy.
    "quick": {
        "phase1": "-sS -Pn -T4 --open --top-ports 1000 --min-rate 500 --max-retries 2",
        "phase2_flags": "-sS -sV --version-intensity 7 -Pn -T4 --open",
        "phase2_scripts": "--script=banner,http-title,http-server-header,ssh-hostkey,ftp-anon",
        "os_detect": False,
        "p1_timeout": "120s",
        "p2_timeout": "300s",
        "time": "2-5 min",
    },
    # ── Stealth ────────────────────────────────────────────────────
    # Ports 1-1000, slow T2 timing to minimise IDS/firewall triggers.
    # Banner script only — minimal script footprint.
    "stealth": {
        "phase1": "-sS -Pn -T2 --open -p 1-1000 --min-rate 100 --max-retries 3",
        "phase2_flags": "-sT -sV --version-intensity 5 -Pn -T2 --open",
        "phase2_scripts": "--script=banner",
        "os_detect": False,
        "p1_timeout": "300s",
        "p2_timeout": "600s",
        "time": "5-10 min",
    },
    # ── Full ───────────────────────────────────────────────────────
    # All 65 535 TCP ports.  Phase 1 is fast; Phase 2 adds OS + rich scripts.
    "full": {
        "phase1": "-sS -Pn -T4 --open -p 1-65535 --min-rate 1000 --max-retries 2",
        "phase2_flags": "-sS -sV --version-intensity 9 -O -Pn -T4 --open",
        "phase2_scripts": (
            "--script=banner,http-title,http-server-header,http-methods,"
            "ssh-hostkey,ftp-anon,ssl-cert,smtp-commands,dns-recursion"
        ),
        "os_detect": True,
        "p1_timeout": "600s",
        "p2_timeout": "900s",
        "time": "10-20 min",
    },
    # ── Aggressive ─────────────────────────────────────────────────
    # Top-10 000 ports with the full NSE default-script suite + OS detection.
    "aggressive": {
        "phase1": "-sS -Pn -T4 --open --top-ports 10000 --min-rate 1000 --max-retries 2",
        "phase2_flags": "-sS -sV --version-intensity 9 -O -Pn -T4 --open",
        "phase2_scripts": (
            "-sC --script=banner,http-title,http-server-header,ftp-anon,"
            "ssh-hostkey,ssl-cert,smtp-commands,dns-recursion,"
            "smtp-open-relay,http-shellshock"
        ),
        "os_detect": True,
        "p1_timeout": "300s",
        "p2_timeout": "600s",
        "time": "5-15 min",
    },
    # ── Vulnerability ──────────────────────────────────────────────
    # Phase 1 (port discovery) + Phase 2 (scripts on open ports only)
    # Actual args are built dynamically in _run_vulnerability_scan().
    "vulnerability": {
        "args": "",
        "time": "10-20 min",
    },
}

# Estimated nmap execution duration (seconds) per scan type.
# Used by the progress ticker to spread simulated progress across the run.
SCAN_ESTIMATED_SECONDS = {
    "quick":         180,
    "stealth":       480,
    "full":          900,
    "aggressive":    600,
    "vulnerability": 900,
}

# Targeted NSE scripts only — no heavy "vuln" category (offline DB covers CVEs).
# Each script has a known fast execution time on remote hosts.
_VULN_SCRIPTS = (
    "banner,http-headers,http-title,http-server-header,ftp-anon,ssh-hostkey,"
    "ssl-heartbleed,ssl-poodle,smb-vuln-ms17-010,smb-vuln-ms08-067,http-shellshock,"
    "dns-recursion,smtp-open-relay"
)


def _cvss_to_severity(cvss: float) -> str:
    """Map a CVSS v2/v3 score to a severity label."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"


def _progress_ticker(
    scan_id: str,
    start_pct: int,
    end_pct: int,
    estimated_secs: int,
    callback: Callable,
    stop_event: threading.Event,
    messages: Optional[List[str]] = None,
) -> None:
    """
    Background thread that ticks progress from *start_pct* toward *end_pct*,
    firing *callback* every TICK_INTERVAL seconds.

    Phase 1: Fills start_pct → end_pct over DISPLAY_SECS seconds.
    Phase 2: Once capped, keeps heartbeating every TICK_INTERVAL seconds with
             a slowly creeping value (0.2% per tick) up to end_pct-1, so the
             UI never appears frozen during long-running scans.
    """
    TICK_INTERVAL = 3       # fire every 3 seconds — user sees regular updates
    # Spread start_pct→end_pct over 90% of the estimated scan time so the bar
    # fills gradually rather than hitting the cap in 60 s and freezing there.
    DISPLAY_SECS  = max(60, int(estimated_secs * 0.9))

    total_ticks = max(1, DISPLAY_SECS // TICK_INTERVAL)
    step = (end_pct - start_pct) / total_ticks
    HEARTBEAT_STEP = 0.2   # slow creep during phase 2 so bar isn't truly frozen

    current = float(start_pct)
    tick = 0

    default_messages = [
        "Probing open ports…",
        "Sending SYN packets…",
        "Waiting for host responses…",
        "Fingerprinting services…",
        "Analyzing response times…",
        "Scanning port ranges…",
        "Collecting banner data…",
        "Running detection scripts…",
        "Cross-referencing services…",
        "Finalizing port states…",
    ]
    msgs = messages or default_messages

    while not stop_event.is_set():
        stop_event.wait(TICK_INTERVAL)
        if stop_event.is_set():
            break
        if current < end_pct - 1:
            # Phase 1: fast fill
            current = min(current + step, end_pct - 1)
        else:
            # Phase 2: heartbeat — keep the bar visibly alive
            current = min(current + HEARTBEAT_STEP, end_pct - 1)
        pct = int(current)
        msg = msgs[tick % len(msgs)]
        try:
            callback(scan_id, pct, "running", f"🔍 {msg} ({pct}%)")
        except Exception:
            pass
        tick += 1


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
    cve_data: List[Dict[str, Any]] = field(default_factory=list)


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
        event_callback: Optional[Callable] = None,
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

        # ── Vulnerability scan: dedicated two-phase implementation ──
        if scan_type == ScanType.VULNERABILITY and not custom_args:
            return self._run_vulnerability_scan(
                target=target,
                scan_id=scan_id,
                custom_ports=custom_ports,
                callback=callback,
                event_callback=event_callback,
                started_at=started_at,
            )

        # ── Custom scan: single-pass with user-supplied args ──────
        if scan_type == ScanType.CUSTOM:
            args = custom_args if custom_args else "-sV -T4 --open"
            if custom_ports:
                args_parts = [p for p in args.split() if not p.startswith("-p")]
                args = " ".join(args_parts) + f" -p {custom_ports}"
            return self._run_custom_scan(
                target=target,
                scan_id=scan_id,
                args=args,
                callback=callback,
                event_callback=event_callback,
                started_at=started_at,
            )

        # ── Standard scans: two-phase (discovery → version/scripts) ─
        return self._run_standard_scan(
            target=target,
            scan_type=scan_type,
            scan_id=scan_id,
            custom_ports=custom_ports,
            callback=callback,
            event_callback=event_callback,
            started_at=started_at,
        )

    # ─────────────────────────────────────
    # Standard two-phase scan (quick / stealth / full / aggressive)
    # ─────────────────────────────────────
    def _run_standard_scan(
        self,
        target: str,
        scan_type: "ScanType",
        scan_id: str,
        custom_ports: str,
        callback: Optional[Callable],
        event_callback: Optional[Callable],
        started_at: datetime,
    ) -> "ScanSummary":
        """
        Two-phase scan shared by quick / stealth / full / aggressive types.

        Phase 1  — Fast SYN sweep to identify which ports are open.
        Phase 2a — Version + OS + banner detection ONLY on open ports.
        Phase 2b — Retry with TCP-connect + banner script when Phase 2a
                   returns no product/version (common against hardened
                   internet hosts that drop SYN-based version probes).
        """
        profile = SCAN_PROFILES[scan_type.value]
        p1_args  = profile["phase1"]
        p2_flags = profile["phase2_flags"]
        p2_scrip = profile["phase2_scripts"]
        os_flag  = "-O" if profile.get("os_detect") else ""
        p1_to    = profile["p1_timeout"]
        p2_to    = profile["p2_timeout"]
        profile_time = profile["time"]

        # ── Override port range if caller supplied custom_ports ───
        if custom_ports:
            # Strip any --top-ports / -p from the phase1 template
            p1_parts = [
                p for p in p1_args.split()
                if not p.startswith("-p") and p != "--top-ports"
                and not (p1_args.split()[p1_args.split().index(p) - 1]
                         if p1_args.split().index(p) > 0 else "").startswith("--top-ports")
            ]
            # Rebuild without top-ports value token
            clean = []
            skip_next = False
            for tok in p1_args.split():
                if skip_next:
                    skip_next = False
                    continue
                if tok == "--top-ports":
                    skip_next = True
                    continue
                if tok.startswith("-p"):
                    continue
                clean.append(tok)
            p1_args = " ".join(clean) + f" -p {custom_ports}"

        # ════════════════════════════════════════════════════════
        # Phase 1 — Port discovery
        # ════════════════════════════════════════════════════════
        self._update_progress(
            scan_id, 5, "running",
            f"Phase 1/2 — port discovery on {target} ({scan_type.value})…",
            callback,
        )
        logger.info(
            "[NETRIX] %s | [%s] Phase 1 — discovery: nmap %s %s",
            datetime.now(timezone.utc).isoformat(), scan_id, p1_args, target,
        )

        _stop_p1 = threading.Event()
        if callback:
            threading.Thread(
                target=_progress_ticker,
                args=(scan_id, 5, 35, 60, callback, _stop_p1,
                      ["Sending SYN probes…", "Probing port ranges…",
                       "Waiting for host responses…", "Filtering open ports…"]),
                daemon=True,
            ).start()

        nm_disc = nmap.PortScanner()
        try:
            nm_disc.scan(
                hosts=target,
                arguments=f"{p1_args} --host-timeout {p1_to}",
            )
        except nmap.PortScannerError as e:
            _stop_p1.set()
            err = str(e)
            if "root" in err.lower() or "admin" in err.lower():
                raise Exception("Need root privileges for SYN scan.")
            raise Exception(f"Port discovery failed: {e}")
        except Exception as e:
            _stop_p1.set()
            raise Exception(f"Port discovery failed: {e}")
        finally:
            _stop_p1.set()

        # Collect every open port across all discovered hosts
        open_ports: List[int] = []
        p1_hosts = nm_disc.all_hosts()
        for h in p1_hosts:
            for proto in ("tcp", "udp"):
                try:
                    for p, data in nm_disc[h].get(proto, {}).items():
                        if data.get("state") == "open":
                            open_ports.append(int(p))
                except Exception:
                    pass
        open_ports = sorted(set(open_ports))
        port_count = len(open_ports)
        ports_str  = ",".join(str(p) for p in open_ports)

        logger.info(
            "[NETRIX] %s | [%s] Phase 1 complete — %d open port(s): %s",
            datetime.now(timezone.utc).isoformat(), scan_id,
            port_count, ports_str[:200],
        )

        if event_callback:
            event_callback({
                "event": "progress",
                "progress": 35,
                "ports_found": port_count,
                "message": (
                    f"Phase 1 done — {port_count} open port(s) found. "
                    "Starting version/script detection…"
                    if port_count else
                    "Phase 1 done — no open ports found."
                ),
            })

        # ════════════════════════════════════════════════════════
        # Phase 2a — Version + OS + banner on discovered ports
        # ════════════════════════════════════════════════════════
        self._update_progress(
            scan_id, 38, "running",
            f"Phase 2/2 — version & service detection on {port_count} port(s)…",
            callback,
        )

        if open_ports:
            p2a_args = (
                f"{p2_flags} {os_flag} "
                f"-p {ports_str} {p2_scrip} "
                f"--host-timeout {p2_to} --script-timeout 15s"
            ).strip()
        else:
            # No open ports found — fall back to a shallow sweep so we still
            # record the host as "up" with whatever info nmap returns.
            p2a_args = (
                f"{p2_flags} --top-ports 100 "
                f"--host-timeout {p2_to}"
            ).strip()

        logger.info(
            "[NETRIX] %s | [%s] Phase 2a — version: nmap %s %s",
            datetime.now(timezone.utc).isoformat(), scan_id, p2a_args, target,
        )

        _stop_p2a = threading.Event()
        if callback:
            threading.Thread(
                target=_progress_ticker,
                args=(scan_id, 38, 78,
                      max(30, port_count * 8), callback, _stop_p2a,
                      ["Fingerprinting services…", "Grabbing service banners…",
                       "Detecting OS…", "Running NSE scripts…",
                       "Resolving hostnames…", "Analysing service versions…"]),
                daemon=True,
            ).start()

        try:
            self.nm.scan(hosts=target, arguments=p2a_args)
        except nmap.PortScannerError as e:
            _stop_p2a.set()
            raise Exception(f"Version scan failed: {e}")
        except Exception as e:
            _stop_p2a.set()
            raise Exception(f"Version scan failed: {e}")
        finally:
            _stop_p2a.set()

        # If Phase 2a returned 0 hosts (firewall ate the probes), fall back
        # to Phase 1 results so we at least record the host + open ports.
        p2a_hosts = self.nm.all_hosts() if self.nm else []
        if not p2a_hosts and p1_hosts:
            logger.warning(
                "[NETRIX] [%s] Phase 2a returned 0 hosts — "
                "using Phase 1 results for %s", scan_id, target,
            )
            self.nm = nm_disc

        # ════════════════════════════════════════════════════════
        # Phase 2b — TCP-connect banner retry when -sV got nothing
        # (common against internet hosts that filter SYN-based probes)
        # Also runs when Phase 2a returned 0 hosts (firewall blocked all
        # SYN probes) — we still need version data from TCP-connect.
        # ════════════════════════════════════════════════════════
        if ports_str:
            has_version = any(
                (self.nm[h].get(proto, {}).get(str(p), {}).get("product") or
                 self.nm[h].get(proto, {}).get(str(p), {}).get("version"))
                for h in self.nm.all_hosts()
                for proto in ("tcp", "udp")
                for p in (self.nm[h].get(proto) or {})
            )
            if not has_version:
                logger.info(
                    "[NETRIX] [%s] Phase 2a got no version data — "
                    "retrying with TCP-connect + banner script on %s",
                    scan_id, target,
                )
                nm_retry = nmap.PortScanner()
                retry_args = (
                    f"-sT -sV --version-intensity 9 -Pn -T4 --open "
                    f"-p {ports_str} --script=banner,http-title,"
                    f"http-server-header,ssh-hostkey,ftp-anon "
                    f"--host-timeout {p2_to} --script-timeout 10s"
                )
                _stop_p2b = threading.Event()
                if callback:
                    threading.Thread(
                        target=_progress_ticker,
                        args=(scan_id, 79, 81, max(30, port_count * 8),
                              callback, _stop_p2b,
                              ["TCP-connect retry — probing services…",
                               "Grabbing service banners…",
                               "Fingerprinting open ports (TCP)…"]),
                        daemon=True,
                    ).start()
                try:
                    nm_retry.scan(hosts=target, arguments=retry_args)
                    for h in nm_retry.all_hosts():
                        if h not in self.nm.all_hosts():
                            continue
                        for proto in ("tcp", "udp"):
                            for port_n, port_d in (nm_retry[h].get(proto) or {}).items():
                                existing = self.nm[h].get(proto, {}).get(port_n, {})
                                if not existing.get("product") and port_d.get("product"):
                                    existing["product"] = port_d["product"]
                                if not existing.get("version") and port_d.get("version"):
                                    existing["version"] = port_d["version"]
                                # Last resort: raw banner text
                                banner = (port_d.get("script") or {}).get("banner", "")
                                if banner and not existing.get("product"):
                                    parsed = self._parse_banner(banner)
                                    if parsed:
                                        existing["product"] = parsed["product"]
                                        existing["version"] = parsed.get("version", "")
                                # Merge any script output (http-title etc.)
                                for sname, sout in (port_d.get("script") or {}).items():
                                    if existing.get("script") is None:
                                        existing["script"] = {}
                                    if sname not in existing["script"]:
                                        existing["script"][sname] = sout
                except Exception as retry_err:
                    logger.debug(
                        "[NETRIX] [%s] Banner retry failed (non-fatal): %s",
                        scan_id, retry_err,
                    )
                finally:
                    _stop_p2b.set()

        self._update_progress(
            scan_id, 82, "running",
            "Parsing results and calculating risk scores…",
            callback,
        )

        # ════════════════════════════════════════════════════════
        # Parse & build summary
        # ════════════════════════════════════════════════════════
        hosts = self._parse_results(scan_id, event_callback=event_callback)

        self._update_progress(
            scan_id, 92, "running",
            f"Parsed {len(hosts)} host(s) — finalising…",
            callback,
        )

        completed_at = datetime.now(timezone.utc)
        duration = (completed_at - started_at).total_seconds()

        try:
            nmap_command = self.nm.command_line()
        except Exception:
            nmap_command = f"nmap {p2a_args} {target}"

        try:
            nmap_ver = self.nm.nmap_version()
            nmap_ver_str = (
                ".".join(str(v) for v in nmap_ver)
                if isinstance(nmap_ver, tuple) else str(nmap_ver)
            )
        except Exception:
            nmap_ver_str = "unknown"

        hosts_up         = sum(1 for h in hosts if h.status == "up")
        total_open_ports = sum(h.open_ports_count for h in hosts)
        total_vulns      = sum(len(h.vulnerabilities_found) for h in hosts)
        critical_hosts   = sum(1 for h in hosts if h.risk_level == "critical")
        high_risk_hosts  = sum(1 for h in hosts if h.risk_level == "high")

        summary = ScanSummary(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type.value,
            scan_profile=profile_time,
            nmap_command=nmap_command,
            nmap_version=nmap_ver_str,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            duration_seconds=round(duration, 2),
            total_hosts=len(hosts),
            hosts_up=hosts_up,
            hosts_down=len(hosts) - hosts_up,
            hosts=hosts,
            total_open_ports=total_open_ports,
            total_vulnerabilities=total_vulns,
            critical_hosts=critical_hosts,
            high_risk_hosts=high_risk_hosts,
            scan_args_used=p2a_args,
        )

        self._update_progress(
            scan_id, 100, "completed",
            f"Scan complete — {hosts_up} host(s), "
            f"{total_open_ports} open port(s), {total_vulns} vuln(s)",
            callback,
        )

        logger.info(
            "[NETRIX] %s | [%s] %s scan complete — "
            "%d host(s), %d port(s), %d vuln(s) in %.1fs",
            datetime.now(timezone.utc).isoformat(), scan_id,
            scan_type.value, len(hosts), total_open_ports, total_vulns, duration,
        )

        return summary

    # ─────────────────────────────────────
    # Custom scan (single-pass, user-supplied args)
    # ─────────────────────────────────────
    def _run_custom_scan(
        self,
        target: str,
        scan_id: str,
        args: str,
        callback: Optional[Callable],
        event_callback: Optional[Callable],
        started_at: datetime,
    ) -> "ScanSummary":
        """Single-pass scan with caller-supplied nmap arguments."""
        self._update_progress(
            scan_id, 5, "running",
            f"Custom scan on {target}…",
            callback,
        )
        logger.info(
            "[NETRIX] %s | [%s] Custom scan: nmap %s %s",
            datetime.now(timezone.utc).isoformat(), scan_id, args, target,
        )

        _stop = threading.Event()
        if callback:
            threading.Thread(
                target=_progress_ticker,
                args=(scan_id, 5, 80, 300, callback, _stop),
                daemon=True,
            ).start()

        try:
            self.nm.scan(hosts=target, arguments=args + " --host-timeout 600s")
        except nmap.PortScannerError as e:
            _stop.set()
            err = str(e)
            if "root" in err.lower() or "admin" in err.lower():
                raise Exception("Need root privileges for this scan type.")
            raise Exception(f"Custom scan error: {e}")
        except Exception as e:
            _stop.set()
            raise Exception(f"Custom scan failed: {e}")
        finally:
            _stop.set()

        self._update_progress(scan_id, 82, "running", "Parsing results…", callback)
        hosts = self._parse_results(scan_id, event_callback=event_callback)

        completed_at     = datetime.now(timezone.utc)
        duration         = (completed_at - started_at).total_seconds()
        hosts_up         = sum(1 for h in hosts if h.status == "up")
        total_open_ports = sum(h.open_ports_count for h in hosts)
        total_vulns      = sum(len(h.vulnerabilities_found) for h in hosts)

        try:
            nmap_ver = self.nm.nmap_version()
            nmap_ver_str = (
                ".".join(str(v) for v in nmap_ver)
                if isinstance(nmap_ver, tuple) else str(nmap_ver)
            )
        except Exception:
            nmap_ver_str = "unknown"

        summary = ScanSummary(
            scan_id=scan_id,
            target=target,
            scan_type="custom",
            scan_profile="custom",
            nmap_command=f"nmap {args} {target}",
            nmap_version=nmap_ver_str,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            duration_seconds=round(duration, 2),
            total_hosts=len(hosts),
            hosts_up=hosts_up,
            hosts_down=len(hosts) - hosts_up,
            hosts=hosts,
            total_open_ports=total_open_ports,
            total_vulnerabilities=total_vulns,
            critical_hosts=sum(1 for h in hosts if h.risk_level == "critical"),
            high_risk_hosts=sum(1 for h in hosts if h.risk_level == "high"),
            scan_args_used=args,
        )

        self._update_progress(
            scan_id, 100, "completed",
            f"Custom scan complete — {hosts_up} host(s), {total_open_ports} port(s)",
            callback,
        )
        return summary

    # ─────────────────────────────────────
    # Two-phase vulnerability scan
    # ─────────────────────────────────────
    def _run_vulnerability_scan(
        self,
        target: str,
        scan_id: str,
        custom_ports: str,
        callback: Optional[Callable],
        event_callback: Optional[Callable],
        started_at: datetime,
    ) -> "ScanSummary":
        """
        Phase 1 — fast SYN scan to discover open ports.
        Phase 2 — deep vuln scripts only on the discovered ports.

        This is dramatically faster than running scripts against all 65 535
        ports: a typical web server with 3 open ports finishes in ~3 minutes
        instead of 45–60.
        """
        # ── Phase 1: port discovery ──────────────────────────────
        # Phase 1: use --top-ports 1000 by default (covers 90%+ of real services
        # while sending 65x fewer packets than -p-, avoiding IDS rate-limit blocks).
        # If the user specified custom_ports, honour that instead.
        if custom_ports:
            port_range = custom_ports
            port_arg = f"-p {port_range}"
        else:
            port_range = ""
            port_arg = "--top-ports 1000"
        phase1_args = (
            f"-sS -T4 --open {port_arg} --min-rate 1000 -Pn --host-timeout 300s"
        )

        self._update_progress(
            scan_id, 5, "running",
            f"Phase 1/2 — fast port discovery on {target}…",
            callback,
        )

        _stop_p1 = threading.Event()
        if callback:
            p1_msgs = [
                "Sending SYN probes…", "Waiting for host responses…",
                "Filtering open ports…", "Enumerating port states…",
                "Mapping port ranges…",
            ]
            threading.Thread(
                target=_progress_ticker,
                args=(scan_id, 5, 38, 120, callback, _stop_p1, p1_msgs),
                daemon=True,
            ).start()

        nm_disc = nmap.PortScanner()
        try:
            nm_disc.scan(hosts=target, arguments=phase1_args)
        except nmap.PortScannerError as e:
            _stop_p1.set()
            err = str(e)
            if "root" in err.lower() or "admin" in err.lower():
                raise Exception("Need root/admin rights for SYN scan.")
            raise Exception(f"Port discovery failed: {e}")
        except Exception as e:
            _stop_p1.set()
            raise Exception(f"Port discovery failed: {e}")
        finally:
            _stop_p1.set()

        # Collect open ports across all discovered hosts
        open_ports: List[int] = []
        for h in nm_disc.all_hosts():
            for proto in ("tcp", "udp"):
                try:
                    for p, data in nm_disc[h].get(proto, {}).items():
                        if data.get("state") == "open":
                            open_ports.append(int(p))
                except Exception:
                    pass
        open_ports = sorted(set(open_ports))

        port_count = len(open_ports)
        logger.info(
            "[NETRIX] %s | Phase 1 complete — %d open port(s): %s",
            datetime.now(timezone.utc).isoformat(),
            port_count,
            ",".join(str(p) for p in open_ports[:20]),
        )

        if event_callback:
            event_callback({
                "event": "progress",
                "progress": 40,
                "ports_found": port_count,
                "message": (
                    f"Phase 1 done — {port_count} open port(s) found. "
                    "Starting vulnerability analysis on discovered ports…"
                    if port_count else
                    "Phase 1 done — no open ports found."
                ),
            })

        # ── Phase 2a: version detection on open ports ────────────
        # Run -sV separately from vuln scripts so scripts never
        # interfere with service fingerprinting.
        self._update_progress(
            scan_id, 40, "running",
            f"Phase 2a — service/version detection on {port_count} open port(s)…",
            callback,
        )

        if open_ports:
            ports_str = ",".join(str(p) for p in open_ports)
            # Firewall-bypass version detection:
            # --version-intensity 9 : max probe coverage
            # --source-port 53      : spoof DNS source port (often allowed through firewalls)
            # -f                    : fragment packets to evade packet inspection
            # -O                    : OS detection
            phase2a_args = (
                f"-sS -sV --version-intensity 9 -O -Pn -T4 --open "
                f"-p {ports_str} --source-port 53 -f --host-timeout 180s"
            )
        else:
            ports_str = ""
            phase2a_args = (
                "-sS -sV --version-intensity 9 -O -Pn -T4 --open "
                "--top-ports 1000 --source-port 53 -f --host-timeout 180s"
            )

        _stop_p2a = threading.Event()
        if callback:
            threading.Thread(
                target=_progress_ticker,
                args=(scan_id, 40, 58, max(30, port_count * 3), callback, _stop_p2a,
                      ["Fingerprinting services…", "Reading service banners…",
                       "Detecting OS…", "Analyzing service versions…"]),
                daemon=True,
            ).start()

        try:
            self.nm.scan(hosts=target, arguments=phase2a_args)
        except Exception as e:
            _stop_p2a.set()
            raise Exception(f"Version scan failed: {e}")
        finally:
            _stop_p2a.set()

        # ── Fallback: if Phase 2a returned 0 hosts but Phase 1 found hosts,
        #    copy Phase 1 results into self.nm so we still persist host/port data.
        p2a_hosts = self.nm.all_hosts() if self.nm else []
        if not p2a_hosts and nm_disc.all_hosts():
            logger.warning(
                "[NETRIX] Phase 2a returned 0 hosts — falling back to Phase 1 "
                "discovery results for %s", target
            )
            self.nm = nm_disc

        # ── Retry: if no product/version data detected (including when Phase 2a
        #    returned 0 hosts due to firewall filtering), try TCP connect + banner.
        if ports_str:
            has_version = any(
                self.nm[h].get(proto, {}).get(str(p), {}).get("product") or
                self.nm[h].get(proto, {}).get(str(p), {}).get("version")
                for h in self.nm.all_hosts()
                for proto in ("tcp", "udp")
                for p in (self.nm[h].get(proto) or {})
            )
            if not has_version:
                logger.info(
                    "[NETRIX] Phase 2a got no product/version — retrying with "
                    "TCP connect + banner script for %s", target
                )
                nm_retry = nmap.PortScanner()
                retry_args = (
                    f"-sT -sV --version-intensity 9 -Pn -T4 --open "
                    f"-p {ports_str} --source-port 80 --script=banner --host-timeout 180s"
                )
                try:
                    nm_retry.scan(hosts=target, arguments=retry_args)
                    if nm_retry.all_hosts():
                        # Merge retry version/banner data into self.nm
                        for h in nm_retry.all_hosts():
                            if h not in self.nm.all_hosts():
                                continue
                            for proto in ("tcp", "udp"):
                                for port_n, port_d in (nm_retry[h].get(proto) or {}).items():
                                    existing = self.nm[h].get(proto, {}).get(port_n, {})
                                    if not existing.get("product") and port_d.get("product"):
                                        existing["product"] = port_d["product"]
                                    if not existing.get("version") and port_d.get("version"):
                                        existing["version"] = port_d["version"]
                                    # Parse raw banner as last-resort product/version
                                    banner = (port_d.get("script") or {}).get("banner", "")
                                    if banner and not existing.get("product"):
                                        parsed = self._parse_banner(banner)
                                        if parsed:
                                            existing["product"] = parsed["product"]
                                            existing["version"] = parsed.get("version", "")
                except Exception as retry_err:
                    logger.debug("[NETRIX] Banner retry failed: %s", retry_err)

        logger.info(
            "[NETRIX] %s | Phase 2a complete — %d host(s) in self.nm",
            datetime.now(timezone.utc).isoformat(),
            len(self.nm.all_hosts()),
        )

        self._update_progress(
            scan_id, 58, "running",
            f"Phase 2b — running vulnerability scripts on {port_count} open port(s)…",
            callback,
        )

        # ── Phase 2b: vuln scripts on same ports (separate instance) ─
        # Use a fresh PortScanner so self.nm keeps the clean version data.
        # After scripts finish we merge their NSE output back into self.nm.
        nm_scripts = nmap.PortScanner()
        estimated_p2b = max(60, port_count * 10)
        _stop_p2b = threading.Event()
        if callback:
            threading.Thread(
                target=_progress_ticker,
                args=(scan_id, 58, 83, estimated_p2b, callback, _stop_p2b),
                daemon=True,
            ).start()

        script_scan_ok = False
        if open_ports:
            try:
                nm_scripts.scan(
                    hosts=target,
                    arguments=(
                        f"-sS -Pn -T4 --open -p {ports_str} "
                        f"--script={_VULN_SCRIPTS} "
                        f"--script-timeout 10s --host-timeout 120s"
                    ),
                )
                script_scan_ok = True
            except Exception as script_err:
                logger.warning(
                    "[NETRIX] Script scan failed (non-fatal): %s", str(script_err)
                )
            finally:
                _stop_p2b.set()
        else:
            _stop_p2b.set()

        # ── Merge NSE script output into self.nm version results ──
        if script_scan_ok:
            for h in nm_scripts.all_hosts():
                if h not in self.nm.all_hosts():
                    continue
                for proto in ("tcp", "udp"):
                    for port, pdata in nm_scripts[h].get(proto, {}).items():
                        script_out = pdata.get("script", {})
                        if not script_out:
                            continue
                        try:
                            self.nm[h][proto][port]["script"] = script_out
                        except (KeyError, TypeError):
                            pass

        self._update_progress(scan_id, 85, "running", "Parsing results…", callback)

        # ── Parse & build summary ────────────────────────────────
        hosts = self._parse_results(scan_id, event_callback=event_callback)

        self._update_progress(
            scan_id, 90, "running",
            f"Parsed {len(hosts)} host(s) — calculating risk scores",
            callback,
        )

        completed_at = datetime.now(timezone.utc)
        duration = (completed_at - started_at).total_seconds()

        try:
            nmap_cmd = self.nm.command_line()
        except Exception:
            nmap_cmd = f"nmap {phase2a_args} {target}"

        try:
            nmap_ver = self.nm.nmap_version()
            nmap_ver_str = ".".join(str(v) for v in nmap_ver) if isinstance(nmap_ver, tuple) else str(nmap_ver)
        except Exception:
            nmap_ver_str = "unknown"

        hosts_up = sum(1 for h in hosts if h.status == "up")
        total_open_ports = sum(h.open_ports_count for h in hosts)
        total_vulns = sum(len(h.vulnerabilities_found) for h in hosts)
        critical_hosts = sum(1 for h in hosts if h.risk_level == "critical")
        high_risk_hosts = sum(1 for h in hosts if h.risk_level == "high")

        summary = ScanSummary(
            scan_id=scan_id,
            target=target,
            scan_type="vulnerability",
            scan_profile="10-20 min",
            nmap_command=nmap_cmd,
            nmap_version=nmap_ver_str,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            duration_seconds=round(duration, 2),
            total_hosts=len(hosts),
            hosts_up=hosts_up,
            hosts_down=len(hosts) - hosts_up,
            hosts=hosts,
            total_open_ports=total_open_ports,
            total_vulnerabilities=total_vulns,
            critical_hosts=critical_hosts,
            high_risk_hosts=high_risk_hosts,
            scan_args_used=phase2a_args,
        )

        self._update_progress(
            scan_id, 100, "completed",
            f"Scan complete — {hosts_up} host(s), {total_open_ports} port(s), {total_vulns} vuln(s)",
            callback,
        )

        logger.info(
            "[NETRIX] %s | Vuln scan %s complete — %d host(s), %d port(s), %d vuln(s) in %.1fs",
            datetime.now(timezone.utc).isoformat(),
            scan_id, len(hosts), total_open_ports, total_vulns, duration,
        )

        return summary

    # ─────────────────────────────────────
    # Result parsing
    # ─────────────────────────────────────
    def _parse_results(
        self,
        scan_id: str,
        event_callback: Optional[Callable] = None,
    ) -> List[HostScanResult]:
        """
        Iterate over every host in the nmap results and produce
        a list of fully-parsed ``HostScanResult`` objects.

        Fires ``host_found``, ``port_found``, and ``cve_found``
        events via ``event_callback`` as each item is parsed.
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

                # Fire host_found event
                if event_callback:
                    event_callback({
                        "event": "host_found",
                        "ip": host_result.ip,
                        "hostname": host_result.hostname or "",
                        "status": host_result.status,
                        "os_name": host_result.os_info.name or "",
                        "risk_score": host_result.risk_score,
                        "risk_level": host_result.risk_level,
                        "message": f"✅ Host discovered: {host_result.ip}"
                                   + (f" ({host_result.hostname})" if host_result.hostname else ""),
                    })

                    # Fire port_found events for each open port
                    for svc in host_result.services:
                        if svc.state == "open":
                            product_str = f" ({svc.product}" + (f" {svc.version}" if svc.version else "") + ")" if svc.product else ""
                            event_callback({
                                "event": "port_found",
                                "ip": host_result.ip,
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "service": svc.service_name,
                                "product": svc.product,
                                "version": svc.version,
                                "message": f"🔓 Open port: {svc.port}/{svc.protocol} {svc.service_name}{product_str}",
                            })

                    # Fire cve_found events — use real CVE/CVSS from services
                    emitted: set = set()
                    for svc in host_result.services:
                        for cve_entry in svc.cve_data:
                            cve_id = cve_entry["cve_id"]
                            if cve_id in emitted:
                                continue
                            emitted.add(cve_id)
                            cvss = cve_entry.get("cvss", 0.0)
                            severity = cve_entry.get("severity", _cvss_to_severity(cvss))
                            event_callback({
                                "event": "cve_found",
                                "ip": host_result.ip,
                                "port": svc.port,
                                "service": svc.service_name,
                                "cve_id": cve_id,
                                "cvss": cvss,
                                "severity": severity,
                                "url": cve_entry.get("url", ""),
                                "message": (
                                    f"⚠️ {cve_id} [CVSS {cvss}] on "
                                    f"{host_result.ip}:{svc.port}/{svc.service_name}"
                                ),
                            })
                    # Fall back for non-CVE script detections
                    for vuln_name in host_result.vulnerabilities_found:
                        if vuln_name.startswith("CVE-") or vuln_name in emitted:
                            continue
                        severity = self._severity_from_script(vuln_name)
                        event_callback({
                            "event": "cve_found",
                            "ip": host_result.ip,
                            "cve_id": vuln_name,
                            "cvss": 0.0,
                            "severity": severity,
                            "message": f"⚠️ Vulnerability: {vuln_name} [{severity.upper()}] on {host_result.ip}",
                        })

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
            # Prefer iterating the hostnames list directly — hostname() may
            # return "" even when entries exist (e.g. type != 'PTR')
            raw_hostnames = host_data.get("hostnames", [])
            for h in raw_hostnames:
                name = h.get("name", "").strip()
                if name:
                    hostname = name
                    break
        except Exception:
            pass

        if not hostname:
            try:
                hostname = host_data.hostname() or ""
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
        seen_cves: set = set()
        for svc in services:
            # Prefer real CVE IDs from cve_data
            for cve_entry in svc.cve_data:
                cve_id = cve_entry["cve_id"]
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    vulns_found.append(cve_id)
            # Fall back to script-name detection for scripts without CVE IDs
            if not svc.cve_data:
                for script_name, script_output in svc.nse_scripts.items():
                    if self._is_vulnerable_output(script_output):
                        label = f"{script_name}:{svc.port}"
                        if label not in vulns_found:
                            vulns_found.append(label)

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

                    # Fallback: if -sV returned no product/version, try the
                    # raw banner captured by the NSE banner script (present
                    # whenever -sC or --script=banner was used).
                    if not product:
                        banner = nse_scripts.get("banner", "")
                        if banner:
                            parsed = self._parse_banner(banner)
                            if parsed:
                                product = parsed.get("product", "")
                                version = parsed.get("version", version)

                    # Flags
                    is_critical = int(port_number) in CRITICAL_PORTS
                    is_vuln = any(
                        self._is_vulnerable_output(output)
                        for output in nse_scripts.values()
                    )

                    # Real CVE/CVSS extraction
                    cve_data = self._extract_cve_cvss_from_scripts(nse_scripts)
                    if cve_data:
                        is_vuln = True

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
                        cve_data=cve_data,
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
    # Banner parser — extract product/version from raw service banners
    # when nmap -sV cannot fingerprint the service normally.
    # ─────────────────────────────────────
    @staticmethod
    def _parse_banner(banner: str) -> dict:
        """
        Parse a raw service banner string into product/version.
        Handles common protocols: SSH, FTP, SMTP, HTTP, POP3, IMAP.
        Returns dict with 'product' and optionally 'version', or {} if unknown.
        """
        import re as _re
        banner = banner.strip()

        patterns = [
            # SSH: SSH-2.0-OpenSSH_8.9p1
            (_re.compile(r'SSH-[\d.]+-(\S+?)(?:_| )([\d.]+\S*)', _re.I),
             lambda m: {"product": m.group(1), "version": m.group(2)}),
            # SSH no version: SSH-2.0-OpenSSH_8.9
            (_re.compile(r'SSH-[\d.]+-(\S+)', _re.I),
             lambda m: {"product": m.group(1)}),
            # FTP: 220 (vsFTPd 3.0.3) or 220 ProFTPD 1.3.5
            (_re.compile(r'220[\s-]+(?:\()?(\w+(?:FTPd?|\w+))\s+([\d.]+)', _re.I),
             lambda m: {"product": m.group(1), "version": m.group(2)}),
            # SMTP/POP3/IMAP: product name + version in banner
            (_re.compile(r'(?:Postfix|Exim|Sendmail|Dovecot|Courier)\s*([\d.]*)', _re.I),
             lambda m: {"product": m.group(0).split()[0], "version": m.group(1)}),
            # HTTP Server header: Apache/2.4.51 or nginx/1.18.0
            (_re.compile(r'(Apache|nginx|lighttpd|IIS|Caddy|Cherokee)/([\d.]+)', _re.I),
             lambda m: {"product": m.group(1), "version": m.group(2)}),
            # Generic: ProductName/Version
            (_re.compile(r'([A-Za-z][\w-]+)/([\d.]+)', _re.I),
             lambda m: {"product": m.group(1), "version": m.group(2)}),
        ]

        for pattern, extractor in patterns:
            m = pattern.search(banner)
            if m:
                try:
                    return extractor(m)
                except Exception:
                    continue
        return {}

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
    def _extract_cve_cvss_from_scripts(scripts: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Parse real CVE IDs and CVSS scores from NSE script output.

        Handles two formats:
        - vulners:     ``CVE-XXXX-XXXX  7.5  https://vulners.com/...``
        - vuln scripts: ``IDs: CVE:CVE-XXXX-XXXX`` + ``CVSS Score: 9.3``
        """
        import re as _re
        results: List[Dict[str, Any]] = []
        seen: set = set()

        for script_name, output in scripts.items():
            if not output:
                continue

            if script_name == "vulners":
                # vulners format: CVE-XXXX-XXXXX  7.5  https://...
                for m in _re.finditer(
                    r'(CVE-\d{4}-\d+)\s+([\d.]+)\s+https?://\S+',
                    output,
                ):
                    cve_id = m.group(1)
                    if cve_id in seen:
                        continue
                    seen.add(cve_id)
                    try:
                        cvss = float(m.group(2))
                    except ValueError:
                        cvss = 0.0
                    results.append({
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "severity": _cvss_to_severity(cvss),
                        "source": "vulners",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })
            else:
                # vuln-script format: IDs: CVE:CVE-XXXX-XXXX  + CVSS Score: 9.3
                cve_ids = _re.findall(r'CVE[:\s]+(CVE-\d{4}-\d+)', output)
                cvss_m = _re.search(r'CVSS\s+(?:Score)?[:\s]+([\d.]+)', output, _re.IGNORECASE)
                cvss = float(cvss_m.group(1)) if cvss_m else 0.0

                # Also look for bare CVE references
                if not cve_ids:
                    cve_ids = _re.findall(r'\b(CVE-\d{4}-\d+)\b', output)

                for cve_id in cve_ids:
                    if cve_id in seen:
                        continue
                    seen.add(cve_id)
                    results.append({
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "severity": _cvss_to_severity(cvss),
                        "source": script_name,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })

        # Sort by CVSS descending
        results.sort(key=lambda x: x["cvss"], reverse=True)
        return results

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
            "EXPLOITABLE",
            "CVE-",
            "SEVERITY: HIGH",
            "SEVERITY: CRITICAL",
            "SEVERITY: MEDIUM",
            "DISCLOSURE DATE:",
            "REFERENCES:",
            "IDS:",
            "DANGEROUS",
            "BACKDOOR",
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
        from app.scanner.vuln_engine import CVEEngine as _CVEEngine

        # Pre-load CVE engine once for the whole save operation
        try:
            _cve_engine = _CVEEngine()
        except Exception:
            _cve_engine = None

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
            scan.nmap_version = summary.nmap_version
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

                    # ── Step 4a: NSE-detected vulnerabilities ────────────
                    nse_cve_ids_saved: set = set()
                    for script_name, script_output in svc.nse_scripts.items():
                        if self._is_vulnerable_output(script_output):
                            cve_id, cvss_score = self._extract_cve_from_output(
                                script_output
                            )
                            # Enrich CVSS from offline DB when not in NSE output
                            if cve_id and cvss_score is None and _cve_engine:
                                if cve_id in _cve_engine._offline_db:
                                    _offline_score = _cve_engine._offline_db[cve_id].get("cvss_score")
                                    if _offline_score is not None:
                                        cvss_score = float(_offline_score)
                            severity = self._severity_from_script(script_name)
                            # Override severity from CVSS score when available
                            if cvss_score is not None:
                                if cvss_score >= 9.0:
                                    severity = "critical"
                                elif cvss_score >= 7.0:
                                    severity = "high"
                                elif cvss_score >= 4.0:
                                    severity = "medium"
                                else:
                                    severity = "low"
                            if not cve_id:
                                cve_id = None
                            else:
                                nse_cve_ids_saved.add(cve_id)
                            vuln = Vulnerability(
                                port_id=port.id,
                                scan_id=scan.id,
                                host_id=host.id,
                                cve_id=cve_id,
                                cvss_score=cvss_score,
                                title=f"NSE: {script_name}",
                                description=script_output[:2000],
                                severity=severity,
                                source="nse_script",
                                nse_script_name=script_name,
                                nse_output=script_output,
                                is_confirmed=True,
                            )
                            db_session.add(vuln)

                            logger.info(
                                "[NETRIX] %s | NSE Vulnerability: %s on %s:%d",
                                datetime.now(timezone.utc).isoformat(),
                                script_name, host_data.ip, svc.port,
                            )

                    # ── Step 4b: Service-version CVE matching (offline DB) ──
                    # Run for every open port that has a known product/service.
                    # This catches CVEs even when NSE scripts don't explicitly
                    # fire — e.g. OpenSSH 7.4, Apache 2.4.49, vsftpd 2.3.4.
                    if svc.state == "open" and _cve_engine and (svc.product or svc.service_name):
                        try:
                            svc_cve_matches = self._match_service_cves_offline(
                                product=svc.product or svc.service_name,
                                version=svc.version or "",
                                cpe=svc.cpe or "",
                                offline_db=_cve_engine._offline_db,
                            )
                            for matched_cve_id, cve_data in svc_cve_matches[:5]:
                                if matched_cve_id in nse_cve_ids_saved:
                                    continue  # Already saved by NSE step
                                # Skip if this CVE is already recorded for this scan
                                already = db_session.query(Vulnerability).filter(
                                    Vulnerability.scan_id == scan.id,
                                    Vulnerability.cve_id == matched_cve_id,
                                ).first()
                                if already:
                                    continue
                                score = float(cve_data.get("cvss_score") or 0.0)
                                sev = cve_data.get("severity") or self._severity_from_cvss(score)
                                vuln = Vulnerability(
                                    port_id=port.id,
                                    scan_id=scan.id,
                                    host_id=host.id,
                                    cve_id=matched_cve_id,
                                    cvss_score=score or None,
                                    title=cve_data.get("title") or matched_cve_id,
                                    description=(cve_data.get("description") or "")[:2000],
                                    severity=sev,
                                    source="offline_db",
                                    remediation=(cve_data.get("remediation") or "")[:1000] or None,
                                    is_confirmed=False,
                                )
                                db_session.add(vuln)
                                nse_cve_ids_saved.add(matched_cve_id)
                                logger.info(
                                    "[NETRIX] %s | Service CVE match: %s on %s:%d (%s %s)",
                                    datetime.now(timezone.utc).isoformat(),
                                    matched_cve_id, host_data.ip, svc.port,
                                    svc.product, svc.version,
                                )
                        except Exception as _svc_match_err:
                            logger.debug("[NETRIX] Service CVE match error: %s", _svc_match_err)

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
    def _extract_cve_from_output(output: str):
        """
        Extract the highest-scored CVE ID and CVSS score from NSE script output.

        Handles multiple formats:
          - ``CVE-2011-2523 10.0``          (vulners script)
          - ``IDs: CVE:CVE-2011-2523``      (vuln-category script)
          - ``CVE-2011-2523``               (bare CVE reference)

        Returns the CVE with the highest CVSS score found in the output.
        Returns:
            tuple[str|None, float|None]: (cve_id, cvss_score)
        """
        import re as _re
        if not output:
            return None, None

        best_cve: Optional[str] = None
        best_score: Optional[float] = None

        # Format 1: "CVE-XXXX-XXXXXX <score>" (vulners script — multiple per output)
        for m in _re.finditer(r'(CVE-\d{4}-\d{4,7})\s+(\d+(?:\.\d+)?)', output):
            cid = m.group(1)
            try:
                s = float(m.group(2))
                if 0.0 <= s <= 10.0:
                    if best_score is None or s > best_score:
                        best_score = s
                        best_cve = cid
            except ValueError:
                pass

        if best_cve:
            return best_cve, best_score

        # Format 2: "CVE:CVE-XXXX-XXXXXX" (vuln-category scripts)
        prefixed = _re.search(r'CVE:(CVE-\d{4}-\d{4,7})', output, _re.IGNORECASE)
        if prefixed:
            return prefixed.group(1), None

        # Format 3: bare "CVE-XXXX-XXXXXX" reference
        bare = _re.search(r'(CVE-\d{4}-\d{4,7})', output, _re.IGNORECASE)
        if bare:
            return bare.group(1), None

        return None, None

    @staticmethod
    def _severity_from_cvss(score: float) -> str:
        """Convert a CVSS score to a severity label."""
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "info"

    @staticmethod
    def _match_service_cves_offline(
        product: str,
        version: str,
        cpe: str,
        offline_db: dict,
    ) -> list:
        """
        Match a service (product + version) to CVEs using only the offline DB.
        Returns a list of (cve_id, cve_data) tuples, sorted by CVSS score desc.

        Matching strategy (broadest to narrowest):
        1. Well-known vulnerable service table (exact & prefix match)
        2. Offline DB 'affected' list (partial name match)
        3. Offline DB description text match
        """
        import re as _re
        from app.scanner.vuln_engine import WELL_KNOWN_VULNERABLE_SERVICES

        results: list = []
        seen: set = set()

        name_lower = product.lower().strip()
        version_lower = version.lower().strip()
        # First meaningful word of the product name, e.g. "apache" from "apache httpd"
        name_first = name_lower.split()[0] if name_lower else ""
        lookup_full = f"{name_lower} {version_lower}".strip()
        lookup_short = f"{name_first} {version_lower}".strip() if name_first != name_lower else ""

        # ── 1. Well-known vulnerable services ──────────────────────
        for key, cve_ids in WELL_KNOWN_VULNERABLE_SERVICES.items():
            if key in (lookup_full, lookup_short, name_lower, name_first) or \
               name_lower.startswith(key) or name_first == key.split()[0]:
                for cid in cve_ids:
                    if cid not in seen and cid in offline_db:
                        results.append((cid, offline_db[cid]))
                        seen.add(cid)

        # ── 2. Offline DB 'affected' list match ────────────────────
        for cve_id, cve_data in offline_db.items():
            if cve_id in seen:
                continue
            for af in cve_data.get("affected", []):
                af_lower = af.lower()
                # Match if product name word (e.g. "apache") appears in affected string
                if name_first and name_first in af_lower:
                    # Version match: if version given, require it to appear in affected
                    if not version_lower or version_lower in af_lower or version_lower[:3] in af_lower:
                        results.append((cve_id, cve_data))
                        seen.add(cve_id)
                        break
                elif name_lower and name_lower in af_lower:
                    results.append((cve_id, cve_data))
                    seen.add(cve_id)
                    break

        # ── 3. Description text match (fallback, only if version known) ──
        if version_lower and name_first:
            for cve_id, cve_data in offline_db.items():
                if cve_id in seen:
                    continue
                desc = cve_data.get("description", "").lower()
                if name_first in desc and version_lower[:3] in desc:
                    results.append((cve_id, cve_data))
                    seen.add(cve_id)

        # Sort by CVSS score descending
        results.sort(key=lambda x: float(x[1].get("cvss_score") or 0), reverse=True)
        return results

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
