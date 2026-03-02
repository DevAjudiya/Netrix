# ─────────────────────────────────────────
# Netrix — script_engine.py
# Purpose: NSE (Nmap Scripting Engine) script manager — selects
#          appropriate scripts per scan type, parses output, and
#          extracts CVE identifiers and vulnerability indicators.
# ─────────────────────────────────────────

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger("netrix")


class NSEScriptEngine:
    """
    Manages NSE script selection, output parsing, and vulnerability
    detection for the Netrix scanning pipeline.
    """

    # ─────────────────────────────────────
    # Script categories
    # ─────────────────────────────────────
    SCRIPT_CATEGORIES: Dict[str, List[str]] = {
        "service_info": [
            "banner",
            "http-headers",
            "http-title",
            "http-server-header",
            "http-methods",
            "ftp-anon",
            "ssh-hostkey",
            "ssh-auth-methods",
            "smtp-commands",
            "dns-recursion",
            "snmp-info",
        ],
        "vulnerabilities": [
            "smb-vuln-ms17-010",
            "smb-vuln-ms08-067",
            "http-shellshock",
            "http-sql-injection",
            "http-csrf",
            "http-dombased-xss",
            "ssl-heartbleed",
            "ssl-poodle",
            "rdp-vuln-ms12-020",
            "ftp-vsftpd-backdoor",
            "http-vuln-cve2014-3704",
            "http-vuln-cve2017-5638",
        ],
        "auth_check": [
            "http-auth-finder",
            "http-default-accounts",
            "ftp-anon",
            "ssh-brute",
            "telnet-brute",
        ],
    }

    # Maps service names to additional script recommendations
    SERVICE_SCRIPTS: Dict[str, List[str]] = {
        "http": [
            "http-headers", "http-title", "http-methods",
            "http-server-header", "http-csrf", "http-dombased-xss",
            "http-shellshock", "http-sql-injection",
        ],
        "https": [
            "ssl-heartbleed", "ssl-poodle", "ssl-cert",
            "ssl-enum-ciphers",
        ],
        "ssh": ["ssh-hostkey", "ssh-auth-methods"],
        "ftp": ["ftp-anon", "ftp-vsftpd-backdoor"],
        "smb": ["smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-os-discovery"],
        "smtp": ["smtp-commands", "smtp-open-relay"],
        "dns": ["dns-recursion", "dns-zone-transfer"],
        "rdp": ["rdp-vuln-ms12-020", "rdp-enum-encryption"],
        "snmp": ["snmp-info", "snmp-brute"],
        "telnet": ["telnet-brute"],
        "mysql": ["mysql-info", "mysql-empty-password"],
        "mongodb": ["mongodb-info"],
    }

    # CVE extraction pattern
    _CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    # Keywords that indicate a positive vulnerability finding
    _VULN_KEYWORDS = [
        "VULNERABLE",
        "State: VULNERABLE",
        "Risk factor:",
        "Exploit available",
    ]

    def __init__(self) -> None:
        """Initialise the NSE script engine."""
        logger.info("[NETRIX] NSE Script Engine initialised")

    # ─────────────────────────────────────
    # Script selection
    # ─────────────────────────────────────
    def get_scripts_for_scan(
        self,
        scan_type: str,
        target_services: Optional[List[str]] = None,
    ) -> str:
        """
        Build a comma-separated NSE script list appropriate for
        the given scan type.

        Args:
            scan_type:       One of ``quick``, ``full``, ``vulnerability``,
                             ``stealth``, ``aggressive``, or ``custom``.
            target_services: Optional list of detected service names
                             (e.g. ``["http", "ssh", "smb"]``) used to
                             add service-specific scripts.

        Returns:
            str: Comma-separated script names ready for ``--script=``.
        """
        scripts: List[str] = []

        scan_lower = scan_type.lower()

        if scan_lower in ("quick", "stealth"):
            scripts.extend(self.SCRIPT_CATEGORIES["service_info"])

        elif scan_lower in ("full", "aggressive"):
            scripts.extend(self.SCRIPT_CATEGORIES["service_info"])
            scripts.extend(self.SCRIPT_CATEGORIES["vulnerabilities"])

        elif scan_lower == "vulnerability":
            for category_scripts in self.SCRIPT_CATEGORIES.values():
                scripts.extend(category_scripts)

        else:
            # Custom / unknown — default to service info
            scripts.extend(self.SCRIPT_CATEGORIES["service_info"])

        # ── Append service-specific scripts ──────────────────────
        if target_services:
            for service in target_services:
                service_lower = service.lower()
                extra = self.SERVICE_SCRIPTS.get(service_lower, [])
                scripts.extend(extra)

        # De-duplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for s in scripts:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        result = ",".join(unique)
        logger.info(
            "[NETRIX] Selected %d NSE scripts for %s scan",
            len(unique), scan_type,
        )
        return result

    # ─────────────────────────────────────
    # Output parsing
    # ─────────────────────────────────────
    def parse_script_output(
        self,
        script_name: str,
        raw_output: str,
    ) -> Dict:
        """
        Parse raw NSE script output into a structured dictionary.

        Returns:
            dict: Keys — ``script_name``, ``is_vulnerable`` (bool),
                  ``severity`` (str), ``details`` (str), ``cve_ids``
                  (list of str).
        """
        is_vuln = self.is_script_vulnerable(raw_output)
        cve_ids = self.extract_cves_from_output(raw_output)
        severity = self._determine_severity(script_name, raw_output, cve_ids)
        cleaned = self._clean_output(raw_output)

        return {
            "script_name": script_name,
            "is_vulnerable": is_vuln,
            "severity": severity,
            "details": cleaned,
            "cve_ids": cve_ids,
        }

    # ─────────────────────────────────────
    # CVE extraction
    # ─────────────────────────────────────
    def extract_cves_from_output(self, output: str) -> List[str]:
        """
        Extract unique CVE identifiers from NSE script output.

        Args:
            output: Raw script output string.

        Returns:
            List[str]: Sorted unique CVE IDs (e.g. ``["CVE-2017-0144"]``).
        """
        if not output:
            return []

        matches = self._CVE_PATTERN.findall(output)
        unique = sorted(set(m.upper() for m in matches))
        return unique

    # ─────────────────────────────────────
    # Vulnerability detection
    # ─────────────────────────────────────
    def is_script_vulnerable(self, script_output: str) -> bool:
        """
        Determine whether an NSE script's output indicates a
        confirmed vulnerability.

        Args:
            script_output: Raw script output string.

        Returns:
            bool: ``True`` if vulnerability keywords are found.
        """
        if not script_output:
            return False

        upper = script_output.upper()
        return any(kw.upper() in upper for kw in self._VULN_KEYWORDS)

    # ─────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────
    def _determine_severity(
        self,
        script_name: str,
        output: str,
        cve_ids: List[str],
    ) -> str:
        """
        Infer a severity level from the script name, output content,
        and any embedded CVE identifiers.

        Returns:
            str: One of ``"critical"``, ``"high"``, ``"medium"``,
                 ``"low"``, ``"info"``.
        """
        name_lower = script_name.lower()

        # ── Critical scripts ─────────────────────────────────────
        critical_scripts = {
            "smb-vuln-ms17-010", "smb-vuln-ms08-067",
            "ftp-vsftpd-backdoor", "http-shellshock",
        }
        if name_lower in critical_scripts:
            return "critical"

        # ── High scripts ─────────────────────────────────────────
        high_scripts = {
            "ssl-heartbleed", "ssl-poodle",
            "rdp-vuln-ms12-020", "http-sql-injection",
            "http-vuln-cve2014-3704", "http-vuln-cve2017-5638",
        }
        if name_lower in high_scripts:
            return "high"

        # ── Medium scripts ───────────────────────────────────────
        medium_scripts = {
            "http-csrf", "http-dombased-xss",
            "http-methods", "dns-recursion",
        }
        if name_lower in medium_scripts:
            return "medium"

        # ── Heuristic fallbacks ──────────────────────────────────
        if cve_ids:
            return "high"

        if self.is_script_vulnerable(output):
            return "medium"

        # Default — informational
        return "info"

    @staticmethod
    def _clean_output(raw_output: str) -> str:
        """
        Remove excessive whitespace from NSE output while preserving
        readability.
        """
        if not raw_output:
            return ""
        # Collapse runs of whitespace into single spaces
        cleaned = " ".join(raw_output.split())
        # Cap length at 5 000 characters
        if len(cleaned) > 5000:
            cleaned = cleaned[:5000] + " … [truncated]"
        return cleaned

    # ─────────────────────────────────────
    # Batch parsing
    # ─────────────────────────────────────
    def parse_all_scripts(
        self,
        nse_output: Dict[str, str],
    ) -> List[Dict]:
        """
        Parse multiple NSE script outputs in one call.

        Args:
            nse_output: Mapping of ``{script_name: raw_output}``.

        Returns:
            List[dict]: One parsed result dict per script.
        """
        results: List[Dict] = []

        for script_name, raw_output in nse_output.items():
            try:
                parsed = self.parse_script_output(script_name, raw_output)
                results.append(parsed)
            except Exception as parse_err:
                logger.warning(
                    "[NETRIX] Failed to parse script %s: %s",
                    script_name, str(parse_err),
                )
                results.append({
                    "script_name": script_name,
                    "is_vulnerable": False,
                    "severity": "info",
                    "details": raw_output or "",
                    "cve_ids": [],
                })

        return results

    def get_vulnerable_scripts(
        self,
        nse_output: Dict[str, str],
    ) -> List[Dict]:
        """
        Convenience method — returns only the scripts whose output
        indicates a vulnerability.
        """
        all_parsed = self.parse_all_scripts(nse_output)
        return [p for p in all_parsed if p["is_vulnerable"]]
