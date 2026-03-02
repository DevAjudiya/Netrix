# ─────────────────────────────────────────
# Netrix — CVE Engine
# Purpose: CVE fetching, matching, analysis
# ─────────────────────────────────────────

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from app.config import get_settings
from app.models.vulnerability import Vulnerability

logger = logging.getLogger("netrix")

# ─────────────────────────────────────────
# Constants
# ─────────────────────────────────────────
SEVERITY_LEVELS: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
    "info": 0.0,
}

WELL_KNOWN_VULNERABLE_SERVICES: Dict[str, List[str]] = {
    "apache 2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
    "apache 2.4.50": ["CVE-2021-42013"],
    "openssh 7.2": ["CVE-2016-6210"],
    "openssh 7.4": ["CVE-2018-15473"],
    "vsftpd 2.3.4": ["CVE-2011-2523"],
    "proftpd 1.3.3": ["CVE-2010-4221"],
    "samba 3.5": ["CVE-2017-7494"],
    "php 5.6": ["CVE-2019-11043"],
    "php 7.0": ["CVE-2019-11043"],
    "mysql 5.5": ["CVE-2016-6662"],
    "mysql 5.6": ["CVE-2016-6662"],
    "tomcat 7.0": ["CVE-2017-12617"],
    "tomcat 8.0": ["CVE-2017-12617"],
    "iis 7.5": ["CVE-2017-7269"],
    "rdp": ["CVE-2019-0708"],
    "smb": ["CVE-2017-0144"],
    "telnet": ["CVE-2020-10188"],
}


# ─────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────
@dataclass
class CVEDetail:
    """Full detail record for a single CVE."""

    cve_id: str
    title: str
    description: str
    cvss_score: float
    cvss_vector: str
    severity: str
    published_date: str
    remediation: str
    references: List[str] = field(default_factory=list)
    source: str = "offline_db"
    affected_products: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityMatch:
    """Aggregated vulnerability findings for one service/port."""

    service_name: str
    service_version: str
    port: int
    protocol: str
    cve_details: List[CVEDetail] = field(default_factory=list)
    nse_findings: List[str] = field(default_factory=list)
    total_vulnerabilities: int = 0
    highest_severity: str = "info"
    highest_cvss: float = 0.0


# ─────────────────────────────────────────
# CVEEngine
# ─────────────────────────────────────────
class CVEEngine:
    """Engine for CVE fetching, matching and risk analysis."""

    def __init__(self) -> None:
        """Initialize the CVE Engine with config, HTTP session, and offline DB."""
        self.settings = get_settings()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Netrix/1.0"})
        if self.settings.NVD_API_KEY:
            self.session.headers["apiKey"] = self.settings.NVD_API_KEY
        self._offline_db: Dict[str, Dict] = {}
        self._last_nvd_call: float = 0.0
        self.load_offline_database()
        logger.info("[NETRIX] CVE Engine initialized")

    # ─────────────────────────────────────
    # Severity helper
    # ─────────────────────────────────────
    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "info"

    # ─────────────────────────────────────
    # NVD rate-limit helper
    # ─────────────────────────────────────
    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_nvd_call
        if elapsed < 0.6:
            time.sleep(0.6 - elapsed)
        self._last_nvd_call = time.time()

    # ─────────────────────────────────────
    # NVD: fetch single CVE
    # ─────────────────────────────────────
    def fetch_cve_from_nvd(self, cve_id: str) -> Optional[CVEDetail]:
        """Fetch a single CVE from the NVD API v2.0."""
        try:
            self._rate_limit()
            resp = self.session.get(
                self.settings.NVD_API_URL,
                params={"cveId": cve_id},
                timeout=30,
            )
            if resp.status_code == 429:
                logger.warning("[NETRIX] NVD rate-limited, waiting 6s")
                time.sleep(6)
                resp = self.session.get(
                    self.settings.NVD_API_URL,
                    params={"cveId": cve_id},
                    timeout=30,
                )
            if resp.status_code != 200:
                logger.warning("[NETRIX] NVD returned HTTP %d for %s", resp.status_code, cve_id)
                return None
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            return self._parse_nvd_item(vulns[0], source="nvd_api")
        except requests.RequestException as exc:
            logger.warning("[NETRIX] NVD request failed for %s: %s", cve_id, exc)
            return None
        except Exception as exc:
            logger.error("[NETRIX] Unexpected NVD error for %s: %s", cve_id, exc)
            return None

    # ─────────────────────────────────────
    # NVD: keyword search
    # ─────────────────────────────────────
    def search_cves_by_keyword(self, keyword: str, max_results: int = 10) -> List[CVEDetail]:
        """Search CVEs by product/service keyword via NVD API."""
        try:
            self._rate_limit()
            resp = self.session.get(
                self.settings.NVD_API_URL,
                params={"keywordSearch": keyword, "resultsPerPage": max_results},
                timeout=30,
            )
            if resp.status_code == 429:
                logger.warning("[NETRIX] NVD rate-limited on keyword search")
                time.sleep(6)
                resp = self.session.get(
                    self.settings.NVD_API_URL,
                    params={"keywordSearch": keyword, "resultsPerPage": max_results},
                    timeout=30,
                )
            if resp.status_code != 200:
                logger.warning("[NETRIX] NVD keyword search returned HTTP %d", resp.status_code)
                return []
            data = resp.json()
            results: List[CVEDetail] = []
            for item in data.get("vulnerabilities", []):
                detail = self._parse_nvd_item(item, source="nvd_api")
                if detail:
                    results.append(detail)
            return results
        except Exception as exc:
            logger.warning("[NETRIX] NVD keyword search failed: %s", exc)
            return []

    # ─────────────────────────────────────
    # NVD: CPE search
    # ─────────────────────────────────────
    def search_cves_by_cpe(self, cpe_string: str) -> List[CVEDetail]:
        """Search CVEs using a CPE string from Nmap."""
        try:
            self._rate_limit()
            resp = self.session.get(
                self.settings.NVD_API_URL,
                params={"cpeName": cpe_string, "resultsPerPage": 10},
                timeout=30,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            results: List[CVEDetail] = []
            for item in data.get("vulnerabilities", []):
                detail = self._parse_nvd_item(item, source="nvd_api")
                if detail:
                    results.append(detail)
            return results
        except Exception as exc:
            logger.warning("[NETRIX] NVD CPE search failed: %s", exc)
            return []

    # ─────────────────────────────────────
    # NVD response parser
    # ─────────────────────────────────────
    def _parse_nvd_item(self, item: Dict, source: str = "nvd_api") -> Optional[CVEDetail]:
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            descriptions = cve_data.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            cvss_vector = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mlist = metrics.get(key, [])
                if mlist:
                    cd = mlist[0].get("cvssData", {})
                    cvss_score = cd.get("baseScore", 0.0)
                    cvss_vector = cd.get("vectorString", "")
                    break
            published = cve_data.get("published", "")
            refs = [r.get("url", "") for r in cve_data.get("references", [])]
            affected: List[str] = []
            for cfg in cve_data.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        affected.append(match.get("criteria", ""))
            return CVEDetail(
                cve_id=cve_id,
                title=f"{cve_id} — {desc[:80]}..." if len(desc) > 80 else f"{cve_id} — {desc}",
                description=desc,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=self._score_to_severity(cvss_score),
                published_date=published,
                remediation=self.get_remediation(cve_id, ""),
                references=refs,
                source=source,
                affected_products=affected,
            )
        except Exception as exc:
            logger.debug("[NETRIX] Failed to parse NVD item: %s", exc)
            return None

    # ─────────────────────────────────────
    # Offline database
    # ─────────────────────────────────────
    def load_offline_database(self) -> Dict:
        """Load offline CVE JSON database, creating it if absent."""
        db_path = self.settings.OFFLINE_CVE_DB_PATH
        if os.path.exists(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as fh:
                    self._offline_db = json.load(fh)
                logger.info("[NETRIX] Loaded offline CVE database: %d entries", len(self._offline_db))
                return self._offline_db
            except (json.JSONDecodeError, IOError) as exc:
                logger.error("[NETRIX] Failed to load offline CVE DB: %s", exc)

        self._offline_db = self._create_default_offline_db()
        try:
            os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
            with open(db_path, "w", encoding="utf-8") as fh:
                json.dump(self._offline_db, fh, indent=2)
            logger.info("[NETRIX] Created default offline CVE database at %s", db_path)
        except IOError as exc:
            logger.error("[NETRIX] Failed to save offline CVE DB: %s", exc)
        return self._offline_db

    @staticmethod
    def _create_default_offline_db() -> Dict[str, Dict]:
        return {
            "CVE-2021-44228": {
                "title": "Log4Shell — Apache Log4j Remote Code Execution",
                "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing remote code execution.",
                "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "critical", "published_date": "2021-12-10",
                "affected": ["log4j 2.0-beta9 through 2.14.1"],
                "remediation": "Update to Apache Log4j 2.17.1 or later. Remove JndiLookup class from classpath.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            },
            "CVE-2021-34527": {
                "title": "PrintNightmare — Windows Print Spooler RCE",
                "description": "Windows Print Spooler service improperly performs privileged file operations, allowing remote code execution with SYSTEM privileges.",
                "cvss_score": 8.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "severity": "high", "published_date": "2021-07-02",
                "affected": ["windows print spooler"],
                "remediation": "Apply Microsoft security update KB5004945. Disable Print Spooler service if not needed.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"],
            },
            "CVE-2017-0144": {
                "title": "EternalBlue — SMB Remote Code Execution",
                "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets (EternalBlue).",
                "cvss_score": 9.3, "cvss_vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                "severity": "critical", "published_date": "2017-03-17",
                "affected": ["smb", "windows smb"],
                "remediation": "Apply Microsoft MS17-010 patch. Disable SMBv1 protocol.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
            },
            "CVE-2019-0708": {
                "title": "BlueKeep — RDP Remote Code Execution",
                "description": "A remote code execution vulnerability exists in Remote Desktop Services when an unauthenticated attacker sends specially crafted requests (BlueKeep).",
                "cvss_score": 9.8, "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical", "published_date": "2019-05-14",
                "affected": ["rdp", "remote desktop"],
                "remediation": "Apply Microsoft security update. Enable Network Level Authentication. Disable RDP if not needed.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
            },
            "CVE-2014-0160": {
                "title": "Heartbleed — OpenSSL Information Disclosure",
                "description": "The TLS heartbeat extension in OpenSSL 1.0.1 through 1.0.1f allows remote attackers to read sensitive memory (Heartbleed).",
                "cvss_score": 7.5, "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "severity": "high", "published_date": "2014-04-07",
                "affected": ["openssl 1.0.1"],
                "remediation": "Update OpenSSL to 1.0.1g or later. Revoke and reissue all SSL certificates.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
            },
            "CVE-2021-41773": {
                "title": "Apache HTTP Server 2.4.49 Path Traversal",
                "description": "A path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49 allows attackers to map URLs to files outside the expected document root.",
                "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high", "published_date": "2021-10-05",
                "affected": ["apache 2.4.49"],
                "remediation": "Update Apache HTTP Server to 2.4.51 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            },
            "CVE-2017-5638": {
                "title": "Apache Struts 2 Remote Code Execution",
                "description": "Apache Struts 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 allows remote code execution via a crafted Content-Type header.",
                "cvss_score": 10.0, "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "critical", "published_date": "2017-03-11",
                "affected": ["apache struts 2.3", "apache struts 2.5"],
                "remediation": "Update Apache Struts to 2.3.32 or 2.5.10.1 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
            },
            "CVE-2018-11776": {
                "title": "Apache Struts 2 Namespace RCE",
                "description": "Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 allow remote code execution when namespace value is not set for results with no namespace.",
                "cvss_score": 8.1, "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "high", "published_date": "2018-08-22",
                "affected": ["apache struts 2.3", "apache struts 2.5"],
                "remediation": "Update Apache Struts to 2.3.35 or 2.5.17 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-11776"],
            },
            "CVE-2011-2523": {
                "title": "VSFTPD 2.3.4 Backdoor Command Execution",
                "description": "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200 when a username containing :) is used.",
                "cvss_score": 10.0, "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "severity": "critical", "published_date": "2011-07-04",
                "affected": ["vsftpd 2.3.4"],
                "remediation": "Remove compromised vsftpd 2.3.4. Install a clean version from official source.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
            },
            "CVE-2017-7494": {
                "title": "SambaCry — Samba Remote Code Execution",
                "description": "Samba 3.5.0 onwards is vulnerable to remote code execution by a malicious client uploading a shared library to a writable share.",
                "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical", "published_date": "2017-05-24",
                "affected": ["samba 3.5", "samba 4"],
                "remediation": "Update Samba to 4.6.4, 4.5.10, or 4.4.14 or later. Add 'nt pipe support = no' to smb.conf.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7494"],
            },
            "CVE-2016-6210": {
                "title": "OpenSSH User Enumeration",
                "description": "OpenSSH before 7.3 is vulnerable to user enumeration via timing differences in authentication responses.",
                "cvss_score": 7.0, "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "high", "published_date": "2016-08-07",
                "affected": ["openssh 7.2", "openssh 7.0"],
                "remediation": "Update OpenSSH to 7.3 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-6210"],
            },
            "CVE-2020-10188": {
                "title": "Telnet Remote Code Execution",
                "description": "Telnetd in netkit telnet through 0.17 allows remote attackers to execute arbitrary code via short writes or urgent data.",
                "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical", "published_date": "2020-03-06",
                "affected": ["telnet"],
                "remediation": "Disable telnet service. Use SSH for remote administration instead.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-10188"],
            },
            "CVE-2014-6271": {
                "title": "Shellshock — GNU Bash Remote Code Execution",
                "description": "GNU Bash through 4.3 processes trailing strings after function definitions in environment variables, allowing remote code execution.",
                "cvss_score": 10.0, "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "severity": "critical", "published_date": "2014-09-24",
                "affected": ["bash 4.3", "bash 4.2", "bash 4.1"],
                "remediation": "Update GNU Bash to 4.3 patch 25 or later.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
            },
            "CVE-2016-6662": {
                "title": "MySQL Remote Code Execution",
                "description": "Oracle MySQL before 5.5.52, 5.6.x before 5.6.33, and 5.7.x before 5.7.15 allows remote code execution via manipulated config files.",
                "cvss_score": 9.0, "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "critical", "published_date": "2016-09-20",
                "affected": ["mysql 5.5", "mysql 5.6", "mysql 5.7"],
                "remediation": "Update MySQL to 5.5.52, 5.6.33, 5.7.15 or later. Restrict FILE privilege.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-6662"],
            },
            "CVE-2017-12617": {
                "title": "Apache Tomcat Remote Code Execution via PUT",
                "description": "Apache Tomcat 7.0.0 to 7.0.79 and 8.0.0-RC1 to 8.0.44 allows remote code execution via a crafted PUT request with a JSP file.",
                "cvss_score": 8.1, "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "high", "published_date": "2017-10-04",
                "affected": ["tomcat 7.0", "tomcat 8.0"],
                "remediation": "Update Apache Tomcat to 7.0.82 or 8.0.47 or later. Disable PUT method.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-12617"],
            },
        }

    # ─────────────────────────────────────
    # Match vulnerabilities to scan results
    # ─────────────────────────────────────
    def match_vulnerabilities(self, scan_summary: Any) -> List[VulnerabilityMatch]:
        """Match CVEs to all services found in a scan."""
        matches: List[VulnerabilityMatch] = []
        hosts = getattr(scan_summary, "hosts", [])
        for host in hosts:
            for svc in getattr(host, "services", []):
                svc_name = getattr(svc, "product", "") or getattr(svc, "service_name", "")
                svc_version = getattr(svc, "version", "")
                port = getattr(svc, "port", 0)
                protocol = getattr(svc, "protocol", "tcp")
                cpe = getattr(svc, "cpe", "")
                logger.info("[NETRIX] Checking CVEs for %s %s on port %d", svc_name, svc_version, port)
                cve_list = self.match_service_to_cves(svc_name, svc_version, cpe)
                nse_scripts = getattr(svc, "nse_scripts", {})
                nse_findings: List[str] = []
                if nse_scripts:
                    nse_cves = self.parse_nse_vulnerabilities(nse_scripts)
                    existing_ids = {c.cve_id for c in cve_list}
                    for nc in nse_cves:
                        if nc.cve_id not in existing_ids:
                            cve_list.append(nc)
                            existing_ids.add(nc.cve_id)
                    nse_findings = list(nse_scripts.keys())
                if not cve_list:
                    continue
                highest_cvss = max((c.cvss_score for c in cve_list), default=0.0)
                match = VulnerabilityMatch(
                    service_name=svc_name,
                    service_version=svc_version,
                    port=port,
                    protocol=protocol,
                    cve_details=cve_list,
                    nse_findings=nse_findings,
                    total_vulnerabilities=len(cve_list),
                    highest_severity=self._score_to_severity(highest_cvss),
                    highest_cvss=highest_cvss,
                )
                matches.append(match)
                for cve in cve_list:
                    logger.info(
                        "[NETRIX] CVE Found: %s | Severity: %s | Score: %.1f",
                        cve.cve_id, cve.severity, cve.cvss_score,
                    )
        return matches

    # ─────────────────────────────────────
    # Match single service to CVEs
    # ─────────────────────────────────────
    def match_service_to_cves(self, service_name: str, version: str, cpe: str = "") -> List[CVEDetail]:
        """Match a single service+version to known CVEs using all sources."""
        results: List[CVEDetail] = []
        seen_ids: set = set()
        name_lower = service_name.lower().strip()
        version_lower = version.lower().strip()
        lookup_key = f"{name_lower} {version_lower}".strip()

        # 1. Well-known vulnerable services
        for key, cve_ids in WELL_KNOWN_VULNERABLE_SERVICES.items():
            if key == lookup_key or key == name_lower:
                for cid in cve_ids:
                    if cid not in seen_ids:
                        detail = self._lookup_cve(cid)
                        if detail:
                            results.append(detail)
                            seen_ids.add(cid)

        # 2. Offline DB fuzzy match
        for cve_id, cve_data in self._offline_db.items():
            if cve_id in seen_ids:
                continue
            affected = cve_data.get("affected", [])
            desc_lower = cve_data.get("description", "").lower()
            for af in affected:
                if name_lower in af.lower() or lookup_key in af.lower():
                    detail = self._offline_to_cve_detail(cve_id, cve_data)
                    results.append(detail)
                    seen_ids.add(cve_id)
                    break
            else:
                if lookup_key and lookup_key in desc_lower:
                    detail = self._offline_to_cve_detail(cve_id, cve_data)
                    results.append(detail)
                    seen_ids.add(cve_id)

        # 3. CPE-based NVD search
        if cpe:
            try:
                cpe_results = self.search_cves_by_cpe(cpe)
                for cr in cpe_results:
                    if cr.cve_id not in seen_ids:
                        results.append(cr)
                        seen_ids.add(cr.cve_id)
            except Exception as exc:
                logger.debug("[NETRIX] CPE search failed: %s", exc)

        # 4. Keyword NVD search
        if lookup_key:
            try:
                kw_results = self.search_cves_by_keyword(lookup_key, max_results=5)
                for kr in kw_results:
                    if kr.cve_id not in seen_ids:
                        results.append(kr)
                        seen_ids.add(kr.cve_id)
            except Exception as exc:
                logger.debug("[NETRIX] Keyword search failed: %s", exc)

        results.sort(key=lambda c: c.cvss_score, reverse=True)
        return results

    # ─────────────────────────────────────
    # Helper: lookup CVE from offline then NVD
    # ─────────────────────────────────────
    def _lookup_cve(self, cve_id: str) -> Optional[CVEDetail]:
        if cve_id in self._offline_db:
            return self._offline_to_cve_detail(cve_id, self._offline_db[cve_id])
        return self.fetch_cve_from_nvd(cve_id)

    def _offline_to_cve_detail(self, cve_id: str, data: Dict) -> CVEDetail:
        score = data.get("cvss_score", 0.0)
        return CVEDetail(
            cve_id=cve_id,
            title=data.get("title", cve_id),
            description=data.get("description", ""),
            cvss_score=score,
            cvss_vector=data.get("cvss_vector", ""),
            severity=data.get("severity", self._score_to_severity(score)),
            published_date=data.get("published_date", ""),
            remediation=data.get("remediation", self.get_remediation(cve_id, "")),
            references=data.get("references", []),
            source="offline_db",
            affected_products=data.get("affected", []),
        )

    # ─────────────────────────────────────
    # Parse NSE vulnerabilities
    # ─────────────────────────────────────
    def parse_nse_vulnerabilities(self, nse_output: Dict[str, str]) -> List[CVEDetail]:
        """Extract CVE details from NSE script output."""
        results: List[CVEDetail] = []
        seen: set = set()
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

        for script_name, output in nse_output.items():
            if not output:
                continue
            upper_output = output.upper()
            is_vuln = any(kw in upper_output for kw in ("VULNERABLE", "STATE: VULNERABLE", "RISK FACTOR:", "EXPLOIT AVAILABLE"))
            if not is_vuln:
                continue
            cve_ids = cve_pattern.findall(output)
            if cve_ids:
                for cid in cve_ids:
                    cid_upper = cid.upper()
                    if cid_upper not in seen:
                        detail = self._lookup_cve(cid_upper)
                        if detail:
                            results.append(detail)
                            seen.add(cid_upper)
            else:
                nse_detail = CVEDetail(
                    cve_id=f"NSE-{script_name}",
                    title=f"NSE Detection: {script_name}",
                    description=output[:500],
                    cvss_score=7.0,
                    cvss_vector="",
                    severity="high",
                    published_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    remediation=f"Investigate and remediate finding from NSE script: {script_name}",
                    references=[],
                    source="nse_script",
                    affected_products=[],
                )
                results.append(nse_detail)
        return results

    # ─────────────────────────────────────
    # Remediation advice
    # ─────────────────────────────────────
    def get_remediation(self, cve_id: str, service_name: str) -> str:
        """Generate remediation advice for a CVE."""
        if cve_id in self._offline_db:
            stored = self._offline_db[cve_id].get("remediation", "")
            if stored:
                return stored

        svc = service_name.lower()
        if any(w in svc for w in ("apache", "nginx", "httpd", "iis")):
            return f"Update the web server software to the latest patched version. Review {cve_id} advisory for specific patches."
        if any(w in svc for w in ("ssh", "openssh")):
            return f"Update OpenSSH to the latest version. Review {cve_id} for configuration mitigations."
        if any(w in svc for w in ("mysql", "postgres", "mariadb", "mssql")):
            return f"Update the database server to the latest version. Restrict network access to database ports. Review {cve_id}."
        if any(w in svc for w in ("ftp", "vsftpd", "proftpd")):
            return f"Update or replace the FTP server. Consider switching to SFTP. Review {cve_id}."
        if any(w in svc for w in ("smb", "samba")):
            return f"Apply security patches for SMB/Samba. Disable SMBv1 if possible. Review {cve_id}."
        if any(w in svc for w in ("rdp", "remote desktop")):
            return f"Apply the latest Windows security updates. Enable NLA. Restrict RDP access via firewall. Review {cve_id}."
        if "telnet" in svc:
            return f"Disable telnet immediately. Replace with SSH. Review {cve_id}."
        return f"Apply vendor patches for {cve_id}. Update affected software to the latest version. Restrict network exposure."

    # ─────────────────────────────────────
    # Risk calculation
    # ─────────────────────────────────────
    def calculate_overall_risk(self, vulnerability_matches: List[VulnerabilityMatch]) -> Dict:
        """Calculate overall network risk assessment."""
        if not vulnerability_matches:
            return {
                "overall_score": 0, "overall_severity": "info",
                "total_vulnerabilities": 0, "critical_count": 0,
                "high_count": 0, "medium_count": 0, "low_count": 0,
                "most_vulnerable_host": "N/A", "most_dangerous_cve": "N/A",
                "risk_summary": "No vulnerabilities detected.",
            }

        critical = high = medium = low = 0
        all_cves: List[CVEDetail] = []
        host_vuln_count: Dict[str, int] = {}

        for match in vulnerability_matches:
            host_key = f"{match.service_name}:{match.port}"
            host_vuln_count[host_key] = host_vuln_count.get(host_key, 0) + match.total_vulnerabilities
            for cve in match.cve_details:
                all_cves.append(cve)
                sev = cve.severity.lower()
                if sev == "critical":
                    critical += 1
                elif sev == "high":
                    high += 1
                elif sev == "medium":
                    medium += 1
                elif sev == "low":
                    low += 1

        total = critical + high + medium + low
        score = min(100, critical * 25 + high * 15 + medium * 8 + low * 3)
        most_vuln = max(host_vuln_count, key=host_vuln_count.get) if host_vuln_count else "N/A"
        most_dangerous = max(all_cves, key=lambda c: c.cvss_score).cve_id if all_cves else "N/A"

        severity = self._score_to_severity(score / 10.0) if score > 0 else "info"
        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        elif score >= 20:
            severity = "low"

        summary_parts = []
        if critical:
            summary_parts.append(f"{critical} critical")
        if high:
            summary_parts.append(f"{high} high")
        if medium:
            summary_parts.append(f"{medium} medium")
        if low:
            summary_parts.append(f"{low} low")
        risk_summary = f"Found {total} vulnerabilities: {', '.join(summary_parts)}. Immediate action required for critical findings."

        return {
            "overall_score": score, "overall_severity": severity,
            "total_vulnerabilities": total, "critical_count": critical,
            "high_count": high, "medium_count": medium, "low_count": low,
            "most_vulnerable_host": most_vuln, "most_dangerous_cve": most_dangerous,
            "risk_summary": risk_summary,
        }

    # ─────────────────────────────────────
    # Save to database
    # ─────────────────────────────────────
    def save_vulnerabilities_to_db(
        self,
        vulnerability_matches: List[VulnerabilityMatch],
        scan_id: int,
        db_session: Any,
    ) -> int:
        """Persist vulnerability findings to the MySQL database."""
        count = 0
        try:
            for match in vulnerability_matches:
                for cve in match.cve_details:
                    pub_date = None
                    if cve.published_date:
                        try:
                            pub_date = datetime.strptime(cve.published_date[:10], "%Y-%m-%d").date()
                        except (ValueError, TypeError):
                            pub_date = None

                    vuln_record = Vulnerability(
                        scan_id=scan_id,
                        host_id=1,
                        port_id=None,
                        cve_id=cve.cve_id,
                        cvss_score=cve.cvss_score,
                        cvss_vector=cve.cvss_vector,
                        severity=cve.severity,
                        title=cve.title[:255],
                        description=cve.description,
                        remediation=cve.remediation,
                        published_date=pub_date,
                        source=cve.source if cve.source in ("nvd_api", "offline_db", "nse_script") else "offline_db",
                    )
                    db_session.add(vuln_record)
                    count += 1
            db_session.commit()
            logger.info("[NETRIX] Saved %d vulnerabilities to database", count)
        except Exception as exc:
            db_session.rollback()
            logger.error("[NETRIX] Failed to save vulnerabilities: %s", exc)
        return count

    # ─────────────────────────────────────
    # Serialization
    # ─────────────────────────────────────
    def to_dict(self, matches: List[VulnerabilityMatch]) -> List[Dict]:
        """Convert vulnerability matches to list of dicts."""
        result: List[Dict] = []
        for match in matches:
            result.append({
                "service_name": match.service_name,
                "service_version": match.service_version,
                "port": match.port,
                "protocol": match.protocol,
                "total_vulnerabilities": match.total_vulnerabilities,
                "highest_severity": match.highest_severity,
                "highest_cvss": match.highest_cvss,
                "nse_findings": match.nse_findings,
                "cve_details": [asdict(cve) for cve in match.cve_details],
            })
        return result
