# ─────────────────────────────────────────
# Netrix — cli/api_client.py
# Purpose: Centralized API client — all backend calls go through here.
# ─────────────────────────────────────────

from pathlib import Path
from typing import Dict, List, Optional

import httpx

from cli.config import API_BASE_URL, get_token


class NetrixAPIClient:
    """Handles all Netrix backend API communication."""

    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        self.base_url = base_url or API_BASE_URL
        self.token = token or get_token()
        self.headers: Dict[str, str] = {}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    # ── Internal helpers ─────────────────────────────────────────────

    def _get(self, path: str, params: Optional[Dict] = None, timeout: float = 30.0) -> httpx.Response:
        return httpx.get(
            f"{self.base_url}{path}",
            headers=self.headers,
            params=params,
            timeout=timeout,
        )

    def _post(self, path: str, json: Optional[Dict] = None, timeout: float = 30.0) -> httpx.Response:
        return httpx.post(
            f"{self.base_url}{path}",
            headers=self.headers,
            json=json,
            timeout=timeout,
        )

    def _delete(self, path: str, timeout: float = 30.0) -> httpx.Response:
        return httpx.delete(
            f"{self.base_url}{path}",
            headers=self.headers,
            timeout=timeout,
        )

    # ── Auth ─────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> httpx.Response:
        return httpx.post(
            f"{self.base_url}/auth/login",
            json={"username": username, "password": password},
            timeout=15.0,
        )

    def register(self, username: str, email: str, password: str) -> httpx.Response:
        return httpx.post(
            f"{self.base_url}/auth/register",
            json={"username": username, "email": email, "password": password},
            timeout=15.0,
        )

    def get_me(self) -> httpx.Response:
        return self._get("/auth/me")

    def logout_server(self) -> httpx.Response:
        return self._post("/auth/logout")

    # ── Scans ─────────────────────────────────────────────────────────

    def start_scan(
        self, target: str, scan_type: str, custom_ports: Optional[str] = None
    ) -> httpx.Response:
        payload: Dict = {"target": target, "scan_type": scan_type}
        if custom_ports:
            payload["custom_ports"] = custom_ports
        return self._post("/scans/", json=payload, timeout=30.0)

    def get_scan_status(self, scan_id: int) -> httpx.Response:
        return self._get(f"/scans/{scan_id}/status", timeout=10.0)

    def get_scan_results(self, scan_id: int) -> httpx.Response:
        return self._get(f"/scans/{scan_id}/results", timeout=30.0)

    def get_scans(
        self, page: int = 1, page_size: int = 20, status: Optional[str] = None
    ) -> httpx.Response:
        params: Dict = {"page": page, "page_size": page_size}
        if status:
            params["status"] = status
        return self._get("/scans/", params=params)

    def delete_scan(self, scan_id: int) -> httpx.Response:
        return self._delete(f"/scans/{scan_id}")

    # ── Hosts ──────────────────────────────────────────────────────────

    def get_hosts(self, scan_id: int) -> httpx.Response:
        return self._get(f"/scans/{scan_id}/hosts")

    def get_host_ports(self, host_id: int) -> httpx.Response:
        return self._get(f"/hosts/{host_id}/ports")

    # ── Vulnerabilities ───────────────────────────────────────────────

    def get_vulnerabilities(
        self,
        scan_id: Optional[int] = None,
        severity: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> httpx.Response:
        params: Dict = {"page": page, "page_size": page_size}
        if scan_id:
            params["scan_id"] = scan_id
        if severity and severity.lower() != "all":
            params["severity"] = severity.lower()
        return self._get("/vulnerabilities/", params=params)

    def get_cve_detail(self, cve_id: str) -> httpx.Response:
        return self._get(f"/vulnerabilities/cve/{cve_id}", timeout=20.0)

    def get_vuln_stats(self, scan_id: int) -> httpx.Response:
        return self._get(f"/vulnerabilities/stats/{scan_id}")

    # ── Reports ───────────────────────────────────────────────────────

    def generate_report(self, scan_id: int, format: str) -> httpx.Response:
        return self._post(
            "/reports/generate",
            json={"scan_id": scan_id, "format": format},
            timeout=120.0,
        )

    def download_report(self, report_id: int) -> httpx.Response:
        return self._get(f"/reports/{report_id}/download", timeout=120.0)

    def get_reports(
        self, page: int = 1, page_size: int = 20, format: Optional[str] = None
    ) -> httpx.Response:
        params: Dict = {"page": page, "page_size": page_size}
        if format:
            params["format"] = format
        return self._get("/reports/", params=params)

    def delete_report(self, report_id: int) -> httpx.Response:
        return self._delete(f"/reports/{report_id}")

    # ── Dashboard ─────────────────────────────────────────────────────

    def get_dashboard_stats(self) -> httpx.Response:
        return self._get("/dashboard/stats")

    def get_recent_scans(self, limit: int = 5) -> httpx.Response:
        return self._get("/dashboard/recent-scans", params={"limit": limit})

    def get_vuln_chart(self) -> httpx.Response:
        return self._get("/dashboard/vulnerability-chart")

    # ── Health ────────────────────────────────────────────────────────

    def health_check(self) -> httpx.Response:
        return httpx.get(f"{self.base_url.replace('/api/v1', '')}/health", timeout=5.0)
