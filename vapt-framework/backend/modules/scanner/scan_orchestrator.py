"""
Module 2: Unified Scanner Orchestrator.

Implements the decision tree, uses recon data, and merges results
into the scan_context from Module 1.
"""

import asyncio
import logging
from typing import Optional, Callable, Dict, Any, List
from datetime import datetime, timezone

from .data_contracts import ScanResult, HttpFinding, HeaderIssue, PortInfo, CVEInfo
from .http_scanner import HTTPScanner
from .port_scanner import PortScanner
from .service_detector import ServiceDetector
from .vuln_matcher import VulnMatcher

logger = logging.getLogger(__name__)


class ScanOrchestratorConfig:
    """Configuration for the unified scanner."""
    def __init__(self,
                 http_timeout: float = 10.0,
                 port_timeout: float = 2.0,
                 max_concurrency: int = 100,
                 top_ports_web: List[int] = None,
                 top_ports_full: List[int] = None,
                 progress_callback: Optional[Callable] = None):
        self.http_timeout = http_timeout
        self.port_timeout = port_timeout
        self.max_concurrency = max_concurrency
        self.top_ports_web = top_ports_web or PortScanner.TOP_20
        self.top_ports_full = top_ports_full or PortScanner.TOP_100
        self.progress_callback = progress_callback


class ScanOrchestrator:
    """
    Orchestrates the intelligent scanning process.

    Uses recon data from Module 1 and applies the decision tree.
    """

    def __init__(self, config: Optional[ScanOrchestratorConfig] = None):
        self.config = config or ScanOrchestratorConfig()
        self.http_scanner = HTTPScanner(timeout=self.config.http_timeout)
        self.port_scanner = PortScanner(timeout=self.config.port_timeout,
                                        max_concurrency=self.config.max_concurrency)
        self.service_detector = ServiceDetector(timeout=self.config.port_timeout)
        self.vuln_matcher = VulnMatcher()

    async def run(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point. Accepts the scan_context from Module 1 and returns updated context.
        """
        target = scan_context["target"]
        target_type = scan_context["target_type"]
        recon_data = scan_context.get("recon_data", {})
        resolved_ips = recon_data.get("resolved_ips", [])

        if not resolved_ips and target_type == "ip":
            resolved_ips = [target]

        primary_ip = resolved_ips[0] if resolved_ips else target

        self._report_progress("scanner", 0, "Initializing scanner")
        scan_result = ScanResult(target=target)
        modules_executed = []

        # ---- Step 1: HTTP/HTTPS Probe ----
        http_finding = await self._probe_web_service(primary_ip, target)
        if http_finding and http_finding.status_code:
            scan_result.http_finding = http_finding
            scan_result.header_issues.extend(http_finding.header_issues)
            for issue in http_finding.header_issues:
                scan_result.update_summary(issue.severity)
            modules_executed.append("http_scanner")

            # ---- Step 2: Version -> CVE Matching ----
            if http_finding.server_software:
                cves = self.vuln_matcher.match(http_finding.server_software, http_finding.server_version)
                scan_result.cve_matches = cves
                for cve in cves:
                    scan_result.update_summary(cve.severity)
                modules_executed.append("vuln_matcher")

        # ---- Step 3: Intelligent Port Scan ----
        if http_finding and http_finding.status_code:
            # Web service found, light scan
            ports_to_scan = self.config.top_ports_web
        else:
            # No web service, full scan
            ports_to_scan = self.config.top_ports_full

        self._report_progress("scanner", 40, f"Scanning {len(ports_to_scan)} ports")
        open_ports = await self.port_scanner.scan(primary_ip, ports_to_scan)
        modules_executed.append("port_scanner")

        # ---- Step 4: Service Detection ----
        port_infos = []
        if open_ports:
            self._report_progress("scanner", 70, "Detecting services")
            tasks = [self.service_detector.detect(primary_ip, port) for port in open_ports]
            port_infos = await asyncio.gather(*tasks, return_exceptions=True)
            port_infos = [p for p in port_infos if isinstance(p, PortInfo)]
            modules_executed.append("service_detector")

        scan_result.open_ports = port_infos

        # ---- Step 5: Calculate Score ----
        scan_result.calculate_score()
        scan_result.modules_executed = modules_executed
        self._report_progress("scanner", 100, "Scan complete")

        # Merge into scan_context
        scan_context["scanner_results"] = scan_result.to_dict()
        scan_context["modules_executed"] = scan_context.get("modules_executed", []) + modules_executed
        return scan_context

    async def _probe_web_service(self, ip: str, target: str) -> Optional[HttpFinding]:
        """Try HTTPS first, then HTTP, and return the finding."""
        # Try HTTPS
        self._report_progress("scanner", 10, "Probing HTTPS")
        finding = await self.http_scanner.probe(target, 443, use_https=True)
        if finding and finding.status_code:
            return finding

        # Try HTTP
        self._report_progress("scanner", 20, "Probing HTTP")
        finding = await self.http_scanner.probe(target, 80, use_https=False)
        return finding

    def _report_progress(self, module: str, percent: float, message: str) -> None:
        """Call progress callback if set."""
        if self.config.progress_callback:
            try:
                self.config.progress_callback(module, percent, message)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")
        logger.info(f"[{module}] {percent}% - {message}")