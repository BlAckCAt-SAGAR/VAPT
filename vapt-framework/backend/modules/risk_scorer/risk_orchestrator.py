"""Risk Scoring Orchestrator: converts scanner findings into a RiskReport."""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from .data_contracts import ScoredFinding, RiskReport, RiskSummary
from .cvss_scorer import CVSSScorer
from .risk_calculator import RiskCalculator

logger = logging.getLogger(__name__)


class RiskOrchestrator:
    """Orchestrates risk scoring for a target using scanner results."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Args:
            config: Dictionary with optional settings:
                - public_facing: bool, whether target is internet-facing (default True)
                - sensitive_data: bool, if target likely handles sensitive data (default False)
                - environmental_modifiers: list of predefined modifiers to apply globally
        """
        self.config = config or {}
        self.global_modifiers = self.config.get("environmental_modifiers", [])
        if self.config.get("public_facing", True):
            self.global_modifiers.append("publicly_accessible")
        if self.config.get("sensitive_data", False):
            self.global_modifiers.append("sensitive_data_exposed")

    def run(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform scanner_results into a RiskReport and merge back.

        Args:
            scan_context: The current state from previous modules.

        Returns:
            Updated scan_context with 'risk_report' key.
        """
        target = scan_context.get("target", "unknown")
        target_type = scan_context.get("target_type", "domain")
        scanner_results = scan_context.get("scanner_results", {})

        findings: List[ScoredFinding] = []
        # --- Process CVE matches ---
        cve_matches = scanner_results.get("cve_matches", [])
        for cve in cve_matches:
            finding = self._score_cve(cve, target)
            findings.append(finding)

        # --- Process header issues ---
        header_issues = scanner_results.get("header_issues", [])
        for issue in header_issues:
            finding = self._score_header_issue(issue, target)
            findings.append(finding)

        # --- Process open ports ---
        open_ports = scanner_results.get("open_ports", [])
        for port_info in open_ports:
            finding = self._score_open_port(port_info, target)
            if finding:
                findings.append(finding)

        # --- Process HTTP finding for SSL issues ---
        http_finding = scanner_results.get("http_finding")
        if http_finding:
            ssl_issues = self._check_ssl_issues(http_finding, target)
            findings.extend(ssl_issues)

        # Prioritize and compute scores
        findings = RiskCalculator.prioritize_findings(findings)
        overall_score = RiskCalculator.calculate_overall_score(findings, target_type)
        summary = RiskCalculator.generate_summary(findings)
        grade, grade_desc = RiskCalculator.grade_from_score(overall_score)

        # Top 3 recommendations (from critical/high findings)
        top_findings = [f for f in findings if f.severity in ("critical", "high")][:3]
        recommendations = [f.remediation for f in top_findings]
        if len(recommendations) < 3:
            # Add generic ones if not enough
            if not any("HSTS" in r for r in recommendations):
                recommendations.append("Enable HTTP Strict Transport Security (HSTS)")
            if not any("CSP" in r for r in recommendations):
                recommendations.append("Implement a Content Security Policy (CSP)")

        risk_report = RiskReport(
            target=target,
            target_type=target_type,
            overall_score=overall_score,
            grade=grade,
            grade_description=grade_desc,
            summary=summary,
            findings=findings,
            recommendations=recommendations[:3]
        )

        # Merge into scan_context
        scan_context["risk_report"] = risk_report.to_dict()
        scan_context["modules_executed"] = scan_context.get("modules_executed", []) + ["risk_scorer"]
        # Also update the scanner_results summary/score fields for consistency
        scanner_results["security_score"] = overall_score
        scanner_results["summary"] = summary.to_dict()
        scan_context["scanner_results"] = scanner_results

        logger.info(f"Risk scoring complete for {target}: Score {overall_score}/100 ({grade})")
        return scan_context

    def _score_cve(self, cve: Dict[str, Any], target: str) -> ScoredFinding:
        raw_cvss = cve.get("cvss_score", 0.0)
        severity = cve.get("severity", "info")
        cve_id = cve.get("cve_id", "CVE-UNKNOWN")
        # Determine modifiers
        modifiers = self.global_modifiers.copy()
        if cve.get("exploit_available", False):
            modifiers.append("exploit_publicly_available")

        return ScoredFinding(
            finding_id=f"cve-{cve_id}",
            title=f"CVE: {cve_id} - {cve.get('title', 'Unknown')}",
            description=cve.get("description", ""),
            raw_cvss=raw_cvss,
            adjusted_cvss=CVSSScorer.apply_modifiers(raw_cvss, modifiers),
            severity=CVSSScorer.severity_from_score(CVSSScorer.apply_modifiers(raw_cvss, modifiers)),
            category="cve",
            affected_asset=target,
            remediation=cve.get("remediation", "Apply vendor patch"),
            source="cve_database",
            environmental_modifiers=modifiers
        )

    def _score_header_issue(self, issue: Dict[str, Any], target: str) -> ScoredFinding:
        header_name = issue.get("header_name", "")
        # Determine finding_type key for default CVSS
        finding_type = self._map_header_to_type(header_name)
        modifiers = self.global_modifiers.copy()
        base_score = CVSSScorer.score_finding(finding_type, severity=issue.get("severity"))
        adjusted = CVSSScorer.apply_modifiers(base_score, modifiers)

        return ScoredFinding(
            finding_id=f"header-{header_name}",
            title=f"Missing or misconfigured: {header_name}",
            description=issue.get("issue", ""),
            raw_cvss=base_score,
            adjusted_cvss=adjusted,
            severity=CVSSScorer.severity_from_score(adjusted),
            category="header",
            affected_asset=target,
            remediation=issue.get("recommendation", "Add missing header"),
            source="http_scanner",
            environmental_modifiers=modifiers
        )

    def _score_open_port(self, port_info: Dict[str, Any], target: str) -> Optional[ScoredFinding]:
        port = port_info.get("port")
        service = port_info.get("service", "unknown").lower()
        # Skip if port is common HTTP/HTTPS (80/443) unless it's a sensitive service
        if port in (80, 443) and service in ("http", "https"):
            # Only flag if there is an explicit banner with vulnerable version
            banner = port_info.get("banner", "")
            if not banner or "cloudflare" in banner.lower():
                return None  # likely just a reverse proxy

        finding_type = f"open_{service}" if service in ("ssh", "mysql", "rdp", "ftp", "telnet") else "open_unknown_service"
        modifiers = self.global_modifiers.copy()
        if service == "ssh":
            modifiers.append("port_ssh_open")
        base_score = CVSSScorer.score_finding(finding_type)
        adjusted = CVSSScorer.apply_modifiers(base_score, modifiers)

        return ScoredFinding(
            finding_id=f"port-{port}",
            title=f"Open port {port} ({service})",
            description=f"Port {port} is open and running {service}. Banner: {port_info.get('banner', 'None')}",
            raw_cvss=base_score,
            adjusted_cvss=adjusted,
            severity=CVSSScorer.severity_from_score(adjusted),
            category="port",
            affected_asset=f"{target}:{port}",
            remediation=f"Close port {port} if not needed, or restrict access via firewall.",
            source="port_scanner",
            environmental_modifiers=modifiers
        )

    def _check_ssl_issues(self, http_finding: Dict[str, Any], target: str) -> List[ScoredFinding]:
        findings = []
        modifiers = self.global_modifiers.copy()
        # SSL expired
        if http_finding.get("ssl_valid") is False:
            base_score = CVSSScorer.score_finding("ssl_expired")
            adjusted = CVSSScorer.apply_modifiers(base_score, modifiers)
            findings.append(ScoredFinding(
                finding_id="ssl-expired",
                title="SSL certificate expired",
                description="The SSL/TLS certificate for this service has expired.",
                raw_cvss=base_score,
                adjusted_cvss=adjusted,
                severity=CVSSScorer.severity_from_score(adjusted),
                category="ssl",
                affected_asset=target,
                remediation="Renew the SSL certificate immediately.",
                source="http_scanner",
                environmental_modifiers=modifiers
            ))
        # Self-signed cert detection (simplistic: issuer empty or common for self-signed)
        issuer = http_finding.get("ssl_issuer", "")
        if issuer and ("self" in issuer.lower() or "unknown" in issuer.lower()):
            base_score = CVSSScorer.score_finding("ssl_self_signed")
            adjusted = CVSSScorer.apply_modifiers(base_score, modifiers)
            findings.append(ScoredFinding(
                finding_id="ssl-selfsigned",
                title="SSL certificate is self-signed",
                description="The SSL certificate is self-signed, which is untrusted for public use.",
                raw_cvss=base_score,
                adjusted_cvss=adjusted,
                severity=CVSSScorer.severity_from_score(adjusted),
                category="ssl",
                affected_asset=target,
                remediation="Replace the self-signed certificate with one from a trusted CA.",
                source="http_scanner",
                environmental_modifiers=modifiers
            ))
        return findings

    @staticmethod
    def _map_header_to_type(header_name: str) -> str:
        mapping = {
            "Strict-Transport-Security": "missing_hsts",
            "Content-Security-Policy": "missing_csp",
            "X-Frame-Options": "missing_x_frame_options",
            "X-Content-Type-Options": "missing_x_content_type_options",
            "Referrer-Policy": "missing_referrer_policy",
            "Permissions-Policy": "missing_permissions_policy",
            "Set-Cookie": "cookie_missing_secure",  # simplified, but will be enriched by issue text
        }
        return mapping.get(header_name, "missing_security_header")