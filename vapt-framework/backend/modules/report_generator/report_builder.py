"""
Builds report sections from scan_context and risk_report.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

from .data_contracts import Report, ExecutiveSummary, FindingSection


class ReportBuilder:
    """Assembles a complete Report from pipeline data."""

    @staticmethod
    def build(scan_context: Dict[str, Any]) -> Report:
        """
        Construct a Report object from the full scan_context.

        Args:
            scan_context: The accumulated data from Modules 1, 2, and 3.

        Returns:
            Report object ready for rendering.
        """
        target = scan_context.get("target", "unknown")
        risk_report = scan_context.get("risk_report", {})
        scanner_results = scan_context.get("scanner_results", {})
        recon_data = scan_context.get("recon_data", {})

        # Executive Summary
        exec_summary = ExecutiveSummary(
            target=target,
            assessment_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            overall_score=risk_report.get("overall_score", 0),
            grade=risk_report.get("grade", "N/A"),
            total_findings=risk_report.get("summary", {}).get("total_findings", 0),
            critical_count=risk_report.get("summary", {}).get("critical_count", 0),
            high_count=risk_report.get("summary", {}).get("high_count", 0),
            medium_count=risk_report.get("summary", {}).get("medium_count", 0),
            low_count=risk_report.get("summary", {}).get("low_count", 0),
            risk_level=ReportBuilder._risk_level(risk_report.get("grade", "N/A")),
            top_3_recommendations=risk_report.get("recommendations", [])[:3]
        )

        # Detailed Findings
        findings = []
        for f in risk_report.get("findings", []):
            findings.append(FindingSection(
                finding_id=f.get("finding_id", str(uuid.uuid4())[:8]),
                title=f.get("title", "Unknown"),
                severity=f.get("severity", "low"),
                cvss_score=f.get("adjusted_cvss", f.get("raw_cvss", 0)),
                description=f.get("description", ""),
                affected_asset=f.get("affected_asset", target),
                remediation=f.get("remediation", ""),
                category=f.get("category", "")
            ))

        # Open ports from scanner
        open_ports = scanner_results.get("open_ports", [])

        # DNS & WHOIS from recon
        dns_info = {
            "dns_records": recon_data.get("dns_records", {}),
            "resolved_ips": recon_data.get("resolved_ips", [])
        }
        whois_info = recon_data.get("whois", {})
        subdomains = recon_data.get("subdomains", [])

        return Report(
            report_id=f"VAPT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
            executive_summary=exec_summary,
            findings=findings,
            open_ports=open_ports,
            dns_info=dns_info,
            whois_info=whois_info,
            subdomains=subdomains
        )

    @staticmethod
    def _risk_level(grade: str) -> str:
        mapping = {"A": "Low", "B": "Moderate", "C": "High", "D": "Critical", "F": "Critical"}
        return mapping.get(grade, "Unknown")