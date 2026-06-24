"""
Data contracts for Module 2: Unified Scanner.

Defines standardized dataclasses for findings, issues, CVEs, ports,
and the final ScanResult.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json


@dataclass
class HeaderIssue:
    """Represents a single security header violation or misconfiguration."""
    header_name: str
    severity: str          # critical, high, medium, low, info
    issue: str
    recommendation: str
    current_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header_name": self.header_name,
            "severity": self.severity,
            "issue": self.issue,
            "recommendation": self.recommendation,
            "current_value": self.current_value
        }

    @staticmethod
    def validate_severity(severity: str) -> bool:
        return severity.lower() in {"critical", "high", "medium", "low", "info"}


@dataclass
class HttpFinding:
    """Result of an HTTP/HTTPS probe."""
    url: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict[str, str]] = field(default_factory=list)
    server_software: Optional[str] = None
    server_version: Optional[str] = None
    is_https: bool = False
    ssl_valid: Optional[bool] = None
    ssl_expiry: Optional[str] = None
    ssl_issuer: Optional[str] = None
    header_issues: List[HeaderIssue] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "cookies": self.cookies,
            "server_software": self.server_software,
            "server_version": self.server_version,
            "is_https": self.is_https,
            "ssl_valid": self.ssl_valid,
            "ssl_expiry": self.ssl_expiry,
            "ssl_issuer": self.ssl_issuer,
            "header_issues": [issue.to_dict() for issue in self.header_issues],
            "error": self.error
        }


@dataclass
class CVEInfo:
    """Represents a matched CVE vulnerability."""
    cve_id: str
    title: str = ""
    cvss_score: float = 0.0
    severity: str = "info"
    description: str = ""
    affected_software: str = ""
    affected_versions: List[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "description": self.description,
            "affected_software": self.affected_software,
            "affected_versions": self.affected_versions,
            "remediation": self.remediation
        }


@dataclass
class PortInfo:
    """Details about an open port and associated service."""
    port: int
    protocol: str = "tcp"       # tcp/udp
    state: str = "open"
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "error": self.error
        }


@dataclass
class ScanResult:
    """Complete result from the Unified Scanner."""
    target: str
    scan_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    http_finding: Optional[HttpFinding] = None
    header_issues: List[HeaderIssue] = field(default_factory=list)
    cve_matches: List[CVEInfo] = field(default_factory=list)
    open_ports: List[PortInfo] = field(default_factory=list)
    security_score: float = 0.0          # 0-100
    summary: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    errors: List[str] = field(default_factory=list)
    modules_executed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "http_finding": self.http_finding.to_dict() if self.http_finding else None,
            "header_issues": [i.to_dict() for i in self.header_issues],
            "cve_matches": [c.to_dict() for c in self.cve_matches],
            "open_ports": [p.to_dict() for p in self.open_ports],
            "security_score": self.security_score,
            "summary": self.summary,
            "errors": self.errors,
            "modules_executed": self.modules_executed
        }

    def calculate_score(self) -> None:
        """Calculate a simple security score based on issue severities."""
        # Weighted deduction: critical -20, high -10, medium -5, low -2, info -0
        deductions = {
            "critical": 20,
            "high": 10,
            "medium": 5,
            "low": 2,
            "info": 0
        }
        total_deduction = sum(
            self.summary.get(sev, 0) * deduct
            for sev, deduct in deductions.items()
        )
        self.security_score = max(0.0, 100.0 - total_deduction)

    def update_summary(self, severity: str) -> None:
        """Increment severity count."""
        if severity in self.summary:
            self.summary[severity] += 1

    def add_error(self, error_msg: str) -> None:
        self.errors.append(error_msg)