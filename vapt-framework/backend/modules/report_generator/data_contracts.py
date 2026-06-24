Data contracts for the Report Generator module.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone


@dataclass
class ExecutiveSummary:
    """High-level summary for management."""
    target: str
    assessment_date: str
    overall_score: float
    grade: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_level: str  # "Low", "Medium", "High", "Critical"
    top_3_recommendations: List[str] = field(default_factory=list)
    scope: str = "Automated VAPT Assessment"
    assessor: str = "VAPT Framework v1.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "assessment_date": self.assessment_date,
            "overall_score": self.overall_score,
            "grade": self.grade,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "risk_level": self.risk_level,
            "top_3_recommendations": self.top_3_recommendations,
            "scope": self.scope,
            "assessor": self.assessor
        }


@dataclass
class FindingSection:
    """Detailed finding for technical audience."""
    finding_id: str
    title: str
    severity: str
    cvss_score: float
    description: str
    affected_asset: str
    remediation: str
    references: List[str] = field(default_factory=list)
    category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "affected_asset": self.affected_asset,
            "remediation": self.remediation,
            "references": self.references,
            "category": self.category
        }


@dataclass
class Report:
    """Complete security assessment report."""
    report_id: str
    executive_summary: ExecutiveSummary
    findings: List[FindingSection]
    open_ports: List[Dict[str, Any]]
    dns_info: Dict[str, Any]
    whois_info: Dict[str, Any]
    subdomains: List[str]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    html_content: Optional[str] = None
    pdf_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "executive_summary": self.executive_summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "open_ports": self.open_ports,
            "dns_info": self.dns_info,
            "whois_info": self.whois_info,
            "subdomains": self.subdomains,
            "generated_at": self.generated_at
        }