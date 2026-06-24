"""Data contracts for Risk Scoring Engine."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone


@dataclass
class ScoredFinding:
    """A finding with a calculated CVSS score and risk context."""
    finding_id: str
    title: str
    description: str
    raw_cvss: float
    adjusted_cvss: float
    severity: str          # critical, high, medium, low, info
    category: str          # cve, header, port, ssl, cookie, cors
    affected_asset: str
    remediation: str
    source: str
    environmental_modifiers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "raw_cvss": self.raw_cvss,
            "adjusted_cvss": self.adjusted_cvss,
            "severity": self.severity,
            "category": self.category,
            "affected_asset": self.affected_asset,
            "remediation": self.remediation,
            "source": self.source,
            "environmental_modifiers": self.environmental_modifiers
        }


@dataclass
class RiskSummary:
    """Counts and metrics of findings."""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    average_cvss: float = 0.0
    highest_cvss: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "average_cvss": round(self.average_cvss, 1),
            "highest_cvss": round(self.highest_cvss, 1)
        }


@dataclass
class RiskReport:
    """Complete risk assessment output."""
    target: str
    target_type: str
    overall_score: float
    grade: str
    grade_description: str
    summary: RiskSummary
    findings: List[ScoredFinding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "overall_score": self.overall_score,
            "grade": self.grade,
            "grade_description": self.grade_description,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
            "generated_at": self.generated_at
        }