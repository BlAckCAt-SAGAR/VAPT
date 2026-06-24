"""Overall risk calculation, summary, and prioritization."""

import logging
from typing import List, Tuple
from .data_contracts import ScoredFinding, RiskSummary, RiskReport
from .cvss_scorer import CVSSScorer

logger = logging.getLogger(__name__)


class RiskCalculator:
    """Computes the overall security score and generates risk reports."""

    # Score deduction weights per severity
    SEVERITY_WEIGHTS = {
        "critical": 3.0,
        "high": 2.0,
        "medium": 1.0,
        "low": 0.5,
        "info": 0.0
    }

    @classmethod
    def calculate_overall_score(cls, findings: List[ScoredFinding], target_type: str = "domain") -> float:
        """
        Calculate overall security score from 0 to 100.

        Deductions are proportional to CVSS and severity weight.

        Args:
            findings: List of ScoredFinding objects.
            target_type: 'domain' or 'ip' (affects default exposure).

        Returns:
            Score between 0 and 100.
        """
        base_score = 100.0
        total_deduction = 0.0
        for f in findings:
            weight = cls.SEVERITY_WEIGHTS.get(f.severity, 0.0)
            deduction = (f.adjusted_cvss / 10.0) * weight
            total_deduction += deduction

        final_score = max(0.0, base_score - total_deduction)
        return round(final_score, 1)

    @classmethod
    def generate_summary(cls, findings: List[ScoredFinding]) -> RiskSummary:
        """Create a count summary and average CVSS."""
        summary = RiskSummary()
        cvss_values = []
        for f in findings:
            cvss_values.append(f.adjusted_cvss)
            if f.severity == "critical":
                summary.critical_count += 1
            elif f.severity == "high":
                summary.high_count += 1
            elif f.severity == "medium":
                summary.medium_count += 1
            elif f.severity == "low":
                summary.low_count += 1
            else:
                summary.info_count += 1
        summary.total_findings = len(findings)
        if cvss_values:
            summary.average_cvss = sum(cvss_values) / len(cvss_values)
            summary.highest_cvss = max(cvss_values)
        return summary

    @classmethod
    def prioritize_findings(cls, findings: List[ScoredFinding]) -> List[ScoredFinding]:
        """Sort findings: severity descending, then CVSS descending."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.adjusted_cvss)
        )

    @classmethod
    def grade_from_score(cls, score: float) -> Tuple[str, str]:
        """Convert numeric score to letter grade and description."""
        if score >= 90:
            return "A", "Excellent – Low risk"
        elif score >= 70:
            return "B", "Good – Moderate risk"
        elif score >= 50:
            return "C", "Fair – High risk"
        elif score >= 30:
            return "D", "Poor – Critical risk"
        else:
            return "F", "Failing – Immediate action required"