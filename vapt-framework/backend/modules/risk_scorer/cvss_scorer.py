"""CVSS scoring and environmental modifiers."""

import logging
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)


class CVSSScorer:
    """Assigns CVSS scores to various types of findings."""

    # Default CVSS scores for non-CVE issues (based on OWASP/NIST averages)
    DEFAULT_CVSS_MAP: Dict[str, float] = {
        "missing_hsts": 5.3,
        "missing_csp": 4.3,
        "missing_x_frame_options": 4.3,
        "missing_x_content_type_options": 3.1,
        "missing_referrer_policy": 2.6,
        "missing_permissions_policy": 2.6,
        "cookie_missing_secure": 5.3,
        "cookie_missing_httponly": 4.3,
        "cookie_samesite_none": 4.3,
        "cors_wildcard": 3.5,
        "ssl_expired": 7.5,
        "ssl_self_signed": 5.3,
        "open_ssh": 3.5,
        "open_mysql": 4.5,
        "open_rdp": 5.3,
        "open_ftp": 4.5,
        "open_telnet": 7.0,
        "open_unknown_service": 2.5,
    }

    # Environmental modifier factors
    MODIFIER_IMPACT: Dict[str, float] = {
        "publicly_accessible": 1.0,
        "sensitive_data_exposed": 1.5,
        "default_credentials": 2.0,
        "no_authentication_required": 1.0,
        "exploit_publicly_available": 1.5,
        "port_ssh_open": 0.5,
        "ssl_weak_cipher": 1.0,
    }

    @classmethod
    def score_finding(cls,
                      finding_type: str,
                      raw_cvss: Optional[float] = None,
                      severity: Optional[str] = None) -> float:
        """
        Return base CVSS score for a finding.

        Args:
            finding_type: Category like 'cve', 'missing_hsts', 'open_ssh', etc.
            raw_cvss: Original CVSS if available (for CVEs).
            severity: Fallback severity string (only used if no other mapping).

        Returns:
            Float score between 0.0 and 10.0.
        """
        # If raw CVSS is provided, use it (CVEs)
        if raw_cvss is not None and 0 <= raw_cvss <= 10:
            return raw_cvss

        # Lookup default mapping
        score = cls.DEFAULT_CVSS_MAP.get(finding_type.lower())
        if score is not None:
            return score

        # Fallback: map severity string to approximate scores
        severity_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.5
        }
        if severity:
            return severity_map.get(severity.lower(), 2.5)

        logger.warning(f"No score mapping for finding type '{finding_type}'. Using default 2.5")
        return 2.5

    @classmethod
    def apply_modifiers(cls, base_score: float, modifiers: List[str]) -> float:
        """
        Adjust base score by environmental modifiers (never exceeds 10.0).

        Args:
            base_score: The base CVSS score.
            modifiers: List of modifier keys.

        Returns:
            Adjusted score (capped at 10.0).
        """
        total_mod = sum(cls.MODIFIER_IMPACT.get(m, 0.0) for m in modifiers)
        adjusted = base_score + total_mod
        return min(10.0, max(0.0, adjusted))

    @staticmethod
    def severity_from_score(score: float) -> str:
        """Map numerical CVSS score to severity label."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 0.1:
            return "low"
        return "info"