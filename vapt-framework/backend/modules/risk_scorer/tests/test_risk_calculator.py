import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.risk_scorer.risk_calculator import RiskCalculator
from backend.modules.risk_scorer.data_contracts import ScoredFinding

def sample_findings():
    return [
        ScoredFinding("1", "CVE-2020-11984", "High risk", 7.5, 8.5, "high", "cve", "example.com", "Upgrade", "cve"),
        ScoredFinding("2", "Missing HSTS", "Medium", 5.3, 5.3, "medium", "header", "example.com", "Add HSTS", "http_scanner"),
        ScoredFinding("3", "CORS wildcard", "Low", 3.5, 3.5, "low", "cors", "example.com", "Fix CORS", "http_scanner"),
    ]

def test_calculate_overall_score():
    score = RiskCalculator.calculate_overall_score(sample_findings(), "domain")
    # Expected deductions: high: (8.5/10)*2.0=1.7, medium: (5.3/10)*1.0=0.53, low: (3.5/10)*0.5=0.175
    # Total: 2.405, score = 100 - 2.405 = 97.595 -> round to 97.6
    assert round(score, 1) == 97.6

def test_prioritize_findings():
    findings = sample_findings()
    sorted_f = RiskCalculator.prioritize_findings(findings)
    assert sorted_f[0].severity == "high"
    assert sorted_f[-1].severity == "low"

def test_grade():
    grade, desc = RiskCalculator.grade_from_score(85)
    assert grade == "B"
    grade, desc = RiskCalculator.grade_from_score(45)
    assert grade == "D"