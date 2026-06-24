import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.risk_scorer.cvss_scorer import CVSSScorer

def test_score_cve():
    score = CVSSScorer.score_finding("cve", raw_cvss=9.8)
    assert score == 9.8

def test_score_missing_hsts():
    score = CVSSScorer.score_finding("missing_hsts")
    assert score == 5.3

def test_apply_modifiers():
    base = 5.0
    adjusted = CVSSScorer.apply_modifiers(base, ["publicly_accessible", "exploit_publicly_available"])
    assert adjusted == 7.5  # 5.0 + 1.0 + 1.5

def test_severity_from_score():
    assert CVSSScorer.severity_from_score(9.0) == "critical"
    assert CVSSScorer.severity_from_score(7.0) == "high"
    assert CVSSScorer.severity_from_score(4.0) == "medium"
    assert CVSSScorer.severity_from_score(2.0) == "low"
    assert CVSSScorer.severity_from_score(0.0) == "info"