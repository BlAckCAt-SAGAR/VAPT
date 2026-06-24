import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.scanner.vuln_matcher import VulnMatcher

def test_match_exact_version():
    matcher = VulnMatcher()
    matcher.cve_entries = [{
        "software": "Apache",
        "versions": ["2.4.41"],
        "cve_id": "CVE-2020-11984",
        "cvss": 7.5,
        "severity": "high",
        "description": "Test",
        "remediation": "Upgrade"
    }]
    matches = matcher.match("Apache", "2.4.41")
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2020-11984"

def test_match_range_less_equal():
    matcher = VulnMatcher()
    matcher.cve_entries = [{
        "software": "nginx",
        "versions": ["<=1.18.0"],
        "cve_id": "CVE-2021-23017",
        "cvss": 7.5,
        "severity": "high",
        "description": "Test",
        "remediation": "Upgrade"
    }]
    matches = matcher.match("nginx", "1.17.5")
    assert len(matches) == 1
    matches_out = matcher.match("nginx", "1.19.0")
    assert len(matches_out) == 0

def test_version_comparison():
    matcher = VulnMatcher()
    assert matcher._version_le("2.4.41", "2.4.42") is True
    assert matcher._version_lt("2.4.41", "2.4.41") is False
    assert matcher._version_ge("2.5.0", "2.4.42") is True