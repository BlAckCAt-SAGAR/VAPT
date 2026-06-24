import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.risk_scorer.risk_orchestrator import RiskOrchestrator

def test_run_integration():
    scan_context = {
        "target": "example.com",
        "target_type": "domain",
        "scanner_results": {
            "cve_matches": [
                {"cve_id": "CVE-2020-11984", "cvss_score": 7.5, "severity": "high",
                 "title": "Apache vulnerability", "description": "desc", "remediation": "Upgrade"}
            ],
            "header_issues": [
                {"header_name": "Strict-Transport-Security", "severity": "high",
                 "issue": "Missing HSTS", "recommendation": "Enable HSTS"}
            ],
            "open_ports": [
                {"port": 22, "service": "ssh", "banner": "OpenSSH 7.9"}
            ],
            "http_finding": {
                "ssl_valid": True,
                "ssl_issuer": "GlobalSign"
            },
            "security_score": None,
            "summary": None
        },
        "modules_executed": ["recon", "scanner"]
    }

    orchestrator = RiskOrchestrator(config={"public_facing": True})
    result = orchestrator.run(scan_context)

    assert "risk_report" in result
    report = result["risk_report"]
    assert report["overall_score"] <= 100
    assert report["grade"] in ("A","B","C","D","F")
    assert len(report["findings"]) >= 3  # CVE + header + port
    assert "risk_scorer" in result["modules_executed"]
    assert result["scanner_results"]["security_score"] is not None