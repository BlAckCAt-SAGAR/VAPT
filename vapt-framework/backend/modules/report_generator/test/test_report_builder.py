import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.report_generator.report_builder import ReportBuilder

def test_build_report():
    scan_context = {
        "target": "example.com",
        "risk_report": {
            "overall_score": 85.0,
            "grade": "B",
            "summary": {"total_findings": 3, "critical_count": 0, "high_count": 1, "medium_count": 2, "low_count": 0},
            "recommendations": ["Fix HSTS", "Add CSP"],
            "findings": [
                {"finding_id": "1", "title": "Missing HSTS", "severity": "high", "adjusted_cvss": 7.5,
                 "description": "desc", "affected_asset": "example.com", "remediation": "Add HSTS", "category": "header"}
            ]
        },
        "scanner_results": {"open_ports": []},
        "recon_data": {"dns_records": {}, "resolved_ips": [], "whois": {}, "subdomains": []}
    }
    report = ReportBuilder.build(scan_context)
    assert report.executive_summary.grade == "B"
    assert len(report.findings) == 1