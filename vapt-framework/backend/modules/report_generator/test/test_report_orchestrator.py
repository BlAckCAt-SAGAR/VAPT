import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.report_generator.report_orchestrator import ReportOrchestrator

def test_generate_report():
    scan_context = {
        "target": "example.com",
        "risk_report": {
            "overall_score": 90.0,
            "grade": "A",
            "summary": {"total_findings": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0},
            "recommendations": ["Keep up the good work"],
            "findings": []
        },
        "scanner_results": {"open_ports": []},
        "recon_data": {"dns_records": {}, "resolved_ips": [], "whois": {}, "subdomains": []}
    }
    orchestrator = ReportOrchestrator(output_dir="test_reports")
    result = orchestrator.generate(scan_context)
    assert "report" in result
    assert result["report"]["generated_file"] is not None