import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.modules.scanner.scan_orchestrator import ScanOrchestrator, ScanOrchestratorConfig
from backend.modules.scanner.data_contracts import ScanResult, HttpFinding

@pytest.fixture
def scan_context():
    return {
        "target": "example.com",
        "target_type": "domain",
        "recon_data": {"resolved_ips": ["93.184.216.34"]},
        "modules_executed": ["recon"]
    }

@pytest.mark.asyncio
async def test_run_domain(scan_context):
    config = ScanOrchestratorConfig()
    orchestrator = ScanOrchestrator(config)
    
    # Mock sub-components
    mock_finding = MagicMock(spec=HttpFinding)
    mock_finding.status_code = 200
    mock_finding.server_software = "Apache"
    mock_finding.server_version = "2.4.41"
    mock_finding.header_issues = []
    mock_finding.headers = {}
    mock_finding.cookies = []
    
    orchestrator.http_scanner.probe = AsyncMock(return_value=mock_finding)
    orchestrator.port_scanner.scan = AsyncMock(return_value=[80, 443])
    orchestrator.service_detector.detect = AsyncMock(return_value=MagicMock())
    orchestrator.vuln_matcher.match = MagicMock(return_value=[])
    
    result = await orchestrator.run(scan_context)
    assert "scanner_results" in result
    assert result["scanner_results"]["target"] == "example.com"
    assert "http_scanner" in result["modules_executed"]
    assert "port_scanner" in result["modules_executed"]

@pytest.mark.asyncio
async def test_run_ip_target_no_web():
    scan_context = {
        "target": "192.168.1.1",
        "target_type": "ip",
        "recon_data": {"resolved_ips": ["192.168.1.1"]},
        "modules_executed": ["recon"]
    }
    config = ScanOrchestratorConfig()
    orchestrator = ScanOrchestrator(config)
    # HTTP probe fails
    orchestrator.http_scanner.probe = AsyncMock(return_value=MagicMock(status_code=None))
    orchestrator.port_scanner.scan = AsyncMock(return_value=[22])
    orchestrator.service_detector.detect = AsyncMock(return_value=MagicMock())
    orchestrator.vuln_matcher.match = MagicMock(return_value=[])
    
    result = await orchestrator.run(scan_context)
    assert "port_scanner" in result["modules_executed"]
    assert result["scanner_results"]["http_finding"] is not None