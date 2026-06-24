import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from backend.modules.scanner.http_scanner import HTTPScanner, HttpFinding, HeaderIssue

@pytest.fixture
def http_scanner():
    return HTTPScanner(timeout=5.0)

@pytest.mark.asyncio
async def test_probe_https_success(http_scanner):
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.headers = {"Server": "Apache/2.4.41", "Content-Type": "text/html"}
    mock_response.cookies.jar = []
    with patch("httpx.AsyncClient.get", return_value=mock_response):
        finding = await http_scanner.probe("example.com", 443, True)
        assert finding.status_code == 200
        assert finding.server_software == "Apache"

def test_analyze_missing_headers(http_scanner):
    headers = {}
    issues = http_scanner.analyze_headers(headers)
    assert len(issues) == len(HTTPScanner.SECURITY_HEADERS)

def test_analyze_cookies(http_scanner):
    cookies = [{"name": "session", "secure": False, "httponly": False, "samesite": "None"}]
    issues = http_scanner.analyze_cookies(cookies)
    assert len(issues) == 3

def test_analyze_cors_wildcard(http_scanner):
    headers = {"Access-Control-Allow-Origin": "*"}
    issue = http_scanner.analyze_cors(headers)
    assert issue is not None
    assert issue.severity == "high"