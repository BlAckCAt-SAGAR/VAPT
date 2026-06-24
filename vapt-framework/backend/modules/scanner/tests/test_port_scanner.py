import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.scanner.port_scanner import PortScanner

def test_top_20_ports():
    assert 80 in PortScanner.TOP_20
    assert 443 in PortScanner.TOP_20
    assert 22 in PortScanner.TOP_20

def test_top_100_ports():
    assert len(PortScanner.TOP_100) >= 100
    assert 80 in PortScanner.TOP_100
    assert 6379 in PortScanner.TOP_100  # Redis

@pytest.mark.asyncio
async def test_scan_no_ports():
    scanner = PortScanner()
    ports = await scanner.scan("127.0.0.1", [])
    assert ports == []