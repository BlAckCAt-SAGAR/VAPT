import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from backend.modules.scanner.service_detector import ServiceDetector
from backend.modules.scanner.data_contracts import PortInfo

def test_guess_service():
    detector = ServiceDetector()
    assert detector._guess_service(22) == "SSH"
    assert detector._guess_service(80) == "HTTP"
    assert detector._guess_service(3306) == "MySQL"
    assert detector._guess_service(9999) == "unknown"

def test_parse_banner_ssh():
    detector = ServiceDetector()
    port_info = PortInfo(port=22)
    port_info.banner = "SSH-2.0-OpenSSH_7.9"
    detector._parse_banner(port_info, 22)
    assert port_info.service == "SSH"
    assert port_info.version == "OpenSSH_7.9"

def test_parse_banner_http():
    detector = ServiceDetector()
    port_info = PortInfo(port=80)
    port_info.banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
    detector._parse_banner(port_info, 80)
    assert port_info.service == "HTTP"
    assert "nginx/1.18.0" in port_info.version

def test_parse_banner_smtp():
    detector = ServiceDetector()
    port_info = PortInfo(port=25)
    port_info.banner = "220 smtp.example.com ESMTP Postfix"
    detector._parse_banner(port_info, 25)
    assert port_info.service == "SMTP"
    assert port_info.version == "Postfix"