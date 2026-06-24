"""
Unit tests for DNS Enumerator module.
Run from project root: pytest backend/modules/recon/tests/
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from unittest.mock import patch
import dns.resolver
import dns.exception

# Use absolute imports
from backend.modules.recon.dns_enumerator import DNSEnumerator, DNSEnumeratorConfig
from backend.modules.recon.data_normalizer import DNSRecord


@pytest.fixture
def enumerator():
    """Create DNS enumerator instance for testing."""
    config = DNSEnumeratorConfig(
        record_types=("A", "MX"),
        timeout=2.0,
        lifetime=5.0,
        max_retries=1
    )
    return DNSEnumerator(config)


class TestDNSEnumerator:
    """Test cases for DNS enumerator."""
    
    def test_sanitize_domain_valid(self, enumerator):
        """Test domain sanitization with valid input."""
        result = enumerator._sanitize_domain("example.com")
        assert result == "example.com"
    
    def test_sanitize_domain_invalid(self, enumerator):
        """Test domain sanitization with invalid input."""
        import pytest
        with pytest.raises(ValueError):
            enumerator._sanitize_domain("example.com; rm -rf /")
    
    def test_get_resolved_ips(self, enumerator):
        """Test extracting resolved IPs from DNS data."""
        dns_data = {
            "A": ["192.0.2.1", "192.0.2.2"],
            "AAAA": ["2001:db8::1"],
            "MX": ["mail.example.com"]
        }
        
        ips = enumerator.get_resolved_ips(dns_data)
        assert len(ips) == 3
        assert "192.0.2.1" in ips
        assert "2001:db8::1" in ips

    def test_empty_dns_data(self, enumerator):
        """Test with empty DNS data."""
        ips = enumerator.get_resolved_ips({})
        assert ips == []