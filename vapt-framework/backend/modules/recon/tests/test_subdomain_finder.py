"""
Unit tests for Subdomain Finder module.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest

from backend.modules.recon.subdomain_finder import SubdomainFinder, SubdomainFinderConfig


@pytest.fixture
def subdomain_finder():
    """Create subdomain finder instance."""
    config = SubdomainFinderConfig(
        timeout=5.0,
        max_retries=1,
        use_crtsh=True,
        use_certspotter=False,
        use_hackertarget=False,
    )
    return SubdomainFinder(config)


class TestSubdomainFinder:
    """Test cases for subdomain finder."""
    
    def test_clean_subdomain_valid(self, subdomain_finder):
        """Test cleaning valid subdomains."""
        result = subdomain_finder._clean_subdomain("www.example.com", "example.com")
        assert result == "www.example.com"  # This should now pass
        
        result = subdomain_finder._clean_subdomain("api.example.com", "example.com")
        assert result == "api.example.com"
    
    def test_clean_subdomain_wildcard(self, subdomain_finder):
        """Test cleaning wildcard entries."""
        result = subdomain_finder._clean_subdomain("*.example.com", "example.com")
        assert result is None
    
    def test_clean_subdomain_wrong_domain(self, subdomain_finder):
        """Test cleaning subdomain for wrong domain."""
        result = subdomain_finder._clean_subdomain("test.other.com", "example.com")
        assert result is None
    
    def test_clean_subdomain_ip(self, subdomain_finder):
        """Test cleaning IP addresses."""
        result = subdomain_finder._clean_subdomain("192.168.1.1", "example.com")
        assert result is None