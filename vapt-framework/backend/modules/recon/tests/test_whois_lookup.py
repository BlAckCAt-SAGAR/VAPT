"""
Unit tests for WHOIS Lookup module.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from unittest.mock import patch, MagicMock

from backend.modules.recon.whois_lookup import WhoisLookup, WhoisCache
from backend.modules.recon.data_normalizer import WhoisInfo


@pytest.fixture
def whois_lookup():
    """Create WHOIS lookup instance."""
    return WhoisLookup(cache_ttl=5, rate_limit_delay=0.1)


class TestWhoisCache:
    """Test cases for WHOIS cache."""
    
    def test_cache_set_and_get(self):
        """Test basic cache operations."""
        cache = WhoisCache(ttl_seconds=5)
        info = WhoisInfo(registrar="Test Registrar")
        cache.set("example.com", info)
        
        cached = cache.get("example.com")
        assert cached is not None
        assert cached.registrar == "Test Registrar"
    
    def test_cache_miss(self):
        """Test cache miss."""
        cache = WhoisCache(ttl_seconds=5)
        result = cache.get("nonexistent.com")
        assert result is None


class TestWhoisLookup:
    """Test cases for WHOIS lookup."""
    
    def test_sanitize_domain(self, whois_lookup):
        """Test domain sanitization."""
        result = whois_lookup._sanitize_domain("Example.COM.")
        assert result == "example.com"
    
    @patch('whois.whois')
    def test_lookup_success(self, mock_whois, whois_lookup):
        """Test successful WHOIS lookup."""
        mock_response = MagicMock()
        mock_response.registrar = "Test Registrar"
        mock_response.name_servers = ["ns1.example.com"]
        mock_whois.return_value = mock_response
        
        result = whois_lookup.lookup("example.com")
        assert result is not None
        assert result.registrar == "Test Registrar"
    
    @patch('whois.whois')
    def test_lookup_failure(self, mock_whois, whois_lookup):
        """Test WHOIS lookup failure."""
        mock_whois.side_effect = Exception("Connection error")
        
        result = whois_lookup.lookup("example.com")
        assert result is None