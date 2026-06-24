"""
Unit tests for Reconnaissance Orchestrator.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock

from backend.modules.recon.recon_orchestrator import ReconOrchestrator, ReconOrchestratorConfig
from backend.modules.recon.data_normalizer import ReconResult


@pytest.fixture
def orchestrator():
    """Create orchestrator instance for testing."""
    config = ReconOrchestratorConfig(
        enable_dns=False,
        enable_whois=False,
        enable_subdomain=False,
        enable_reverse_dns=False,
    )
    return ReconOrchestrator(config)


class TestReconOrchestrator:
    """Test cases for reconnaissance orchestrator."""
    
    @pytest.mark.asyncio
    async def test_empty_target_error(self, orchestrator):
        """Test that empty target raises error."""
        with pytest.raises(ValueError):
            await orchestrator.run("")
    
    @pytest.mark.asyncio
    async def test_empty_target_whitespace(self, orchestrator):
        """Test that whitespace-only target raises error."""
        with pytest.raises(ValueError):
            await orchestrator.run("   ")
    
    def test_determine_target_type(self):
        """Test target type determination."""
        assert ReconResult.determine_target_type("example.com") == "domain"
        assert ReconResult.determine_target_type("192.168.1.1") == "ip"
        assert ReconResult.determine_target_type("2001:db8::1") == "ip"
        assert ReconResult.determine_target_type("sub.example.com") == "domain"
    
    @pytest.mark.asyncio
    async def test_domain_target_type(self, orchestrator):
        """Test domain target type detection with mocked modules."""
        # Mock the DNS enumerator
        orchestrator.dns_enumerator = MagicMock()
        orchestrator.dns_enumerator.enumerate = AsyncMock(return_value={
            "A": ["1.2.3.4"],
            "MX": ["mail.example.com"]
        })
        orchestrator.dns_enumerator.get_resolved_ips = MagicMock(return_value=["1.2.3.4"])
        
        # Mock the WHOIS lookup
        orchestrator.whois_lookup = MagicMock()
        orchestrator.whois_lookup.lookup_to_dict = MagicMock(return_value={
            "registrar": "Test Registrar",
            "name_servers": ["ns1.example.com"]
        })
        
        # Mock the subdomain finder
        orchestrator.subdomain_finder = MagicMock()
        orchestrator.subdomain_finder.discover = AsyncMock(return_value=[
            "www.example.com",
            "api.example.com"
        ])
        orchestrator.subdomain_finder.close = AsyncMock()
        
        # Enable modules
        orchestrator.config.enable_dns = True
        orchestrator.config.enable_whois = True
        orchestrator.config.enable_subdomain = True
        
        # Run orchestrator
        result = await orchestrator.run("example.com")
        
        # Verify results
        assert result["target"] == "example.com"
        assert result["target_type"] == "domain"
        assert "dns" in result["modules_executed"]
        assert "whois" in result["modules_executed"]
        assert "subdomain" in result["modules_executed"]
        assert len(result["errors"]) == 0
        assert result["recon_data"]["resolved_ips"] == ["1.2.3.4"]
        assert len(result["recon_data"]["subdomains"]) == 2
    
    @pytest.mark.asyncio
    async def test_run_with_module_errors(self, orchestrator):
        """Test that module errors are captured but don't crash the orchestrator."""
        # Mock DNS to raise an error
        orchestrator.dns_enumerator = MagicMock()
        orchestrator.dns_enumerator.enumerate = AsyncMock(side_effect=Exception("DNS error"))
        
        # Mock WHOIS to work
        orchestrator.whois_lookup = MagicMock()
        orchestrator.whois_lookup.lookup_to_dict = MagicMock(return_value={
            "registrar": "Test"
        })
        
        # Mock subdomain finder
        orchestrator.subdomain_finder = MagicMock()
        orchestrator.subdomain_finder.discover = AsyncMock(return_value=[])
        orchestrator.subdomain_finder.close = AsyncMock()
        
        orchestrator.config.enable_dns = True
        orchestrator.config.enable_whois = True
        orchestrator.config.enable_subdomain = True
        
        result = await orchestrator.run("example.com")
        
        # Should complete despite DNS error
        assert result["target"] == "example.com"
        assert "whois" in result["modules_executed"]
        assert len(result["errors"]) > 0
        assert any("DNS" in error for error in result["errors"])
    
    def test_recon_result_validation(self):
        """Test ReconResult validation."""
        # Valid result
        result = ReconResult(target="example.com", target_type="domain")
        assert result.validate() is True
        
        # Invalid target type
        result2 = ReconResult(target="example.com", target_type="invalid")
        assert result2.validate() is False
        
        # Empty target
        result3 = ReconResult(target="", target_type="domain")
        assert result3.validate() is False
    
    def test_recon_result_json(self):
        """Test JSON serialization."""
        result = ReconResult(target="test.com", target_type="domain")
        result.dns_records = {"A": ["1.2.3.4"]}
        result.resolved_ips = ["1.2.3.4"]
        result.modules_executed = ["dns"]
        
        json_str = result.to_json()
        assert isinstance(json_str, str)
        assert "test.com" in json_str
        assert "1.2.3.4" in json_str
    
    def test_normalize_domain(self):
        """Test domain normalization."""
        assert ReconResult.normalize_domain("Example.COM") == "example.com"
        assert ReconResult.normalize_domain("test.com.") == "test.com"
        assert ReconResult.normalize_domain("  TEST.com  ") == "test.com"