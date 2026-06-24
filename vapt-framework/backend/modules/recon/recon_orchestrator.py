"""
Reconnaissance Module Orchestrator.

Main entry point for the reconnaissance phase of the VAPT framework.
Coordinates all sub-modules, manages the scan context, and provides
progress reporting.
"""

import logging
import asyncio
import time
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime

from .dns_enumerator import DNSEnumerator, DNSEnumeratorConfig
from .whois_lookup import WhoisLookup
from .subdomain_finder import SubdomainFinder, SubdomainFinderConfig
from .reverse_dns import ReverseDNS, ReverseDNSConfig
from .data_normalizer import ReconResult

logger = logging.getLogger(__name__)


class ReconOrchestratorConfig:
    """Configuration for the reconnaissance orchestrator."""
    
    def __init__(
        self,
        enable_dns: bool = True,
        enable_whois: bool = True,
        enable_subdomain: bool = True,
        enable_reverse_dns: bool = True,
        dns_config: Optional[DNSEnumeratorConfig] = None,
        whois_cache_ttl: int = 300,
        subdomain_config: Optional[SubdomainFinderConfig] = None,
        reverse_dns_config: Optional[ReverseDNSConfig] = None,
        max_concurrent_modules: int = 3,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ):
        """
        Initialize orchestrator configuration.
        
        Args:
            enable_dns: Enable DNS enumeration
            enable_whois: Enable WHOIS lookup
            enable_subdomain: Enable subdomain discovery
            enable_reverse_dns: Enable reverse DNS
            dns_config: DNS enumerator configuration
            whois_cache_ttl: WHOIS cache TTL in seconds
            subdomain_config: Subdomain finder configuration
            reverse_dns_config: Reverse DNS configuration
            max_concurrent_modules: Maximum modules to run concurrently
            progress_callback: Optional callback for progress reporting
        """
        self.enable_dns = enable_dns
        self.enable_whois = enable_whois
        self.enable_subdomain = enable_subdomain
        self.enable_reverse_dns = enable_reverse_dns
        self.dns_config = dns_config or DNSEnumeratorConfig()
        self.whois_cache_ttl = whois_cache_ttl
        self.subdomain_config = subdomain_config or SubdomainFinderConfig()
        self.reverse_dns_config = reverse_dns_config or ReverseDNSConfig()
        self.max_concurrent_modules = max_concurrent_modules
        self.progress_callback = progress_callback


class ReconOrchestrator:
    """
    Orchestrates all reconnaissance sub-modules.
    
    Accepts a target domain or IP, executes all enabled reconnaissance
    modules, and returns a standardized ReconResult containing all
    gathered information.
    
    Attributes:
        config: ReconOrchestratorConfig
        dns_enumerator: DNSEnumerator instance
        whois_lookup: WhoisLookup instance
        subdomain_finder: SubdomainFinder instance
        reverse_dns: ReverseDNS instance
    """
    
    def __init__(self, config: Optional[ReconOrchestratorConfig] = None):
        """
        Initialize the reconnaissance orchestrator.
        
        Args:
            config: Orchestrator configuration
        """
        self.config = config or ReconOrchestratorConfig()
        
        # Initialize sub-modules based on configuration
        self.dns_enumerator = DNSEnumerator(self.config.dns_config) if self.config.enable_dns else None
        self.whois_lookup = WhoisLookup(cache_ttl=self.config.whois_cache_ttl) if self.config.enable_whois else None
        self.subdomain_finder = SubdomainFinder(self.config.subdomain_config) if self.config.enable_subdomain else None
        self.reverse_dns = ReverseDNS(self.config.reverse_dns_config) if self.config.enable_reverse_dns else None
    
    def _report_progress(self, stage: str, percentage: float) -> None:
        """
        Report progress to callback if configured.
        
        Args:
            stage: Current stage description
            percentage: Progress percentage (0-100)
        """
        if self.config.progress_callback:
            try:
                self.config.progress_callback(stage, percentage)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
        
        logger.info(f"Progress: {stage} ({percentage:.1f}%)")
    
    async def _run_dns_enumeration(self, target: str, result: ReconResult) -> None:
        """
        Run DNS enumeration module.
        
        Args:
            target: Target domain
            result: ReconResult to populate
        """
        try:
            self._report_progress("Starting DNS enumeration", 10.0)
            
            dns_data = await self.dns_enumerator.enumerate(target)
            
            if dns_data:
                result.dns_records = dns_data
                result.resolved_ips = self.dns_enumerator.get_resolved_ips(dns_data)
                result.modules_executed.append("dns")
                logger.info(f"DNS enumeration found {len(dns_data)} record types")
            else:
                logger.warning("DNS enumeration returned no data")
            
            self._report_progress("DNS enumeration complete", 30.0)
            
        except Exception as e:
            error_msg = f"DNS enumeration failed: {str(e)}"
            logger.error(error_msg)
            result.add_error(error_msg)
    
    async def _run_whois_lookup(self, target: str, result: ReconResult) -> None:
        """
        Run WHOIS lookup module.
        
        Args:
            target: Target domain
            result: ReconResult to populate
        """
        try:
            self._report_progress("Starting WHOIS lookup", 35.0)
            
            whois_data = self.whois_lookup.lookup_to_dict(target)
            
            if whois_data:
                result.whois = whois_data
                result.modules_executed.append("whois")
                logger.info("WHOIS lookup successful")
            else:
                logger.warning("WHOIS lookup returned no data")
            
            self._report_progress("WHOIS lookup complete", 50.0)
            
        except Exception as e:
            error_msg = f"WHOIS lookup failed: {str(e)}"
            logger.error(error_msg)
            result.add_error(error_msg)
    
    async def _run_subdomain_discovery(self, target: str, result: ReconResult) -> None:
        """
        Run subdomain discovery module.
        
        Args:
            target: Target domain
            result: ReconResult to populate
        """
        try:
            self._report_progress("Starting subdomain discovery", 55.0)
            
            subdomains = await self.subdomain_finder.discover(target)
            
            if subdomains:
                result.subdomains = subdomains
                result.modules_executed.append("subdomain")
                logger.info(f"Subdomain discovery found {len(subdomains)} subdomains")
            else:
                logger.warning("Subdomain discovery returned no data")
            
            self._report_progress("Subdomain discovery complete", 80.0)
            
        except Exception as e:
            error_msg = f"Subdomain discovery failed: {str(e)}"
            logger.error(error_msg)
            result.add_error(error_msg)
    
    async def _run_reverse_dns(self, target: str, result: ReconResult) -> None:
        """
        Run reverse DNS module for IP targets.
        
        Args:
            target: Target IP address
            result: ReconResult to populate
        """
        try:
            self._report_progress("Starting reverse DNS", 30.0)
            
            reverse_result = await self.reverse_dns.lookup(target)
            
            if reverse_result:
                result.reverse_dns = [reverse_result]
                result.modules_executed.append("reverse_dns")
                logger.info(f"Reverse DNS resolved {target} to {reverse_result}")
            else:
                logger.info(f"No reverse DNS record for {target}")
                result.modules_executed.append("reverse_dns")
            
            self._report_progress("Reverse DNS complete", 50.0)
            
        except Exception as e:
            error_msg = f"Reverse DNS lookup failed: {str(e)}"
            logger.error(error_msg)
            result.add_error(error_msg)
    
    async def run(self, target: str) -> Dict[str, Any]:
        """
        Execute all enabled reconnaissance modules.
        
        This is the main entry point for the reconnaissance phase.
        Determines target type, executes appropriate modules, and
        returns the standardized scan_context dictionary.
        
        Args:
            target: Domain name or IP address to recon
            
        Returns:
            Standardized scan_context dictionary with all recon data
            
        Raises:
            ValueError: If target is empty or invalid
        """
        start_time = time.time()
        
        # Validate input
        if not target or not target.strip():
            raise ValueError("Target cannot be empty")
        
        target = target.strip()
        logger.info(f"Starting reconnaissance for target: {target}")
        self._report_progress("Initializing reconnaissance", 0.0)
        
        # Determine target type and create result container
        target_type = ReconResult.determine_target_type(target)
        result = ReconResult(
            target=target,
            target_type=target_type
        )
        
        try:
            if target_type == "domain":
                # Domain target: Run DNS, WHOIS, and Subdomain discovery
                domain = ReconResult.normalize_domain(target)
                tasks = []
                
                if self.config.enable_dns and self.dns_enumerator:
                    tasks.append(self._run_dns_enumeration(domain, result))
                
                if self.config.enable_whois and self.whois_lookup:
                    tasks.append(self._run_whois_lookup(domain, result))
                
                if self.config.enable_subdomain and self.subdomain_finder:
                    tasks.append(self._run_subdomain_discovery(domain, result))
                
                if tasks:
                    await asyncio.gather(*tasks)
                
            elif target_type == "ip":
                # IP target: Run reverse DNS and limited WHOIS
                tasks = []
                
                if self.config.enable_reverse_dns and self.reverse_dns:
                    tasks.append(self._run_reverse_dns(target, result))
                
                # For IPs, we can also try to get DNS info
                if self.config.enable_dns and self.dns_enumerator:
                    # Try to resolve the IP to a hostname first
                    try:
                        reverse_result = await self.reverse_dns.lookup(target) if self.reverse_dns else None
                        if reverse_result:
                            tasks.append(self._run_dns_enumeration(reverse_result, result))
                    except Exception:
                        pass
                
                if tasks:
                    await asyncio.gather(*tasks)
            
            # Validate result
            result.validate()
            
            # Calculate execution time
            result.execution_time_seconds = time.time() - start_time
            
            self._report_progress(
                f"Reconnaissance complete ({len(result.modules_executed)} modules executed)",
                100.0
            )
            
            logger.info(
                f"Reconnaissance completed in {result.execution_time_seconds:.2f}s "
                f"with {len(result.errors)} errors"
            )
            
        except Exception as e:
            error_msg = f"Reconnaissance orchestration failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            result.add_error(error_msg)
            result.execution_time_seconds = time.time() - start_time
        
        finally:
            # Cleanup
            if self.subdomain_finder:
                await self.subdomain_finder.close()
        
        return result.to_dict()
    
    def run_sync(self, target: str) -> Dict[str, Any]:
        """
        Synchronous wrapper for the run method.
        
        Args:
            target: Domain name or IP address
            
        Returns:
            Standardized scan_context dictionary
        """
        return asyncio.run(self.run(target))