"""
DNS Enumerator Module.

Performs comprehensive DNS record enumeration for a given domain,
querying multiple record types concurrently with proper error handling.
"""

import asyncio
import logging
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
import dns.resolver
import dns.exception
import dns.rdatatype
from concurrent.futures import ThreadPoolExecutor
import time

from .data_normalizer import DNSRecord

logger = logging.getLogger(__name__)


@dataclass
class DNSEnumeratorConfig:
    """Configuration for DNS enumeration."""
    
    record_types: Tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
    timeout: float = 5.0
    lifetime: float = 10.0
    max_retries: int = 2
    nameservers: Optional[List[str]] = None
    max_workers: int = 10
    enable_dnssec: bool = False


class DNSEnumerator:
    """
    Enumerates DNS records for a target domain.
    
    Handles various DNS record types with concurrent resolution,
    proper timeout handling, and graceful error recovery.
    
    Attributes:
        config: DNSEnumeratorConfig instance
        resolver: Configured dns.resolver.Resolver
    """
    
    def __init__(self, config: Optional[DNSEnumeratorConfig] = None):
        """
        Initialize DNS Enumerator.
        
        Args:
            config: Configuration for DNS enumeration
        """
        self.config = config or DNSEnumeratorConfig()
        self.resolver = dns.resolver.Resolver()
        self._setup_resolver()
    
    def _setup_resolver(self) -> None:
        """Configure the DNS resolver with specified settings."""
        self.resolver.timeout = self.config.timeout
        self.resolver.lifetime = self.config.lifetime
        
        if self.config.nameservers:
            self.resolver.nameservers = self.config.nameservers
        
        if self.config.enable_dnssec:
            self.resolver.use_edns(edns=True, ednsflags=dns.flags.DO)
    
    def _sanitize_domain(self, domain: str) -> str:
        """
        Sanitize domain input to prevent injection.
        
        Args:
            domain: Raw domain input
            
        Returns:
            Sanitized domain string
            
        Raises:
            ValueError: If domain contains invalid characters
        """
        # Remove any whitespace
        domain = domain.strip()
        
        # Validate domain characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
        if not all(c in allowed_chars for c in domain):
            raise ValueError(f"Domain contains invalid characters: {domain}")
        
        # Ensure it doesn't start or end with a hyphen
        if domain.startswith('-') or domain.endswith('-'):
            raise ValueError(f"Domain cannot start or end with a hyphen: {domain}")
        
        return domain.lower()
    
    def _query_record_type(self, domain: str, record_type: str) -> List[DNSRecord]:
        """
        Query a specific DNS record type.
        
        Args:
            domain: Target domain
            record_type: DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            List of DNSRecord objects
        """
        records = []
        
        for attempt in range(self.config.max_retries + 1):
            try:
                answers = self.resolver.resolve(domain, record_type)
                
                for answer in answers:
                    record_value = str(answer)
                    ttl = getattr(answer, 'ttl', None)
                    priority = None
                    
                    # Extract priority for MX records
                    if record_type == 'MX':
                        priority = getattr(answer, 'preference', None)
                    
                    records.append(DNSRecord(
                        record_type=record_type,
                        value=record_value,
                        ttl=ttl,
                        priority=priority
                    ))
                
                break  # Success, exit retry loop
                
            except dns.resolver.NXDOMAIN:
                logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
                break
                
            except dns.resolver.NoAnswer:
                logger.debug(f"No {record_type} records found for {domain}")
                break
                
            except dns.resolver.NoNameservers:
                logger.warning(f"No nameservers available for {domain} (attempt {attempt + 1})")
                if attempt < self.config.max_retries:
                    time.sleep(1 * (attempt + 1))  # Exponential backoff
                    
            except dns.exception.Timeout:
                logger.warning(f"Timeout querying {record_type} for {domain} (attempt {attempt + 1})")
                if attempt < self.config.max_retries:
                    time.sleep(1 * (attempt + 1))
                    
            except dns.exception.DNSException as e:
                logger.error(f"DNS error querying {record_type} for {domain}: {e}")
                break
                
            except Exception as e:
                logger.error(f"Unexpected error querying {record_type} for {domain}: {e}")
                break
        
        return records
    
    async def _query_record_async(self, domain: str, record_type: str) -> List[DNSRecord]:
        """
        Async wrapper for DNS record query.
        
        Args:
            domain: Target domain
            record_type: DNS record type
            
        Returns:
            List of DNSRecord objects
        """
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            return await loop.run_in_executor(
                executor, 
                self._query_record_type, 
                domain, 
                record_type
            )
    
    async def enumerate(self, domain: str) -> Dict[str, List[str]]:
        """
        Enumerate all configured DNS record types for a domain.
        
        Args:
            domain: Target domain to enumerate
            
        Returns:
            Dictionary mapping record types to lists of record values
            
        Raises:
            ValueError: If domain validation fails
        """
        # Sanitize input
        try:
            domain = self._sanitize_domain(domain)
        except ValueError as e:
            logger.error(f"Domain validation failed: {e}")
            raise
        
        logger.info(f"Starting DNS enumeration for {domain}")
        
        # Create tasks for all record types
        tasks = [
            self._query_record_async(domain, record_type)
            for record_type in self.config.record_types
        ]
        
        # Execute all queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        dns_data: Dict[str, List[str]] = {}
        
        for record_type, result in zip(self.config.record_types, results):
            if isinstance(result, Exception):
                logger.error(f"Failed to query {record_type} for {domain}: {result}")
                continue
            
            if result:
                # Extract values and deduplicate
                values = list(set(record.value for record in result))
                dns_data[record_type] = values
        
        logger.info(f"DNS enumeration complete for {domain}: found {len(dns_data)} record types")
        return dns_data
    
    def get_resolved_ips(self, dns_data: Dict[str, List[str]]) -> List[str]:
        """
        Extract resolved IPs from A and AAAA records.
        
        Args:
            dns_data: DNS enumeration data
            
        Returns:
            List of IP addresses
        """
        ips = []
        for record_type in ['A', 'AAAA']:
            if record_type in dns_data:
                ips.extend(dns_data[record_type])
        return ips