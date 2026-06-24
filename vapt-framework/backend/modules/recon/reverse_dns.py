"""
Reverse DNS Lookup Module.

Performs reverse DNS lookups on IP addresses to discover
associated domain names, with concurrent execution support.
"""

import logging
import socket
import asyncio
from typing import List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import ipaddress

logger = logging.getLogger(__name__)


class ReverseDNSConfig:
    """Configuration for reverse DNS lookups."""
    
    def __init__(
        self,
        timeout: float = 5.0,
        max_retries: int = 2,
        max_workers: int = 10,
    ):
        """
        Initialize reverse DNS configuration.
        
        Args:
            timeout: Socket timeout in seconds
            max_retries: Maximum retry attempts
            max_workers: Maximum concurrent workers
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_workers = max_workers


class ReverseDNS:
    """
    Performs reverse DNS lookups on IP addresses.
    
    Resolves IP addresses to their associated domain names
    using PTR records, with concurrent execution and error handling.
    
    Attributes:
        config: ReverseDNSConfig
    """
    
    def __init__(self, config: Optional[ReverseDNSConfig] = None):
        """
        Initialize reverse DNS lookup.
        
        Args:
            config: Configuration for reverse DNS
        """
        self.config = config or ReverseDNSConfig()
    
    def _validate_ip(self, ip: str) -> str:
        """
        Validate and normalize IP address.
        
        Args:
            ip: IP address string
            
        Returns:
            Normalized IP address
            
        Raises:
            ValueError: If IP is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            return str(ip_obj)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip}") from e
    
    def _perform_single_lookup(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup on a single IP.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Hostname or None if lookup fails
        """
        for attempt in range(self.config.max_retries + 1):
            try:
                # Set socket timeout
                original_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.config.timeout)
                
                try:
                    hostname, aliases, addresses = socket.gethostbyaddr(ip)
                    logger.debug(f"Reverse DNS for {ip}: {hostname}")
                    return hostname.lower()
                finally:
                    socket.setdefaulttimeout(original_timeout)
                    
            except socket.herror as e:
                # No PTR record found
                if attempt == self.config.max_retries:
                    logger.debug(f"No PTR record for {ip}: {e}")
                return None
                
            except socket.gaierror as e:
                logger.warning(f"Address error for {ip} (attempt {attempt + 1}): {e}")
                if attempt < self.config.max_retries:
                    import time
                    time.sleep(1 * (attempt + 1))
                    
            except socket.timeout:
                logger.warning(f"Timeout for reverse DNS lookup of {ip} (attempt {attempt + 1})")
                if attempt < self.config.max_retries:
                    import time
                    time.sleep(1 * (attempt + 1))
                    
            except Exception as e:
                logger.error(f"Unexpected error in reverse DNS lookup for {ip}: {e}")
                return None
        
        return None
    
    async def _lookup_async(self, ip: str) -> Optional[str]:
        """
        Async wrapper for reverse DNS lookup.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Hostname or None
        """
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            return await loop.run_in_executor(
                executor,
                self._perform_single_lookup,
                ip
            )
    
    async def lookup(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup on a single IP.
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None
            
        Raises:
            ValueError: If IP is invalid
        """
        try:
            ip = self._validate_ip(ip)
        except ValueError as e:
            logger.error(f"IP validation failed: {e}")
            raise
        
        logger.info(f"Performing reverse DNS lookup for {ip}")
        result = await self._lookup_async(ip)
        
        if result:
            logger.info(f"Reverse DNS resolved {ip} to {result}")
        else:
            logger.info(f"No reverse DNS record found for {ip}")
        
        return result
    
    async def lookup_multiple(self, ips: List[str]) -> List[Optional[str]]:
        """
        Perform reverse DNS lookups on multiple IPs concurrently.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            List of hostnames (None for failed lookups)
        """
        # Validate and deduplicate IPs
        valid_ips: Set[str] = set()
        for ip in ips:
            try:
                valid_ips.add(self._validate_ip(ip))
            except ValueError as e:
                logger.warning(f"Skipping invalid IP: {e}")
        
        if not valid_ips:
            logger.warning("No valid IPs to perform reverse DNS lookup")
            return []
        
        logger.info(f"Performing reverse DNS lookup on {len(valid_ips)} IPs")
        
        # Create tasks for concurrent execution
        semaphore = asyncio.Semaphore(self.config.max_workers)
        
        async def bounded_lookup(ip: str) -> Optional[str]:
            async with semaphore:
                return await self._lookup_async(ip)
        
        tasks = [bounded_lookup(ip) for ip in valid_ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results, converting exceptions to None
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Reverse DNS lookup failed: {result}")
                processed_results.append(None)
            else:
                processed_results.append(result)
        
        successful = sum(1 for r in processed_results if r is not None)
        logger.info(f"Reverse DNS complete: {successful}/{len(valid_ips)} successful")
        
        return processed_results