"""
Subdomain Discovery Module.

Discovers subdomains using Certificate Transparency logs (crt.sh)
and other passive sources. Implements async HTTP requests with
rate limiting and fallback mechanisms.
"""

import logging
from typing import List, Set, Optional, Dict, Any
import asyncio
import httpx
import json
import re
from urllib.parse import urlencode

from .data_normalizer import SubdomainInfo, ReconResult

logger = logging.getLogger(__name__)


class SubdomainFinderConfig:
    """Configuration for subdomain discovery."""
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        use_crtsh: bool = True,
        use_certspotter: bool = False,
        use_hackertarget: bool = False,
        max_subdomains: int = 1000,
        rate_limit_delay: float = 2.0,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.use_crtsh = use_crtsh
        self.use_certspotter = use_certspotter
        self.use_hackertarget = use_hackertarget
        self.max_subdomains = max_subdomains
        self.rate_limit_delay = rate_limit_delay


class SubdomainFinder:
    """
    Discovers subdomains using passive reconnaissance techniques.
    
    Primarily uses Certificate Transparency logs via crt.sh,
    with fallback to alternative sources if the primary fails.
    """
    
    # Only exclude wildcard entries, keep www and mail
    EXCLUDED_PATTERNS = [
        r'\*\.',  # Wildcard entries
    ]
    
    def __init__(self, config: Optional[SubdomainFinderConfig] = None):
        self.config = config or SubdomainFinderConfig()
        self.client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout),
                follow_redirects=True,
                headers={
                    "User-Agent": "VAPT-Framework/1.0 (Security Research)",
                    "Accept": "application/json",
                }
            )
        return self.client
    
    def _clean_subdomain(self, subdomain: str, domain: str) -> Optional[str]:
        """
        Clean and validate a subdomain entry.
        """
        # Remove whitespace and convert to lowercase
        subdomain = subdomain.strip().lower()
        
        # Remove trailing dots
        subdomain = subdomain.rstrip('.')
        
        # Skip if it doesn't contain the parent domain
        if not subdomain.endswith(f".{domain}") and subdomain != domain:
            return None
        
        # Skip if it's an IP address
        if ReconResult.is_ip_address(subdomain):
            return None
        
        # Skip wildcard entries
        if subdomain.startswith('*.'):
            return None
        
        # Skip entries with invalid characters
        if not re.match(r'^[a-zA-Z0-9\.\-_]+$', subdomain):
            return None
        
        return subdomain
    
    async def _query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency API."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        for attempt in range(self.config.max_retries):
            try:
                client = await self._get_client()
                logger.info(f"Querying crt.sh for {domain} (attempt {attempt + 1})")
                
                response = await client.get(url)
                response.raise_for_status()
                
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        cleaned = self._clean_subdomain(name, domain)
                        if cleaned:
                            subdomains.add(cleaned)
                
                logger.info(f"crt.sh returned {len(subdomains)} unique subdomains for {domain}")
                break
                
            except httpx.HTTPStatusError as e:
                logger.warning(f"HTTP error from crt.sh (attempt {attempt + 1}): {e}")
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.rate_limit_delay * (attempt + 1))
                    
            except httpx.TimeoutException:
                logger.warning(f"Timeout from crt.sh (attempt {attempt + 1})")
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.rate_limit_delay * (attempt + 1))
                    
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse crt.sh response: {e}")
                break
                
            except Exception as e:
                logger.error(f"Unexpected error querying crt.sh: {e}")
                break
        
        return subdomains
    
    async def _query_certspotter(self, domain: str) -> Set[str]:
        """Query CertSpotter API as fallback."""
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        
        try:
            client = await self._get_client()
            logger.info(f"Querying CertSpotter for {domain}")
            
            response = await client.get(url)
            response.raise_for_status()
            
            data = response.json()
            
            for entry in data:
                dns_names = entry.get('dns_names', [])
                for name in dns_names:
                    cleaned = self._clean_subdomain(name, domain)
                    if cleaned:
                        subdomains.add(cleaned)
            
            logger.info(f"CertSpotter returned {len(subdomains)} subdomains for {domain}")
            
        except Exception as e:
            logger.warning(f"CertSpotter query failed for {domain}: {e}")
        
        return subdomains
    
    async def _query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API as additional fallback."""
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        try:
            client = await self._get_client()
            logger.info(f"Querying HackerTarget for {domain}")
            
            response = await client.get(url)
            response.raise_for_status()
            
            for line in response.text.split('\n'):
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                    cleaned = self._clean_subdomain(subdomain, domain)
                    if cleaned:
                        subdomains.add(cleaned)
            
            logger.info(f"HackerTarget returned {len(subdomains)} subdomains for {domain}")
            
        except Exception as e:
            logger.warning(f"HackerTarget query failed for {domain}: {e}")
        
        return subdomains
    
    async def discover(self, domain: str) -> List[str]:
        """Discover subdomains for a target domain."""
        domain = domain.lower().strip().rstrip('.')
        all_subdomains: Set[str] = set()
        
        logger.info(f"Starting subdomain discovery for {domain}")
        
        if self.config.use_crtsh:
            crtsh_results = await self._query_crtsh(domain)
            all_subdomains.update(crtsh_results)
        
        if self.config.use_certspotter and len(all_subdomains) < self.config.max_subdomains:
            certspotter_results = await self._query_certspotter(domain)
            all_subdomains.update(certspotter_results)
        
        if self.config.use_hackertarget and len(all_subdomains) < self.config.max_subdomains:
            hackertarget_results = await self._query_hackertarget(domain)
            all_subdomains.update(hackertarget_results)
        
        sorted_subdomains = sorted(list(all_subdomains))
        if len(sorted_subdomains) > self.config.max_subdomains:
            logger.warning(
                f"Limiting subdomains from {len(sorted_subdomains)} to {self.config.max_subdomains}"
            )
            sorted_subdomains = sorted_subdomains[:self.config.max_subdomains]
        
        logger.info(f"Subdomain discovery complete for {domain}: found {len(sorted_subdomains)} subdomains")
        return sorted_subdomains
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None