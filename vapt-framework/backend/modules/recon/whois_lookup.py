"""
WHOIS Lookup Module.

Performs WHOIS queries for domain registration information,
with caching, rate limiting, and robust error handling.
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import whois
import time

from .data_normalizer import WhoisInfo

logger = logging.getLogger(__name__)


class WhoisCache:
    """Simple TTL-based cache for WHOIS queries."""
    
    def __init__(self, ttl_seconds: int = 300):
        self._cache: Dict[str, tuple] = {}
        self.ttl_seconds = ttl_seconds
    
    def get(self, domain: str) -> Optional[WhoisInfo]:
        """Get cached WHOIS info if not expired."""
        if domain in self._cache:
            info, timestamp = self._cache[domain]
            if datetime.now() - timestamp < timedelta(seconds=self.ttl_seconds):
                logger.debug(f"Cache hit for {domain}")
                return info
            else:
                logger.debug(f"Cache expired for {domain}")
                del self._cache[domain]
        return None
    
    def set(self, domain: str, info: WhoisInfo) -> None:
        """Cache WHOIS info with timestamp."""
        self._cache[domain] = (info, datetime.now())
        logger.debug(f"Cached WHOIS info for {domain}")
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()


class WhoisLookup:
    """Performs WHOIS lookups with caching and error handling."""
    
    def __init__(self, cache_ttl: int = 300, rate_limit_delay: float = 1.0):
        self.cache = WhoisCache(ttl_seconds=cache_ttl)
        self.rate_limit_delay = rate_limit_delay
        self.last_query_time: Optional[datetime] = None
    
    def _respect_rate_limit(self) -> None:
        """Ensure minimum delay between queries."""
        if self.last_query_time:
            elapsed = (datetime.now() - self.last_query_time).total_seconds()
            if elapsed < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - elapsed
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
    
    def _sanitize_domain(self, domain: str) -> str:
        """Sanitize domain input."""
        return domain.lower().strip().rstrip('.')
    
    def _format_date(self, date_value: Any) -> Optional[str]:
        """Format WHOIS date to ISO format string."""
        if date_value is None:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
            if date_value is None:
                return None
        
        if isinstance(date_value, datetime):
            return date_value.isoformat()
        
        if isinstance(date_value, str):
            for fmt in [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d',
                '%d-%b-%Y',
                '%B %d %Y',
            ]:
                try:
                    return datetime.strptime(date_value.strip(), fmt).isoformat()
                except ValueError:
                    continue
        
        return str(date_value)
    
    def _parse_whois_response(self, domain: str, response: Any) -> WhoisInfo:
        """Parse WHOIS response into standardized format."""
        info = WhoisInfo()
        
        try:
            info.registrar = getattr(response, 'registrar', None)
            if info.registrar is None:
                info.registrar = getattr(response, 'registrar_name', None)
            
            info.creation_date = self._format_date(
                getattr(response, 'creation_date', None)
            )
            info.expiration_date = self._format_date(
                getattr(response, 'expiration_date', None)
            )
            info.updated_date = self._format_date(
                getattr(response, 'updated_date', None)
            )
            
            nameservers = getattr(response, 'name_servers', None)
            if nameservers:
                if isinstance(nameservers, str):
                    info.name_servers = [ns.strip().lower() for ns in nameservers.split(',')]
                elif isinstance(nameservers, list):
                    info.name_servers = [str(ns).strip().lower() for ns in nameservers if ns]
            
            info.registrant_organization = getattr(response, 'org', None)
            info.registrant_country = getattr(response, 'country', None)
            info.raw_text = getattr(response, 'text', None)
            
        except Exception as e:
            logger.warning(f"Error parsing WHOIS response for {domain}: {e}")
        
        return info
    
    def lookup(self, domain: str) -> Optional[WhoisInfo]:
        """Perform WHOIS lookup for a domain."""
        domain = self._sanitize_domain(domain)
        
        # Check cache first
        cached = self.cache.get(domain)
        if cached:
            return cached
        
        # Respect rate limiting
        self._respect_rate_limit()
        
        try:
            logger.info(f"Performing WHOIS lookup for {domain}")
            
            # Perform WHOIS query
            response = whois.whois(domain)
            self.last_query_time = datetime.now()
            
            # Handle empty response
            if response is None or (isinstance(response, dict) and not response):
                logger.warning(f"Empty WHOIS response for {domain}")
                return None
            
            # Parse response
            info = self._parse_whois_response(domain, response)
            
            # Cache the result
            self.cache.set(domain, info)
            
            logger.info(f"WHOIS lookup successful for {domain}")
            return info
            
        except AttributeError as e:
            # Handle PywhoisError or any whois attribute errors
            logger.error(f"WHOIS attribute error for {domain}: {e}")
            return None
            
        except Exception as e:
            # Catch ALL exceptions including connection errors
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return None
    
    def lookup_to_dict(self, domain: str) -> Optional[Dict[str, Any]]:
        """Perform WHOIS lookup and return dictionary."""
        info = self.lookup(domain)
        if info:
            return info.to_dict()
        return None