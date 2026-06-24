"""
Data normalization and contract definitions for the Reconnaissance Module.

Defines the standardized data structures that all sub-modules must output,
ensuring consistency across the VAPT framework pipeline.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timezone
import json
import ipaddress


@dataclass
class DNSRecord:
    """Represents a single DNS record with metadata."""
    
    record_type: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None  # For MX records
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {
            "record_type": self.record_type,
            "value": self.value,
        }
        if self.ttl is not None:
            result["ttl"] = self.ttl
        if self.priority is not None:
            result["priority"] = self.priority
        return result
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class WhoisInfo:
    """Standardized WHOIS lookup results."""
    
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    registrant_organization: Optional[str] = None
    registrant_country: Optional[str] = None
    raw_text: Optional[str] = None  # Original response for auditing
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, filtering out None values."""
        result = {}
        if self.registrar:
            result["registrar"] = self.registrar
        if self.creation_date:
            result["creation_date"] = self.creation_date
        if self.expiration_date:
            result["expiration_date"] = self.expiration_date
        if self.updated_date:
            result["updated_date"] = self.updated_date
        if self.name_servers:
            result["name_servers"] = self.name_servers
        if self.registrant_organization:
            result["registrant_organization"] = self.registrant_organization
        if self.registrant_country:
            result["registrant_country"] = self.registrant_country
        return result
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WhoisInfo':
        """Create WhoisInfo from dictionary, with validation."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)


@dataclass
class SubdomainInfo:
    """Represents discovered subdomain information."""
    
    subdomain: str
    source: str  # e.g., "crt.sh", "dns_bruteforce"
    resolved_ips: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            "subdomain": self.subdomain,
            "source": self.source,
        }
        if self.resolved_ips:
            result["resolved_ips"] = self.resolved_ips
        if self.first_seen:
            result["first_seen"] = self.first_seen
        if self.last_seen:
            result["last_seen"] = self.last_seen
        return result
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())
    
    def __hash__(self):
        """Allow deduplication by subdomain name."""
        return hash(self.subdomain.lower())


@dataclass
class ReconResult:
    """
    Complete reconnaissance result container.
    
    This is the primary output contract that the main orchestrator expects.
    All sub-modules populate portions of this structure.
    """
    
    target: str
    target_type: str  # "domain" or "ip"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    # DNS Records grouped by type
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    
    # Resolved IPs (A and AAAA records combined)
    resolved_ips: List[str] = field(default_factory=list)
    
    # WHOIS information
    whois: Optional[Dict[str, Any]] = None
    
    # Discovered subdomains
    subdomains: List[str] = field(default_factory=list)
    
    # Reverse DNS results (only for IP targets)
    reverse_dns: Optional[List[str]] = None
    
    # Execution metadata
    errors: List[str] = field(default_factory=list)
    modules_executed: List[str] = field(default_factory=list)
    execution_time_seconds: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to the standardized scan_context format."""
        recon_data = {
            "resolved_ips": self.resolved_ips,
            "dns_records": self.dns_records,
            "whois": self.whois,
            "subdomains": self.subdomains,
            "reverse_dns": self.reverse_dns,
        }
        
        return {
            "target": self.target,
            "target_type": self.target_type,
            "recon_data": recon_data,
            "errors": self.errors,
            "modules_executed": self.modules_executed,
            "execution_time_seconds": self.execution_time_seconds,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def add_error(self, error: str) -> None:
        """Add an error message to the result."""
        self.errors.append(f"{datetime.now(timezone.utc).isoformat()}: {error}")
    
    def validate(self) -> bool:
        """
        Validate the reconnaissance result.
        
        Returns:
            True if valid, False otherwise
        """
        if not self.target:
            self.add_error("Target is empty")
            return False
        
        if self.target_type not in ["domain", "ip"]:
            self.add_error(f"Invalid target_type: {self.target_type}")
            return False
        
        if self.target_type == "ip":
            try:
                ipaddress.ip_address(self.target)
            except ValueError:
                self.add_error(f"Invalid IP address: {self.target}")
                return False
        
        return True
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """
        Normalize domain name for consistent comparison.
        
        Args:
            domain: Raw domain name input
            
        Returns:
            Normalized domain name (lowercase, no trailing dot, no surrounding whitespace)
        """
        return domain.strip().lower().rstrip('.')
    
    @staticmethod
    def is_ip_address(value: str) -> bool:
        """
        Determine if a value is an IP address.
        
        Args:
            value: String to check
            
        Returns:
            True if value is an IP address
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def determine_target_type(target: str) -> str:
        """
        Determine if target is a domain or IP address.
        
        Args:
            target: The target string
            
        Returns:
            "domain" or "ip"
        """
        if ReconResult.is_ip_address(target):
            return "ip"
        return "domain"