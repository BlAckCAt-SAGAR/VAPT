"""
Reconnaissance Module for VAPT Framework.

Performs passive reconnaissance on target domains/IPs to establish
the attack surface before active probing begins.

Exports:
    ReconOrchestrator: Main entry point for reconnaissance operations
    ReconResult: Standardized reconnaissance result data structure
"""

from .recon_orchestrator import ReconOrchestrator
from .data_normalizer import ReconResult, DNSRecord, WhoisInfo, SubdomainInfo

__all__ = [
    "ReconOrchestrator",
    "ReconResult",
    "DNSRecord",
    "WhoisInfo",
    "SubdomainInfo",
]

__version__ = "1.0.0"
__author__ = "VAPT Framework Team"