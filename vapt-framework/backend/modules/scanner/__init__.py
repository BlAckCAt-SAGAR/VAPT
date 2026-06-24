"""
Unified Scanner Module for VAPT Framework.

Combines HTTP security analysis, port scanning, service detection,
and CVE matching into an intelligent scanning workflow.
"""

from .scan_orchestrator import ScanOrchestrator, ScanOrchestratorConfig
from .data_contracts import ScanResult, HttpFinding, HeaderIssue, CVEInfo, PortInfo

__all__ = [
    "ScanOrchestrator",
    "ScanOrchestratorConfig",
    "ScanResult",
    "HttpFinding",
    "HeaderIssue",
    "CVEInfo",
    "PortInfo",
]