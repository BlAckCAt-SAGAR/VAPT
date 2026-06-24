"""
CVE Matcher: loads a local CVE database and matches software/version.
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Optional

from .data_contracts import CVEInfo

logger = logging.getLogger(__name__)


class VulnMatcher:
    """Matches identified software/version against known CVEs."""

    def __init__(self, database_path: Optional[Path] = None):
        if database_path is None:
            database_path = Path(__file__).parent / "cve_database.json"
        self.database_path = database_path
        self.cve_entries = []
        self._load_database()

    def _load_database(self) -> None:
        """Load CVE database from JSON file."""
        try:
            with open(self.database_path, "r") as f:
                self.cve_entries = json.load(f)
            logger.info(f"Loaded {len(self.cve_entries)} CVE entries")
        except Exception as e:
            logger.error(f"Failed to load CVE database: {e}")
            self.cve_entries = []

    def match(self, software: str, version: Optional[str]) -> List[CVEInfo]:
        """
        Find CVEs matching the given software and version.

        Args:
            software: Software name (e.g., "Apache", "nginx")
            version: Version string (e.g., "2.4.41")

        Returns list of CVEInfo objects.
        """
        if not software or not version:
            return []

        matches = []
        software_lower = software.lower().strip()
        for entry in self.cve_entries:
            if entry.get("software", "").lower() != software_lower:
                continue
            # Check if version is in the affected list
            affected_versions = entry.get("versions", [])
            if self._version_matches(version, affected_versions):
                matches.append(CVEInfo(
                    cve_id=entry.get("cve_id", ""),
                    title=entry.get("title", ""),
                    cvss_score=entry.get("cvss", 0.0),
                    severity=entry.get("severity", "info"),
                    description=entry.get("description", ""),
                    affected_software=software,
                    affected_versions=affected_versions,
                    remediation=entry.get("remediation", "")
                ))
        return matches

    def _version_matches(self, version: str, affected_versions: List[str]) -> bool:
        """
        Check if the given version matches any in the affected list.
        Supports exact match and simple range patterns (e.g., "<=2.4.41").
        """
        if not affected_versions:
            return False
        version = version.strip()
        for aff in affected_versions:
            if aff == version:
                return True
            # Handle range patterns (very basic)
            if aff.startswith("<="):
                max_ver = aff[2:].strip()
                if self._version_le(version, max_ver):
                    return True
            elif aff.startswith("<"):
                max_ver = aff[1:].strip()
                if self._version_lt(version, max_ver):
                    return True
            elif aff.startswith(">="):
                min_ver = aff[2:].strip()
                if self._version_ge(version, min_ver):
                    return True
            elif aff.startswith(">"):
                min_ver = aff[1:].strip()
                if self._version_gt(version, min_ver):
                    return True
        return False

    def _version_tuple(self, ver: str):
        """Convert version string to tuple of integers for comparison."""
        try:
            return tuple(map(int, ver.split(".")))
        except Exception:
            return (0,)

    def _version_le(self, v1, v2):
        return self._version_tuple(v1) <= self._version_tuple(v2)

    def _version_lt(self, v1, v2):
        return self._version_tuple(v1) < self._version_tuple(v2)

    def _version_ge(self, v1, v2):
        return self._version_tuple(v1) >= self._version_tuple(v2)

    def _version_gt(self, v1, v2):
        return self._version_tuple(v1) > self._version_tuple(v2)