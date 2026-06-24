"""
Intelligent TCP Port Scanner using asyncio.
"""

import asyncio
import logging
from typing import List, Optional, Set

from .data_contracts import PortInfo

logger = logging.getLogger(__name__)


class PortScanner:
    """Scans TCP ports concurrently and returns open ports."""

    # Common port lists
    TOP_20 = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
    TOP_100 = TOP_20 + [
        81, 88, 111, 113, 119, 123, 137, 138, 161, 162, 389, 443, 444, 445, 464, 465, 500, 514, 515, 520,
        554, 587, 623, 631, 636, 646, 691, 860, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
        1080, 1194, 1214, 1241, 1311, 1337, 1433, 1434, 1521, 1701, 1720, 1723, 1755, 1812, 1900, 2000, 2049,
        2082, 2083, 2100, 2222, 2302, 2483, 2484, 2745, 2967, 3000, 3128, 3260, 3306, 3389, 3689, 3690,
        3780, 4333, 4443, 4664, 4899, 5000, 5001, 5060, 5190, 5222, 5353, 5432, 5555, 5631, 5800, 5900,
        5984, 6000, 6379, 6667, 7001, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200,
        9300, 10000, 11211, 27017, 27018, 28017, 50000, 50030, 50060
    ]

    def __init__(self, timeout: float = 2.0, max_concurrency: int = 100):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def _check_port(self, ip: str, port: int) -> Optional[int]:
        """Check if a single TCP port is open. Returns port if open, else None."""
        try:
            async with self.semaphore:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception as e:
            logger.debug(f"Error checking {ip}:{port} - {e}")
            return None

    async def scan(self, target: str, ports: List[int]) -> List[int]:
        """
        Scan the given list of ports on the target IP.

        Returns list of open ports.
        """
        logger.info(f"Scanning {len(ports)} ports on {target}")
        tasks = [self._check_port(target, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = [port for port in results if isinstance(port, int)]
        logger.info(f"Open ports on {target}: {open_ports}")
        return open_ports