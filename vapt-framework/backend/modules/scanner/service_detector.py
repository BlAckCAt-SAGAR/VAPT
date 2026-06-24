"""
Service Detector: connects to open ports, grabs banners, and identifies services.
"""

import asyncio
import logging
from typing import Optional

from .data_contracts import PortInfo

logger = logging.getLogger(__name__)


class ServiceDetector:
    """Detects services and versions on open ports."""

    # Simple probes for common services
    PROBES = {
        21: b"",                          # FTP (banner sent automatically)
        22: b"",                          # SSH (banner sent automatically)
        25: b"EHLO test\r\n",            # SMTP
        80: b"HEAD / HTTP/1.0\r\n\r\n",  # HTTP
        110: b"",                         # POP3 (banner)
        143: b"",                         # IMAP (banner)
        443: b"HEAD / HTTP/1.0\r\n\r\n", # HTTPS
        3306: b"",                        # MySQL (banner)
        5432: b"",                        # PostgreSQL (needs special handling)
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
        27017: b"",                       # MongoDB
    }

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def detect(self, ip: str, port: int) -> PortInfo:
        """
        Connect to ip:port, grab banner, identify service and version.

        Returns PortInfo with details.
        """
        port_info = PortInfo(port=port, protocol="tcp")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            # If probe is defined, send it
            probe = self.PROBES.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()

            # Read banner (up to 1024 bytes)
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            except asyncio.TimeoutError:
                banner = b""

            writer.close()
            await writer.wait_closed()

            if banner:
                port_info.banner = banner.decode("utf-8", errors="replace").strip()
                self._parse_banner(port_info, port)
            else:
                # Even without banner, try to identify by port
                port_info.service = self._guess_service(port)

        except ConnectionRefusedError:
            port_info.state = "closed"
        except asyncio.TimeoutError:
            port_info.error = "Connection timeout"
        except Exception as e:
            port_info.error = str(e)
            logger.debug(f"Error detecting service on {ip}:{port}: {e}")

        return port_info

    def _parse_banner(self, port_info: PortInfo, port: int) -> None:
        """Extract service name and version from banner."""
        banner = port_info.banner
        # SSH
        if banner.startswith("SSH-"):
            port_info.service = "SSH"
            # e.g., SSH-2.0-OpenSSH_7.9
            parts = banner.split("-")
            if len(parts) >= 3:
                port_info.version = parts[2]
        # HTTP
        elif banner.startswith("HTTP/") or "Server:" in banner:
            port_info.service = "HTTP"
            for line in banner.split("\r\n"):
                if line.startswith("Server:"):
                    port_info.version = line.split(":", 1)[1].strip()
        # SMTP
        elif banner.startswith("220 "):
            port_info.service = "SMTP"
            # e.g., 220 smtp.example.com ESMTP Postfix
            parts = banner.split()
            if len(parts) >= 3:
                port_info.version = parts[-1]
        # POP3
        elif banner.startswith("+OK"):
            port_info.service = "POP3"
        # IMAP
        elif banner.startswith("* OK"):
            port_info.service = "IMAP"
        # MySQL
        elif banner.startswith(b"\x00"):
            port_info.service = "MySQL"
        else:
            # Fallback: guess by port
            port_info.service = self._guess_service(port)

    def _guess_service(self, port: int) -> str:
        """Map port to common service name."""
        common = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP",
            5900: "VNC", 8080: "HTTP-Proxy", 27017: "MongoDB"
        }
        return common.get(port, "unknown")