"""
HTTP/HTTPS Scanner: probes web services, analyzes headers, cookies, CORS, and SSL.
"""

import logging
import ssl
import socket
from datetime import datetime
from typing import Optional, Dict, List, Tuple
import httpx
from urllib.parse import urlparse

from .data_contracts import HttpFinding, HeaderIssue

logger = logging.getLogger(__name__)


class HTTPScanner:
    """Performs HTTP/HTTPS probing and security header analysis."""

    # Security headers and their recommended values
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "recommended": "default-src 'self'",
            "severity": "high",
            "issue": "Missing Content-Security-Policy header",
            "recommendation": "Add a strict CSP header to prevent XSS and data injection attacks."
        },
        "X-Content-Type-Options": {
            "recommended": "nosniff",
            "severity": "medium",
            "issue": "Missing X-Content-Type-Options header",
            "recommendation": "Set 'X-Content-Type-Options: nosniff' to prevent MIME sniffing."
        },
        "X-Frame-Options": {
            "recommended": "DENY",
            "severity": "medium",
            "issue": "Missing X-Frame-Options header",
            "recommendation": "Set 'X-Frame-Options: DENY' to prevent clickjacking attacks."
        },
        "Strict-Transport-Security": {
            "recommended": "max-age=31536000; includeSubDomains",
            "severity": "high",
            "issue": "Missing HSTS header",
            "recommendation": "Enable HTTP Strict Transport Security to enforce HTTPS."
        },
        "Referrer-Policy": {
            "recommended": "strict-origin-when-cross-origin",
            "severity": "low",
            "issue": "Missing Referrer-Policy header",
            "recommendation": "Set a Referrer-Policy to control referrer information leakage."
        },
        "Permissions-Policy": {
            "recommended": "geolocation=(), microphone=()",
            "severity": "low",
            "issue": "Missing Permissions-Policy header",
            "recommendation": "Restrict browser features using Permissions-Policy."
        }
    }

    def __init__(self, timeout: float = 10.0, user_agent: str = "VAPT-Scanner/2.0"):
        self.timeout = timeout
        self.user_agent = user_agent

    async def probe(self, target: str, port: int = 443, use_https: bool = True) -> Optional[HttpFinding]:
        """
        Probe a target via HTTP/HTTPS and capture response details.

        Returns HttpFinding or None if connection fails.
        """
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{target}:{port}"
        finding = HttpFinding(url=url, is_https=use_https)

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,  # For security testing we may want to see all certs
                headers={"User-Agent": self.user_agent}
            ) as client:
                response = await client.get(url)
                finding.status_code = response.status_code
                finding.headers = dict(response.headers)
                finding.cookies = [
                    {"name": c.name, "value": c.value, "secure": c.secure,
                     "httponly": c.has_httponly, "samesite": c.samesite}
                    for c in response.cookies.jar
                ]

                # Parse Server header
                server = finding.headers.get("Server", "")
                if server:
                    parts = server.split("/", 1)
                    finding.server_software = parts[0].strip()
                    finding.server_version = parts[1].strip() if len(parts) > 1 else None

                # SSL validation if HTTPS
                if use_https:
                    self._validate_ssl(target, port, finding)

                # Analyze security headers
                finding.header_issues = self.analyze_headers(finding.headers)
                # Also analyze cookies and CORS
                finding.header_issues.extend(self.analyze_cookies(finding.cookies))
                cors_issue = self.analyze_cors(finding.headers)
                if cors_issue:
                    finding.header_issues.append(cors_issue)

                return finding

        except httpx.HTTPError as e:
            logger.warning(f"HTTP probe failed for {url}: {e}")
            finding.error = str(e)
            return finding
        except Exception as e:
            logger.error(f"Unexpected error probing {url}: {e}")
            finding.error = str(e)
            return finding

    def _validate_ssl(self, hostname: str, port: int, finding: HttpFinding) -> None:
        """Check SSL certificate validity."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    finding.ssl_valid = True
                    expiry_str = cert.get("notAfter")
                    if expiry_str:
                        # Parse SSL date format
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        finding.ssl_expiry = expiry.isoformat()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    finding.ssl_issuer = issuer.get("organizationName", "Unknown")
        except Exception as e:
            logger.warning(f"SSL validation failed for {hostname}:{port}: {e}")
            finding.ssl_valid = False

    def analyze_headers(self, headers: Dict[str, str]) -> List[HeaderIssue]:
        """Check for missing or misconfigured security headers."""
        issues = []
        for header, config in self.SECURITY_HEADERS.items():
            if header not in headers:
                issues.append(HeaderIssue(
                    header_name=header,
                    severity=config["severity"],
                    issue=config["issue"],
                    recommendation=config["recommendation"],
                    current_value=None
                ))
            else:
                # Check for weak configurations (simple checks)
                current = headers[header]
                if header == "Strict-Transport-Security":
                    if "max-age=" not in current or "includeSubDomains" not in current:
                        issues.append(HeaderIssue(
                            header_name=header,
                            severity="medium",
                            issue="HSTS header is present but may be weak",
                            recommendation="Use 'max-age=31536000; includeSubDomains'",
                            current_value=current
                        ))
        return issues

    def analyze_cookies(self, cookies: List[Dict]) -> List[HeaderIssue]:
        """Check cookies for Secure, HttpOnly, SameSite flags."""
        issues = []
        for cookie in cookies:
            if not cookie.get("secure"):
                issues.append(HeaderIssue(
                    header_name="Set-Cookie",
                    severity="medium",
                    issue=f"Cookie '{cookie.get('name')}' missing Secure flag",
                    recommendation="Set Secure flag to transmit only over HTTPS",
                    current_value=f"Secure={cookie.get('secure')}"
                ))
            if not cookie.get("httponly"):
                issues.append(HeaderIssue(
                    header_name="Set-Cookie",
                    severity="medium",
                    issue=f"Cookie '{cookie.get('name')}' missing HttpOnly flag",
                    recommendation="Set HttpOnly to prevent JavaScript access",
                    current_value=f"HttpOnly={cookie.get('httponly')}"
                ))
            if not cookie.get("samesite") or cookie["samesite"].lower() == "none":
                issues.append(HeaderIssue(
                    header_name="Set-Cookie",
                    severity="low",
                    issue=f"Cookie '{cookie.get('name')}' has SameSite=None or missing",
                    recommendation="Set SameSite=Lax or Strict to prevent CSRF",
                    current_value=f"SameSite={cookie.get('samesite')}"
                ))
        return issues

    def analyze_cors(self, headers: Dict[str, str]) -> Optional[HeaderIssue]:
        """Check for overly permissive CORS configurations."""
        origin = headers.get("Access-Control-Allow-Origin", "")
        if origin == "*":
            return HeaderIssue(
                header_name="Access-Control-Allow-Origin",
                severity="high",
                issue="CORS allows any origin (wildcard '*')",
                recommendation="Restrict to specific origins or use Vary: Origin",
                current_value=origin
            )
        if origin and origin != "null":
            # Could be a reflected origin; simple check if it's the request origin (not implemented here)
            pass
        return None