"""
Security middleware: CORS, CSP headers, rate limiting.
"""

from urllib import response

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import time
from typing import Dict


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Server"] = "VAPT-Framework"
        
        # Remove sensitive headers
        try:
            del response.headers["X-Powered-By"]
        except (KeyError, TypeError):
            pass
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs all API requests with timing."""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        # Log request (exclude API key from logs)
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        status = response.status_code
        
        print(f"[API] {client_ip} {method} {path} → {status} ({duration:.3f}s)")
        
        return response


class RateLimitBypassMiddleware(BaseHTTPMiddleware):
    """Allows health check to bypass rate limiting."""
    
    async def dispatch(self, request: Request, call_next):
        if request.url.path in ["/health", "/docs", "/openapi.json", "/redoc"]:
            return await call_next(request)
        return await call_next(request)


def setup_security(app: FastAPI) -> Limiter:
    """Configure all security middleware for the FastAPI app."""
    
    # CORS
    origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key"],
        max_age=3600,
    )
    
    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Request logging
    app.add_middleware(RequestLoggingMiddleware)
    
    # Rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[os.getenv("API_RATE_LIMIT", "10/minute")]
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    return limiter