"""
Main FastAPI application for VAPT Framework.
"""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
import os
import sys

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.routes import health, scan
from api.middleware.security import setup_security


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    app = FastAPI(
        title="VAPT Framework API",
        description="""
        ## Automated Vulnerability Assessment & Penetration Testing
        
        **Modules:**
        - **Reconnaissance**: DNS, WHOIS, Subdomain discovery
        - **Scanner**: Port scanning, HTTP security headers, CVE matching
        - **Risk Scorer**: CVSS-based risk scoring with environmental modifiers
        - **Report Generator**: Professional HTML/PDF security reports
        
        **Authentication:** API Key required (X-API-Key header)
        """,
        version="1.0.0",
        docs_url="/docs" if os.getenv("APP_ENV") != "production" else None,
        redoc_url="/redoc" if os.getenv("APP_ENV") != "production" else None,
    )
    
    # Setup security middleware
    limiter = setup_security(app)
    
    # Register routes
    app.include_router(health.router)
    app.include_router(scan.router)
    
    @app.on_event("startup")
    async def startup():
        """Verify connections on startup."""
        try:
            from tasks.celery_app import celery_app
            celery_app.control.ping(timeout=1)
            print("[API] Celery worker connected")
        except Exception:
            print("[API] WARNING: Celery worker not available")
    
    @app.on_event("shutdown")
    async def shutdown():
        """Cleanup on shutdown."""
        print("[API] Shutting down")
    
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=os.getenv("APP_ENV") == "development",
        log_level="info"
    )