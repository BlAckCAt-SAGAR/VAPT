"""
Health check endpoint.
"""

from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Health check endpoint - no auth required."""
    return {
        "status": "healthy",
        "service": "VAPT Framework API",
        "version": "1.0.0"
    }


@router.get("/health/ready")
async def readiness_check():
    """Readiness check - verifies Celery/Redis are connected."""
    try:
        from tasks.celery_app import celery_app
        celery_app.control.ping(timeout=1)
        redis_status = "connected"
    except Exception:
        redis_status = "disconnected"
    
    return {
        "status": "ready" if redis_status == "connected" else "degraded",
        "redis": redis_status
    }