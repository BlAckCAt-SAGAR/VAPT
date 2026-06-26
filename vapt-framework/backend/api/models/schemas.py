"""
Pydantic schemas for API request/response validation.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from enum import Enum


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"


class ScanRequest(BaseModel):
    """Request to start a new scan."""
    target: str = Field(..., min_length=1, max_length=255, description="Domain or IP to scan")
    scan_type: Optional[str] = Field(default="full", description="full, quick, recon-only")
    
    @validator("target")
    def sanitize_target(cls, v: str) -> str:
        """Basic input sanitization."""
        v = v.strip().lower()
        # Block shell injection characters
        dangerous = [";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">", "\n", "\r"]
        for char in dangerous:
            if char in v:
                raise ValueError(f"Invalid character in target: {char}")
        return v


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ProgressUpdate(BaseModel):
    """Progress update for a running scan."""
    module: str
    percent: float
    message: str


class ScanResponse(BaseModel):
    """Response after starting a scan."""
    scan_id: str
    status: ScanStatus
    target: str
    message: str


class ScanStatusResponse(BaseModel):
    """Status of a scan."""
    scan_id: str
    target: str
    status: ScanStatus
    progress: float = 0.0
    current_module: Optional[str] = None
    message: Optional[str] = None
    modules_executed: List[str] = []
    errors: List[str] = []
    result_summary: Optional[Dict[str, Any]] = None
    execution_time: Optional[float] = None


class ScanListResponse(BaseModel):
    """List of past scans."""
    scans: List[ScanStatusResponse]
    total: int


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    status_code: int