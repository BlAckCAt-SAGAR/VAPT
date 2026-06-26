"""
API Key authentication middleware.
"""

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from starlette.status import HTTP_403_FORBIDDEN
import os
import secrets
from typing import Optional


API_KEY_HEADER = APIKeyHeader(name=os.getenv("API_KEY_HEADER", "X-API-Key"), auto_error=False)


class APIAuth:
    """Validates API keys and manages authentication."""
    
    def __init__(self):
        self.valid_key = os.getenv("API_KEY", "")
    
    async def validate(self, api_key: Optional[str] = Security(API_KEY_HEADER)) -> str:
        """
        Validate the API key.
        
        Args:
            api_key: The API key from the request header.
            
        Returns:
            The validated API key.
            
        Raises:
            HTTPException: If the API key is invalid.
        """
        if not self.valid_key:
            # In dev mode without API key set, allow all
            if os.getenv("APP_ENV", "development") == "development":
                return "dev-mode"
        
        if not api_key:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="API key required. Provide it in the X-API-Key header."
            )
        
        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(api_key, self.valid_key):
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid API key."
            )
        
        return api_key
    
    @staticmethod
    def generate_key() -> str:
        """Generate a secure API key."""
        return f"vapt_sk_{secrets.token_hex(32)}"


# Global auth instance
api_auth = APIAuth()