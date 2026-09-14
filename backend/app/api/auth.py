import os
from datetime import datetime, timedelta, timezone
from typing import Any
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
import jwt

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"],
)

# Configuration from environment variables
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ulpf_admin_2026")
JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret_in_production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    user: dict[str, Any]
    status: str = "authenticated"

def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication token required")
    
    token = authorization
    if authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token")

@router.post("/login", response_model=LoginResponse)
def login(creds: LoginRequest) -> dict[str, Any]:
    """Authenticate with username and password, returning a stateless JWT."""
    if creds.username == ADMIN_USERNAME and creds.password == ADMIN_PASSWORD:
        user_info = {
            "sub": creds.username,
            "username": creds.username,
            "role": "soc_admin",
            "tier": "Tier 3 Lead Analyst",
            "access_level": "read_write_deploy",
            "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
        }
        
        token = jwt.encode(user_info, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        # Remove 'exp' for the clean response object
        clean_user = user_info.copy()
        clean_user.pop("exp", None)
        
        return {
            "token": token,
            "user": clean_user,
            "status": "authenticated",
        }
    
    raise HTTPException(
        status_code=401,
        detail="Invalid credentials. Verify username and password.",
    )

@router.get("/me")
def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Return active user profile and permission scope."""
    # Remove 'exp' before returning to client
    user_resp = user.copy()
    user_resp.pop("exp", None)
    return user_resp

@router.post("/logout")
def logout() -> dict[str, Any]:
    """
    Stateless JWT cannot be invalidated server-side without a blocklist. 
    Client is expected to drop the token.
    """
    return {"status": "logged_out"}

