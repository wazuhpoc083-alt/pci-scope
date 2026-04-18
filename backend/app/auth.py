"""Authentication utilities: JWT validation, admin token bypass, FastAPI dependency."""
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from jose import JWTError, jwt

from app.config import settings

ALGORITHM = "HS256"

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class TokenClaims:
    tenant_id: Optional[str]
    tenant_name: Optional[str]
    role: str  # "admin" | "viewer"
    is_admin: bool


def create_tenant_token(tenant_id: str, tenant_name: str, expires_hours: int = 24) -> str:
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    payload = {
        "sub": tenant_id,
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "role": "viewer",
        "iat": now,
        "exp": now + timedelta(hours=expires_hours),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def verify_token(token: str) -> TokenClaims:
    """Validate a bearer token. Returns TokenClaims on success, raises HTTPException on failure."""
    # Admin token bypass – checked first, no JWT parsing needed
    if settings.admin_token and token == settings.admin_token:
        return TokenClaims(tenant_id=None, tenant_name=None, role="admin", is_admin=True)

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    tenant_id = payload.get("tenant_id")
    tenant_name = payload.get("tenant_name")
    role = payload.get("role", "viewer")
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing tenant_id claim",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenClaims(tenant_id=tenant_id, tenant_name=tenant_name, role=role, is_admin=False)


def get_current_claims(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TokenClaims:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(credentials.credentials)


def require_admin(claims: TokenClaims = Depends(get_current_claims)) -> TokenClaims:
    if not claims.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return claims
