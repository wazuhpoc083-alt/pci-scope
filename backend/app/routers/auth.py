"""Auth endpoints: /api/auth/me, /api/auth/tenants, /api/auth/tokens"""
from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models
from app.auth import TokenClaims, create_tenant_token, get_current_claims, require_admin
from app.database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

class TenantOut(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantCreate(BaseModel):
    name: str
    slug: str


class TokenRequest(BaseModel):
    tenant_id: str
    expires_hours: int = 24


class TokenResponse(BaseModel):
    token: str
    tenant_id: str
    tenant_name: str
    expires_hours: int


class MeResponse(BaseModel):
    role: str
    is_admin: bool
    tenant_id: str | None
    tenant_name: str | None


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@router.get("/me", response_model=MeResponse)
def me(claims: TokenClaims = Depends(get_current_claims)):
    """Validate the bearer token and return identity info."""
    return MeResponse(
        role=claims.role,
        is_admin=claims.is_admin,
        tenant_id=claims.tenant_id,
        tenant_name=claims.tenant_name,
    )


@router.get("/tenants", response_model=list[TenantOut])
def list_tenants(
    claims: TokenClaims = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return db.query(models.Tenant).order_by(models.Tenant.created_at).all()


@router.post("/tenants", response_model=TenantOut, status_code=201)
def create_tenant(
    payload: TenantCreate,
    claims: TokenClaims = Depends(require_admin),
    db: Session = Depends(get_db),
):
    existing = db.query(models.Tenant).filter(models.Tenant.slug == payload.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant slug already exists")
    tenant = models.Tenant(name=payload.name, slug=payload.slug)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@router.post("/tokens", response_model=TokenResponse)
def issue_token(
    payload: TokenRequest,
    claims: TokenClaims = Depends(require_admin),
    db: Session = Depends(get_db),
):
    tenant = db.query(models.Tenant).filter(models.Tenant.id == payload.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    token = create_tenant_token(tenant.id, tenant.name, payload.expires_hours)
    return TokenResponse(
        token=token,
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        expires_hours=payload.expires_hours,
    )
