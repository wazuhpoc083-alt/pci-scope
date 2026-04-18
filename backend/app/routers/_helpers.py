"""Shared helpers for assessment-scoped routers."""
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app import models
from app.auth import TokenClaims


def get_assessment_for_claims(assessment_id: str, db: Session, claims: TokenClaims) -> models.Assessment:
    """Fetch an assessment, enforcing tenant isolation. Raises 404 if not found or out of scope."""
    q = db.query(models.Assessment).filter(models.Assessment.id == assessment_id)
    if not claims.is_admin:
        q = q.filter(models.Assessment.tenant_id == claims.tenant_id)
    assessment = q.first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment
