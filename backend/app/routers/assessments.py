from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import TokenClaims, get_current_claims
from app.database import get_db

router = APIRouter(prefix="/assessments", tags=["assessments"])


def _scoped_assessment_query(db: Session, claims: TokenClaims):
    """Return a query filtered to the caller's tenant (admin sees all)."""
    q = db.query(models.Assessment)
    if not claims.is_admin:
        q = q.filter(models.Assessment.tenant_id == claims.tenant_id)
    return q


def _get_assessment_or_404(assessment_id: str, db: Session, claims: TokenClaims) -> models.Assessment:
    assessment = _scoped_assessment_query(db, claims).filter(models.Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@router.get("/", response_model=list[schemas.AssessmentOut])
def list_assessments(
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    return _scoped_assessment_query(db, claims).order_by(models.Assessment.created_at.desc()).all()


@router.post("/", response_model=schemas.AssessmentOut, status_code=201)
def create_assessment(
    payload: schemas.AssessmentCreate,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    # Determine which tenant this assessment belongs to
    if claims.is_admin:
        tenant_id = payload.tenant_id or None
        if not tenant_id:
            raise HTTPException(status_code=400, detail="Admin must supply tenant_id in request body")
    else:
        tenant_id = claims.tenant_id

    data = payload.model_dump(exclude={"tenant_id"})
    assessment = models.Assessment(**data, tenant_id=tenant_id)
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}", response_model=schemas.AssessmentOut)
def get_assessment(
    assessment_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    return _get_assessment_or_404(assessment_id, db, claims)


@router.delete("/{assessment_id}", status_code=204)
def delete_assessment(
    assessment_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    assessment = _get_assessment_or_404(assessment_id, db, claims)
    db.delete(assessment)
    db.commit()
