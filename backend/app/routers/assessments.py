from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("/", response_model=list[schemas.AssessmentOut])
def list_assessments(db: Session = Depends(get_db)):
    return db.query(models.Assessment).order_by(models.Assessment.created_at.desc()).all()


@router.post("/", response_model=schemas.AssessmentOut, status_code=201)
def create_assessment(payload: schemas.AssessmentCreate, db: Session = Depends(get_db)):
    assessment = models.Assessment(**payload.model_dump())
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}", response_model=schemas.AssessmentOut)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)):
    assessment = db.query(models.Assessment).filter(models.Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@router.delete("/{assessment_id}", status_code=204)
def delete_assessment(assessment_id: str, db: Session = Depends(get_db)):
    assessment = db.query(models.Assessment).filter(models.Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    db.delete(assessment)
    db.commit()
