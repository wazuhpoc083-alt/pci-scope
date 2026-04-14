from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/assessments/{assessment_id}/assets", tags=["assets"])


def _get_assessment_or_404(assessment_id: str, db: Session) -> models.Assessment:
    assessment = db.query(models.Assessment).filter(models.Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@router.get("/", response_model=list[schemas.AssetOut])
def list_assets(assessment_id: str, db: Session = Depends(get_db)):
    _get_assessment_or_404(assessment_id, db)
    return (
        db.query(models.Asset)
        .filter(models.Asset.assessment_id == assessment_id)
        .order_by(models.Asset.created_at)
        .all()
    )


@router.post("/", response_model=schemas.AssetOut, status_code=201)
def create_asset(assessment_id: str, payload: schemas.AssetCreate, db: Session = Depends(get_db)):
    _get_assessment_or_404(assessment_id, db)
    asset = models.Asset(assessment_id=assessment_id, **payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.post("/bulk", response_model=list[schemas.AssetOut], status_code=201)
def bulk_create_assets(
    assessment_id: str,
    payload: list[schemas.AssetCreate],
    db: Session = Depends(get_db),
):
    _get_assessment_or_404(assessment_id, db)
    assets = [models.Asset(assessment_id=assessment_id, **a.model_dump()) for a in payload]
    db.add_all(assets)
    db.commit()
    for a in assets:
        db.refresh(a)
    return assets


@router.get("/{asset_id}", response_model=schemas.AssetOut)
def get_asset(assessment_id: str, asset_id: str, db: Session = Depends(get_db)):
    asset = (
        db.query(models.Asset)
        .filter(models.Asset.id == asset_id, models.Asset.assessment_id == assessment_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=schemas.AssetOut)
def update_asset(
    assessment_id: str,
    asset_id: str,
    payload: schemas.AssetUpdate,
    db: Session = Depends(get_db),
):
    asset = (
        db.query(models.Asset)
        .filter(models.Asset.id == asset_id, models.Asset.assessment_id == assessment_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=204)
def delete_asset(assessment_id: str, asset_id: str, db: Session = Depends(get_db)):
    asset = (
        db.query(models.Asset)
        .filter(models.Asset.id == asset_id, models.Asset.assessment_id == assessment_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
