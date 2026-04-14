import csv
import io

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/assessments/{assessment_id}/assets", tags=["assets"])

CSV_FIELDS = [
    "name", "ip_address", "hostname", "asset_type", "scope_status",
    "is_cde", "stores_pan", "processes_pan", "transmits_pan",
    "segmentation_notes", "justification", "tags",
]

VALID_ASSET_TYPES = [e.value for e in models.AssetType]
VALID_SCOPE_STATUSES = [e.value for e in models.ScopeStatus]
VALID_BOOLS = {"true", "false"}

CSV_INSTRUCTIONS = [
    "# INSTRUCTIONS — delete these comment rows before uploading",
    "# asset_type: must be one of: " + ", ".join(VALID_ASSET_TYPES),
    "# scope_status: must be one of: " + ", ".join(VALID_SCOPE_STATUSES),
    "# is_cde / stores_pan / processes_pan / transmits_pan: must be: true or false",
    "# tags: semicolon-separated list, e.g. pci;prod;dmz (leave blank if none)",
    "# All fields are required (tags may be empty).",
]


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


@router.get("/csv-template")
def download_csv_template(assessment_id: str, db: Session = Depends(get_db)):
    _get_assessment_or_404(assessment_id, db)
    buf = io.StringIO()
    writer = csv.writer(buf)
    for line in CSV_INSTRUCTIONS:
        writer.writerow([line])
    writer.writerow(CSV_FIELDS)
    writer.writerow([
        "Payment DB", "10.0.1.5", "pay-db-01.internal", "database", "in_scope",
        "true", "true", "false", "true", "N/A", "Handles all PAN transactions", "pci;prod",
    ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets_template.csv"},
    )


@router.post("/csv-import", status_code=201)
def import_csv(
    assessment_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    _get_assessment_or_404(assessment_id, db)

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=422, detail="File must be a .csv")

    content = file.file.read().decode("utf-8-sig")
    reader = csv.DictReader(
        line for line in content.splitlines() if not line.strip().startswith("#")
    )

    missing = set(CSV_FIELDS) - set(reader.fieldnames or [])
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"CSV is missing required columns: {', '.join(sorted(missing))}",
        )

    errors = []
    rows = []
    for i, row in enumerate(reader, start=1):
        row_errors = []

        # Required text fields
        for field in ("name", "ip_address", "hostname", "segmentation_notes", "justification"):
            if not row.get(field, "").strip():
                row_errors.append(f"'{field}' is required")

        # Enum fields
        asset_type = row.get("asset_type", "").strip()
        if asset_type not in VALID_ASSET_TYPES:
            row_errors.append(
                f"'asset_type' value '{asset_type}' is invalid. "
                f"Must be one of: {', '.join(VALID_ASSET_TYPES)}"
            )

        scope_status = row.get("scope_status", "").strip()
        if scope_status not in VALID_SCOPE_STATUSES:
            row_errors.append(
                f"'scope_status' value '{scope_status}' is invalid. "
                f"Must be one of: {', '.join(VALID_SCOPE_STATUSES)}"
            )

        # Boolean fields
        for bool_field in ("is_cde", "stores_pan", "processes_pan", "transmits_pan"):
            val = row.get(bool_field, "").strip().lower()
            if val not in VALID_BOOLS:
                row_errors.append(
                    f"'{bool_field}' value '{row.get(bool_field, '')}' is invalid. "
                    "Must be: true or false"
                )

        if row_errors:
            errors.append(f"Row {i}: " + "; ".join(row_errors))
        else:
            tags_raw = row.get("tags", "").strip()
            tags = [t.strip() for t in tags_raw.split(";") if t.strip()] if tags_raw else []
            rows.append(
                models.Asset(
                    assessment_id=assessment_id,
                    name=row["name"].strip(),
                    ip_address=row["ip_address"].strip(),
                    hostname=row["hostname"].strip(),
                    asset_type=models.AssetType(asset_type),
                    scope_status=models.ScopeStatus(scope_status),
                    is_cde=row["is_cde"].strip().lower() == "true",
                    stores_pan=row["stores_pan"].strip().lower() == "true",
                    processes_pan=row["processes_pan"].strip().lower() == "true",
                    transmits_pan=row["transmits_pan"].strip().lower() == "true",
                    segmentation_notes=row["segmentation_notes"].strip(),
                    justification=row["justification"].strip(),
                    tags=tags,
                )
            )

    if errors:
        raise HTTPException(status_code=422, detail={"errors": errors})

    if not rows:
        raise HTTPException(status_code=422, detail="CSV contains no data rows")

    db.add_all(rows)
    db.commit()
    for asset in rows:
        db.refresh(asset)
    return rows


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
