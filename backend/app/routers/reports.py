from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from app import models, schemas
from app.auth import TokenClaims, get_current_claims
from app.database import get_db
from app.report_builder import build_report_json, build_pdf
from app.routers._helpers import get_assessment_for_claims

router = APIRouter(prefix="/assessments/{assessment_id}/reports", tags=["reports"])


@router.post("/", response_model=schemas.ReportOut, status_code=201)
def generate_report(
    assessment_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    assessment = get_assessment_for_claims(assessment_id, db, claims)
    assets = db.query(models.Asset).filter(models.Asset.assessment_id == assessment_id).all()
    report_json = build_report_json(assessment, assets)

    summary = {
        "in_scope": sum(1 for a in assets if a.scope_status == models.ScopeStatus.in_scope),
        "connected": sum(1 for a in assets if a.scope_status == models.ScopeStatus.connected),
        "out_of_scope": sum(1 for a in assets if a.scope_status == models.ScopeStatus.out_of_scope),
        "pending": sum(1 for a in assets if a.scope_status == models.ScopeStatus.pending),
        "total": len(assets),
    }

    report = models.ScopeReport(
        assessment_id=assessment_id,
        summary=summary,
        report_json=report_json,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/", response_model=list[schemas.ReportOut])
def list_reports(
    assessment_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)
    return (
        db.query(models.ScopeReport)
        .filter(models.ScopeReport.assessment_id == assessment_id)
        .order_by(models.ScopeReport.generated_at.desc())
        .all()
    )


@router.get("/{report_id}/pdf")
def download_report_pdf(
    assessment_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)
    report = (
        db.query(models.ScopeReport)
        .filter(
            models.ScopeReport.id == report_id,
            models.ScopeReport.assessment_id == assessment_id,
        )
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_bytes = build_pdf(report)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=pci-scope-report-{report_id[:8]}.pdf"},
    )
