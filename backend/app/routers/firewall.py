"""
Firewall analysis router.

Endpoints under /api/assessments/{assessment_id}/firewall/:

  POST   /upload           — upload + parse a firewall config file
  GET    /uploads          — list uploads for this assessment
  GET    /uploads/{id}/rules — list parsed rules for an upload
  POST   /analyze          — run scope classification + gap analysis
  GET    /analysis         — get latest analysis for this assessment
  PATCH  /analysis/answers — submit question answers → re-run analysis
  GET    /export/csv       — CSV export of gap findings + scope nodes
"""

from __future__ import annotations

import csv
import io
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import TokenClaims, get_current_claims
from app.database import get_db
from app.gap_engine import extract_answer_driven_cde_seeds, run_gap_analysis
from app.parsers import parse_cisco_asa, parse_fortinet, parse_iptables, parse_palo_alto
from app.routers._helpers import get_assessment_for_claims
from app.scope_engine import classify_scope

router = APIRouter(
    prefix="/assessments/{assessment_id}/firewall",
    tags=["firewall"],
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# Vendor detection
# ---------------------------------------------------------------------------

def _detect_vendor(filename: str, text: str) -> models.FirewallVendor:
    fn = filename.lower()
    if "fortinet" in fn or "fortigate" in fn or "forti" in fn:
        return models.FirewallVendor.fortinet
    if "iptables" in fn or "nftables" in fn:
        return models.FirewallVendor.iptables
    if "cisco" in fn or "asa" in fn:
        return models.FirewallVendor.cisco_asa
    if "paloalto" in fn or "palo" in fn or "panorama" in fn:
        return models.FirewallVendor.palo_alto
    if "config firewall policy" in text or "set srcintf" in text:
        return models.FirewallVendor.fortinet
    if "-A INPUT" in text or "-A FORWARD" in text or "iptables" in text.lower():
        return models.FirewallVendor.iptables
    if "access-list" in text.lower() and "permit" in text.lower():
        return models.FirewallVendor.cisco_asa
    return models.FirewallVendor.unknown


def _parse_config(vendor: models.FirewallVendor, text: str) -> dict:
    if vendor == models.FirewallVendor.fortinet:
        return parse_fortinet(text)
    if vendor == models.FirewallVendor.iptables:
        return parse_iptables(text)
    if vendor == models.FirewallVendor.palo_alto:
        return parse_palo_alto(text)
    if vendor == models.FirewallVendor.cisco_asa:
        return parse_cisco_asa(text)
    return parse_fortinet(text)


# ---------------------------------------------------------------------------
# Upload + parse
# ---------------------------------------------------------------------------

@router.post("/upload", response_model=schemas.FirewallUploadOut, status_code=201)
async def upload_firewall_config(
    assessment_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")

    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as text")

    vendor = _detect_vendor(file.filename or "", text)
    try:
        parsed = _parse_config(vendor, text)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse firewall config: {exc}")

    upload = models.FirewallUpload(
        id=str(uuid.uuid4()),
        assessment_id=assessment_id,
        filename=file.filename or "upload.txt",
        vendor=vendor,
        raw_text=text,
        parse_errors=parsed.get("parse_errors", []),
        rule_count=len(parsed.get("rules", [])),
        interfaces=parsed.get("interfaces", {}),
    )
    db.add(upload)
    db.flush()

    for rule_data in parsed.get("rules", []):
        rule = models.FirewallRule(
            id=str(uuid.uuid4()),
            upload_id=upload.id,
            policy_id=rule_data.get("policy_id"),
            name=rule_data.get("name"),
            src_intf=rule_data.get("src_intf"),
            dst_intf=rule_data.get("dst_intf"),
            src_addrs=rule_data.get("src_addrs", []),
            dst_addrs=rule_data.get("dst_addrs", []),
            services=rule_data.get("services", []),
            action=rule_data.get("action", "permit"),
            nat=rule_data.get("nat", False),
            log_traffic=rule_data.get("log_traffic", True),
            comment=rule_data.get("comment"),
            raw=rule_data.get("raw"),
        )
        db.add(rule)

    db.commit()
    db.refresh(upload)
    return upload


@router.get("/uploads", response_model=list[schemas.FirewallUploadOut])
def list_uploads(
    assessment_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)
    return (
        db.query(models.FirewallUpload)
        .filter(models.FirewallUpload.assessment_id == assessment_id)
        .order_by(models.FirewallUpload.created_at.desc())
        .all()
    )


@router.get("/uploads/{upload_id}/rules", response_model=list[schemas.FirewallRuleOut])
def list_rules(
    assessment_id: str,
    upload_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)
    upload = (
        db.query(models.FirewallUpload)
        .filter(
            models.FirewallUpload.id == upload_id,
            models.FirewallUpload.assessment_id == assessment_id,
        )
        .first()
    )
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")
    return db.query(models.FirewallRule).filter(models.FirewallRule.upload_id == upload_id).all()


# ---------------------------------------------------------------------------
# Analyze: scope + gaps
# ---------------------------------------------------------------------------

@router.post("/analyze", response_model=schemas.FirewallAnalysisOut, status_code=201)
def analyze(
    assessment_id: str,
    payload: schemas.AnalyzeRequest,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)

    upload = (
        db.query(models.FirewallUpload)
        .filter(
            models.FirewallUpload.id == payload.upload_id,
            models.FirewallUpload.assessment_id == assessment_id,
        )
        .first()
    )
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    rules = db.query(models.FirewallRule).filter(models.FirewallRule.upload_id == upload.id).all()
    rule_dicts = [
        {
            "policy_id": r.policy_id,
            "name": r.name,
            "src_intf": r.src_intf,
            "dst_intf": r.dst_intf,
            "src_addrs": r.src_addrs or [],
            "dst_addrs": r.dst_addrs or [],
            "services": r.services or [],
            "action": r.action,
            "nat": r.nat,
            "log_traffic": r.log_traffic,
            "comment": r.comment,
        }
        for r in rules
    ]

    interface_table: dict = {}
    if upload.raw_text and upload.vendor in (
        models.FirewallVendor.fortinet, models.FirewallVendor.palo_alto, models.FirewallVendor.cisco_asa
    ):
        parsed = _parse_config(upload.vendor, upload.raw_text)
        interface_table = parsed.get("interfaces", {})

    cde_seeds = list(payload.cde_seeds or [])
    for subnet, status in (payload.subnet_classifications or {}).items():
        if status == "cde" and subnet not in cde_seeds:
            cde_seeds.append(subnet)

    scope_nodes = classify_scope(rule_dicts, cde_seeds, interface_table)

    if payload.subnet_classifications:
        for node in scope_nodes:
            node_cidr = node.get("ip", "")
            override = payload.subnet_classifications.get(node_cidr)
            if override and override != "cde":
                status_map = {
                    "connected": "connected",
                    "out_of_scope": "out_of_scope",
                    "outofscope": "out_of_scope",
                    "pending": "unknown",
                }
                node["scope_status"] = status_map.get(override, override)

    gap_result = run_gap_analysis(rule_dicts, cde_seeds, scope_nodes)

    existing = (
        db.query(models.FirewallScopeAnalysis)
        .filter(
            models.FirewallScopeAnalysis.upload_id == upload.id,
            models.FirewallScopeAnalysis.assessment_id == assessment_id,
        )
        .first()
    )

    if existing:
        existing.cde_seeds = cde_seeds
        existing.scope_nodes = scope_nodes
        existing.questions = gap_result["questions"]
        existing.gap_findings = gap_result["gap_findings"]
        existing.answers = {}
        analysis = existing
    else:
        analysis = models.FirewallScopeAnalysis(
            id=str(uuid.uuid4()),
            upload_id=upload.id,
            assessment_id=assessment_id,
            cde_seeds=cde_seeds,
            scope_nodes=scope_nodes,
            questions=gap_result["questions"],
            answers={},
            gap_findings=gap_result["gap_findings"],
        )
        db.add(analysis)

    db.commit()
    db.refresh(analysis)
    return analysis


@router.get("/analysis", response_model=schemas.FirewallAnalysisOut)
def get_analysis(
    assessment_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)
    analysis = (
        db.query(models.FirewallScopeAnalysis)
        .filter(models.FirewallScopeAnalysis.assessment_id == assessment_id)
        .order_by(models.FirewallScopeAnalysis.created_at.desc())
        .first()
    )
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found for this assessment")
    return analysis


@router.patch("/analysis/answers", response_model=schemas.FirewallAnalysisOut)
def submit_answers(
    assessment_id: str,
    payload: schemas.AnswersRequest,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)
    analysis = (
        db.query(models.FirewallScopeAnalysis)
        .filter(models.FirewallScopeAnalysis.assessment_id == assessment_id)
        .order_by(models.FirewallScopeAnalysis.created_at.desc())
        .first()
    )
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found")

    current_answers = dict(analysis.answers or {})
    current_answers.update(payload.answers)
    analysis.answers = current_answers

    existing_questions = list(analysis.questions or [])
    extra_seeds = extract_answer_driven_cde_seeds(existing_questions, current_answers)
    cde_seeds = list(analysis.cde_seeds or [])
    for seed in extra_seeds:
        if seed not in cde_seeds:
            cde_seeds.append(seed)

    rule_dicts = []
    interface_table: dict = {}
    upload = (
        db.query(models.FirewallUpload)
        .filter(models.FirewallUpload.id == analysis.upload_id)
        .first()
    )
    if upload:
        rules = db.query(models.FirewallRule).filter(models.FirewallRule.upload_id == upload.id).all()
        rule_dicts = [
            {
                "policy_id": r.policy_id,
                "name": r.name,
                "src_intf": r.src_intf,
                "dst_intf": r.dst_intf,
                "src_addrs": r.src_addrs or [],
                "dst_addrs": r.dst_addrs or [],
                "services": r.services or [],
                "action": r.action,
                "nat": r.nat,
                "log_traffic": r.log_traffic,
                "comment": r.comment,
            }
            for r in rules
        ]
        if upload.raw_text and upload.vendor in (
            models.FirewallVendor.fortinet, models.FirewallVendor.palo_alto, models.FirewallVendor.cisco_asa
        ):
            parsed = _parse_config(upload.vendor, upload.raw_text)
            interface_table = parsed.get("interfaces", {})

    if rule_dicts:
        scope_nodes = classify_scope(rule_dicts, cde_seeds, interface_table)
        gap_result = run_gap_analysis(
            rule_dicts,
            cde_seeds,
            scope_nodes,
            answers=current_answers,
            questions=existing_questions,
        )
        analysis.cde_seeds = cde_seeds
        analysis.scope_nodes = scope_nodes
        analysis.gap_findings = gap_result["gap_findings"]

    db.commit()
    db.refresh(analysis)
    return analysis


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

@router.get("/export/csv")
def export_csv(
    assessment_id: str,
    db: Session = Depends(get_db),
    claims: TokenClaims = Depends(get_current_claims),
):
    get_assessment_for_claims(assessment_id, db, claims)

    analysis = (
        db.query(models.FirewallScopeAnalysis)
        .filter(models.FirewallScopeAnalysis.assessment_id == assessment_id)
        .order_by(models.FirewallScopeAnalysis.created_at.desc())
        .first()
    )
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found")

    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["## Scope Classification"])
    writer.writerow(["IP / CIDR", "Scope Status", "Label", "Connected via Rules"])
    for node in analysis.scope_nodes or []:
        writer.writerow([
            node.get("ip", ""),
            node.get("scope_status", ""),
            node.get("label", ""),
            "; ".join(node.get("rule_ids", [])),
        ])

    writer.writerow([])

    writer.writerow(["## Gap Analysis Findings"])
    writer.writerow(["Severity", "Requirement", "Title", "Affected Rules", "Remediation"])
    for finding in analysis.gap_findings or []:
        writer.writerow([
            finding.get("severity", ""),
            finding.get("requirement", ""),
            finding.get("title", ""),
            "; ".join(finding.get("affected_rules", [])),
            finding.get("remediation", ""),
        ])

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=pci_scope_analysis.csv"},
    )
