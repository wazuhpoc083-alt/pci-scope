from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel
from app.models import AssetType, FirewallVendor, ScopeStatus


class AssessmentCreate(BaseModel):
    tenant_id: Optional[str] = None  # admin only: override target tenant
    name: str
    organization: str
    pci_dss_version: str = "4.0"
    description: Optional[str] = None


class AssessmentOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    organization: str
    pci_dss_version: str
    description: Optional[str]
    is_finalized: bool
    created_at: datetime

    class Config:
        from_attributes = True


class AssetCreate(BaseModel):
    name: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    asset_type: AssetType = AssetType.server
    scope_status: ScopeStatus = ScopeStatus.pending
    is_cde: bool = False
    stores_pan: bool = False
    processes_pan: bool = False
    transmits_pan: bool = False
    segmentation_notes: Optional[str] = None
    justification: Optional[str] = None
    tags: list[str] = []


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    asset_type: Optional[AssetType] = None
    scope_status: Optional[ScopeStatus] = None
    is_cde: Optional[bool] = None
    stores_pan: Optional[bool] = None
    processes_pan: Optional[bool] = None
    transmits_pan: Optional[bool] = None
    segmentation_notes: Optional[str] = None
    justification: Optional[str] = None
    tags: Optional[list[str]] = None


class AssetOut(BaseModel):
    id: str
    assessment_id: str
    name: str
    ip_address: Optional[str]
    hostname: Optional[str]
    asset_type: AssetType
    scope_status: ScopeStatus
    is_cde: bool
    stores_pan: bool
    processes_pan: bool
    transmits_pan: bool
    segmentation_notes: Optional[str]
    justification: Optional[str]
    tags: list
    created_at: datetime

    class Config:
        from_attributes = True


class ReportOut(BaseModel):
    id: str
    assessment_id: str
    generated_at: datetime
    summary: Optional[dict]
    report_json: Optional[dict]

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Firewall Analysis Schemas
# ---------------------------------------------------------------------------

class FirewallUploadOut(BaseModel):
    id: str
    assessment_id: str
    filename: str
    vendor: FirewallVendor
    parse_errors: list
    rule_count: int
    interfaces: dict = {}
    created_at: datetime

    class Config:
        from_attributes = True


class FirewallRuleOut(BaseModel):
    id: str
    upload_id: str
    policy_id: Optional[str]
    name: Optional[str]
    src_intf: Optional[str]
    dst_intf: Optional[str]
    src_addrs: list
    dst_addrs: list
    services: list
    action: str
    nat: bool
    log_traffic: bool
    comment: Optional[str]

    class Config:
        from_attributes = True


class AnalyzeRequest(BaseModel):
    upload_id: str
    cde_seeds: list[str] = []
    subnet_classifications: dict[str, str] = {}


class AnswersRequest(BaseModel):
    answers: dict[str, str]


class FirewallAnalysisOut(BaseModel):
    id: str
    upload_id: str
    assessment_id: str
    cde_seeds: list
    scope_nodes: list
    questions: list
    answers: dict
    gap_findings: list
    created_at: datetime

    class Config:
        from_attributes = True
