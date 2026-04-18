import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, JSON
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class AssetType(str, enum.Enum):
    server = "server"
    database = "database"
    network_device = "network_device"
    workstation = "workstation"
    cloud_service = "cloud_service"
    other = "other"


class ScopeStatus(str, enum.Enum):
    in_scope = "in_scope"
    connected = "connected"
    out_of_scope = "out_of_scope"
    pending = "pending"


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    assessments = relationship("Assessment", back_populates="tenant")


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False)
    organization = Column(String(255), nullable=False)
    pci_dss_version = Column(String(10), default="4.0")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_finalized = Column(Boolean, default=False)

    tenant = relationship("Tenant", back_populates="assessments")
    assets = relationship("Asset", back_populates="assessment", cascade="all, delete-orphan")
    reports = relationship("ScopeReport", back_populates="assessment", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id"), nullable=False)
    name = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    asset_type = Column(Enum(AssetType), nullable=False, default=AssetType.server)
    scope_status = Column(Enum(ScopeStatus), nullable=False, default=ScopeStatus.pending)
    is_cde = Column(Boolean, default=False)
    stores_pan = Column(Boolean, default=False)
    processes_pan = Column(Boolean, default=False)
    transmits_pan = Column(Boolean, default=False)
    segmentation_notes = Column(Text, nullable=True)
    justification = Column(Text, nullable=True)
    tags = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    assessment = relationship("Assessment", back_populates="assets")


class ScopeReport(Base):
    __tablename__ = "scope_reports"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id"), nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    summary = Column(JSON, nullable=True)
    report_json = Column(JSON, nullable=True)

    assessment = relationship("Assessment", back_populates="reports")


# ---------------------------------------------------------------------------
# Firewall Analysis Models
# ---------------------------------------------------------------------------

class FirewallVendor(str, enum.Enum):
    fortinet = "fortinet"
    iptables = "iptables"
    cisco_asa = "cisco_asa"
    palo_alto = "palo_alto"
    unknown = "unknown"


class GapSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class NodeScopeStatus(str, enum.Enum):
    cde = "cde"
    connected = "connected"
    security_providing = "security_providing"
    out_of_scope = "out_of_scope"
    unknown = "unknown"


class FirewallUpload(Base):
    """Stores a parsed firewall config upload linked to an assessment."""
    __tablename__ = "firewall_uploads"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(255), nullable=False)
    vendor = Column(Enum(FirewallVendor), nullable=False, default=FirewallVendor.unknown)
    raw_text = Column(Text, nullable=True)
    parse_errors = Column(JSON, default=list)
    rule_count = Column(Integer, default=0)
    interfaces = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    rules = relationship("FirewallRule", back_populates="upload", cascade="all, delete-orphan")
    analyses = relationship("FirewallScopeAnalysis", back_populates="upload", cascade="all, delete-orphan")


class FirewallRule(Base):
    """Normalized firewall rule extracted from an uploaded config."""
    __tablename__ = "firewall_rules"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    upload_id = Column(String(36), ForeignKey("firewall_uploads.id", ondelete="CASCADE"), nullable=False)
    policy_id = Column(String(64), nullable=True)
    name = Column(String(255), nullable=True)
    src_intf = Column(String(255), nullable=True)
    dst_intf = Column(String(255), nullable=True)
    src_addrs = Column(JSON, default=list)
    dst_addrs = Column(JSON, default=list)
    services = Column(JSON, default=list)
    action = Column(String(16), nullable=False, default="permit")
    nat = Column(Boolean, default=False)
    log_traffic = Column(Boolean, default=True)
    comment = Column(Text, nullable=True)
    raw = Column(JSON, nullable=True)

    upload = relationship("FirewallUpload", back_populates="rules")


class FirewallScopeAnalysis(Base):
    """Tracks one scope analysis run: seeds, scope nodes, answers, gap findings."""
    __tablename__ = "firewall_scope_analyses"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    upload_id = Column(String(36), ForeignKey("firewall_uploads.id", ondelete="CASCADE"), nullable=False)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    cde_seeds = Column(JSON, default=list)
    scope_nodes = Column(JSON, default=list)
    questions = Column(JSON, default=list)
    answers = Column(JSON, default=dict)
    gap_findings = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    upload = relationship("FirewallUpload", back_populates="analyses")
