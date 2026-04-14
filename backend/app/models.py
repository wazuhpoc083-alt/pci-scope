import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    String, Text, JSON
)
from sqlalchemy.dialects.postgresql import UUID
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


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    organization = Column(String(255), nullable=False)
    pci_dss_version = Column(String(10), default="4.0")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_finalized = Column(Boolean, default=False)

    assets = relationship("Asset", back_populates="assessment", cascade="all, delete-orphan")
    reports = relationship("ScopeReport", back_populates="assessment", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    assessment_id = Column(UUID(as_uuid=False), ForeignKey("assessments.id"), nullable=False)
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

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    assessment_id = Column(UUID(as_uuid=False), ForeignKey("assessments.id"), nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    summary = Column(JSON, nullable=True)  # counts by scope_status
    report_json = Column(JSON, nullable=True)

    assessment = relationship("Assessment", back_populates="reports")
