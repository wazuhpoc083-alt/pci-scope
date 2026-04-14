"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-04-14

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")

    op.create_table(
        "assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("organization", sa.String(255), nullable=False),
        sa.Column("pci_dss_version", sa.String(10), server_default="4.0"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_finalized", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), onupdate=sa.func.now(), nullable=True),
    )

    op.create_table(
        "assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column(
            "asset_type",
            sa.Enum("server", "database", "network_device", "workstation", "cloud_service", "other", name="assettype"),
            nullable=False,
            server_default="server",
        ),
        sa.Column(
            "scope_status",
            sa.Enum("in_scope", "connected", "out_of_scope", "pending", name="scopestatus"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("is_cde", sa.Boolean, server_default="false"),
        sa.Column("stores_pan", sa.Boolean, server_default="false"),
        sa.Column("processes_pan", sa.Boolean, server_default="false"),
        sa.Column("transmits_pan", sa.Boolean, server_default="false"),
        sa.Column("segmentation_notes", sa.Text, nullable=True),
        sa.Column("justification", sa.Text, nullable=True),
        sa.Column("tags", postgresql.JSON, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_assets_assessment_id", "assets", ["assessment_id"])

    op.create_table(
        "scope_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("summary", postgresql.JSON, nullable=True),
        sa.Column("report_json", postgresql.JSON, nullable=True),
    )
    op.create_index("ix_scope_reports_assessment_id", "scope_reports", ["assessment_id"])


def downgrade() -> None:
    op.drop_table("scope_reports")
    op.drop_table("assets")
    op.drop_table("assessments")
    op.execute("DROP TYPE IF EXISTS scopestatus")
    op.execute("DROP TYPE IF EXISTS assettype")
