"""firewall analysis tables

Revision ID: 002
Revises: 001
Create Date: 2026-04-15

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enum type idempotently — PostgreSQL does not support
    # "CREATE TYPE IF NOT EXISTS", so we use a DO block instead.
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE firewallvendor
                AS ENUM ('fortinet', 'iptables', 'cisco_asa', 'palo_alto', 'unknown');
        EXCEPTION
            WHEN duplicate_object THEN NULL;
        END $$;
        """
    )

    op.create_table(
        "firewall_uploads",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "assessment_id",
            sa.String(36),
            sa.ForeignKey("assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column(
            "vendor",
            sa.Enum(
                "fortinet", "iptables", "cisco_asa", "palo_alto", "unknown",
                name="firewallvendor",
                create_type=False,   # type already created above
            ),
            nullable=False,
            server_default="unknown",
        ),
        sa.Column("raw_text", sa.Text, nullable=True),
        sa.Column("parse_errors", postgresql.JSON, server_default="[]"),
        sa.Column("rule_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_firewall_uploads_assessment_id", "firewall_uploads", ["assessment_id"])

    op.create_table(
        "firewall_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "upload_id",
            sa.String(36),
            sa.ForeignKey("firewall_uploads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.String(64), nullable=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("src_intf", sa.String(255), nullable=True),
        sa.Column("dst_intf", sa.String(255), nullable=True),
        sa.Column("src_addrs", postgresql.JSON, server_default="[]"),
        sa.Column("dst_addrs", postgresql.JSON, server_default="[]"),
        sa.Column("services", postgresql.JSON, server_default="[]"),
        sa.Column("action", sa.String(16), nullable=False, server_default="permit"),
        sa.Column("nat", sa.Boolean, server_default="false"),
        sa.Column("log_traffic", sa.Boolean, server_default="true"),
        sa.Column("comment", sa.Text, nullable=True),
        sa.Column("raw", postgresql.JSON, nullable=True),
    )
    op.create_index("ix_firewall_rules_upload_id", "firewall_rules", ["upload_id"])

    op.create_table(
        "firewall_scope_analyses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "upload_id",
            sa.String(36),
            sa.ForeignKey("firewall_uploads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_id",
            sa.String(36),
            sa.ForeignKey("assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cde_seeds", postgresql.JSON, server_default="[]"),
        sa.Column("scope_nodes", postgresql.JSON, server_default="[]"),
        sa.Column("questions", postgresql.JSON, server_default="[]"),
        sa.Column("answers", postgresql.JSON, server_default="{}"),
        sa.Column("gap_findings", postgresql.JSON, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_firewall_scope_analyses_upload_id", "firewall_scope_analyses", ["upload_id"])
    op.create_index("ix_firewall_scope_analyses_assessment_id", "firewall_scope_analyses", ["assessment_id"])


def downgrade() -> None:
    op.drop_table("firewall_scope_analyses")
    op.drop_table("firewall_rules")
    op.drop_table("firewall_uploads")
    op.execute("DROP TYPE IF EXISTS firewallvendor")
