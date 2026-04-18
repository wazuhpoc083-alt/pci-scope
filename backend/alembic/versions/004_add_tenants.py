"""add tenants table and tenant_id to assessments

Revision ID: 004
Revises: 003
Create Date: 2026-04-18

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LEGACY_TENANT_ID = "00000000-0000-0000-0000-000000000001"
LEGACY_TENANT_NAME = "__legacy__"
LEGACY_TENANT_SLUG = "__legacy__"


def upgrade() -> None:
    # Create tenants table
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Insert legacy tenant for existing rows
    op.execute(
        f"INSERT INTO tenants (id, name, slug) VALUES "
        f"('{LEGACY_TENANT_ID}', '{LEGACY_TENANT_NAME}', '{LEGACY_TENANT_SLUG}')"
    )

    # Add tenant_id to assessments (nullable first so backfill can run)
    op.add_column(
        "assessments",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=True),
    )

    # Backfill existing assessments to legacy tenant
    op.execute(
        f"UPDATE assessments SET tenant_id = '{LEGACY_TENANT_ID}' WHERE tenant_id IS NULL"
    )

    # Now make it non-nullable
    op.alter_column("assessments", "tenant_id", nullable=False)


def downgrade() -> None:
    op.drop_column("assessments", "tenant_id")
    op.drop_table("tenants")
