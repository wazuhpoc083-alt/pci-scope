"""add interfaces column to firewall_uploads

Revision ID: 003
Revises: 002
Create Date: 2026-04-16

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "firewall_uploads",
        sa.Column("interfaces", postgresql.JSON, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("firewall_uploads", "interfaces")
