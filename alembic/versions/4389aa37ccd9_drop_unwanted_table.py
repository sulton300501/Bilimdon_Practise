"""drop unwanted table

Revision ID: 4389aa37ccd9
Revises: 42cb844f804b
Create Date: 2025-04-11 14:44:36.149358

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4389aa37ccd9'
down_revision: Union[str, None] = '42cb844f804b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
