"""add default

Revision ID: 021371e8dfee
Revises: 3ac6a4af617e
Create Date: 2018-03-16 14:13:41.327255

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '021371e8dfee'
down_revision = '3ac6a4af617e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('roles', sa.Column('default', sa.Boolean(), nullable=True))
    op.add_column('roles', sa.Column('permissions', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_roles_default'), 'roles', ['default'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_default'), table_name='roles')
    op.drop_column('roles', 'permissions')
    op.drop_column('roles', 'default')
    # ### end Alembic commands ###
