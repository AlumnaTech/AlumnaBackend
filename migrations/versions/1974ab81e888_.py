"""empty message

Revision ID: 1974ab81e888
Revises: 1c3baaf9f642
Create Date: 2023-11-03 16:20:40.952974

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1974ab81e888'
down_revision = '1c3baaf9f642'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('class_rep',
               existing_type=sa.BOOLEAN(),
               type_=sa.String(length=50),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('class_rep',
               existing_type=sa.String(length=50),
               type_=sa.BOOLEAN(),
               existing_nullable=False)

    # ### end Alembic commands ###
