"""empty message

Revision ID: a71521b218f9
Revises: d589965694df
Create Date: 2023-11-03 17:37:31.034809

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a71521b218f9'
down_revision = 'd589965694df'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=1000),
               existing_nullable=False)
        batch_op.alter_column('level',
               existing_type=sa.VARCHAR(length=128),
               type_=sa.String(length=320),
               existing_nullable=False)
        batch_op.alter_column('matno',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=320),
               existing_nullable=False)
        batch_op.alter_column('verification_code',
               existing_type=sa.VARCHAR(length=20),
               type_=sa.String(length=120),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('verification_code',
               existing_type=sa.String(length=120),
               type_=sa.VARCHAR(length=20),
               existing_nullable=True)
        batch_op.alter_column('matno',
               existing_type=sa.String(length=320),
               type_=sa.VARCHAR(length=255),
               existing_nullable=False)
        batch_op.alter_column('level',
               existing_type=sa.String(length=320),
               type_=sa.VARCHAR(length=128),
               existing_nullable=False)
        batch_op.alter_column('password',
               existing_type=sa.String(length=1000),
               type_=sa.VARCHAR(length=255),
               existing_nullable=False)

    # ### end Alembic commands ###
