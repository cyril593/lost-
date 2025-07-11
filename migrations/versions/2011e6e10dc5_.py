"""empty message

Revision ID: 2011e6e10dc5
Revises: 68be717acda1
Create Date: 2025-07-07 09:21:33.568952

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2011e6e10dc5'
down_revision = '68be717acda1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_unique_constraint('_email_uc', ['email'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_constraint('_email_uc', type_='unique')

    # ### end Alembic commands ###
