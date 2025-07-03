"""empty message

Revision ID: 81e9aa8c20ec
Revises: 
Create Date: 2025-07-01 12:35:27.404976

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '81e9aa8c20ec'
down_revision = None
branch_labels = None
depends_on = None


from sqlalchemy import inspect

def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    if 'roles' not in inspector.get_table_names():
        op.create_table(
            'roles',
            sa.Column('role_id', mysql.TINYINT(unsigned=True), primary_key=True),
            sa.Column('role_name', sa.String(50), nullable=False),
            sa.UniqueConstraint('role_name')
        )
    op.create_table('users',
        sa.Column('user_id', mysql.INTEGER(unsigned=True), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password', sa.String(length=97), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('role_id', mysql.TINYINT(unsigned=True), nullable=False),
        sa.Column('two_factor_secret_key', mysql.BLOB(length=32), nullable=True),
        sa.Column('two_factor_enabled', sa.Boolean(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('user_id'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.role_id']),
        sa.UniqueConstraint('email')
    )
    
   
    op.create_table('admin_audit_log',
    sa.Column('log_id', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('admin_id', mysql.INTEGER(unsigned=True), nullable=False),
    sa.Column('action_type', sa.String(length=255), nullable=False),
    sa.Column('target_id', mysql.INTEGER(unsigned=True), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['admin_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('log_id')
    )
    op.create_table('admin_profiles',
    sa.Column('admin_id', mysql.INTEGER(unsigned=True), nullable=False),
    sa.Column('requires_2FA', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['admin_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('admin_id')
    )
    op.create_table('items',
    sa.Column('item_id', mysql.INTEGER(unsigned=True), nullable=False),
    sa.Column('user_id', mysql.INTEGER(unsigned=True), nullable=False),
    sa.Column('item_type', sa.Enum('lost', 'found', name='item_types'), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('category', sa.String(length=50), nullable=True),
    sa.Column('location', sa.String(length=100), nullable=True),
    sa.Column('item_date', sa.DateTime(), nullable=False),
    sa.Column('image_path', sa.String(length=255), nullable=True),
    sa.Column('status', sa.Enum('pending', 'matched', 'claimed', 'resolved', name='item_status'), nullable=True),
    sa.Column('qr_code', sa.String(length=100), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('item_id'),
    sa.UniqueConstraint('qr_code')
    )
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.create_index('idx_category', ['category'], unique=False)
        batch_op.create_index('idx_items_category', ['category'], unique=False)
        batch_op.create_index('idx_items_item_date', ['item_date'], unique=False)
        batch_op.create_index('idx_items_location', ['location'], unique=False)
        batch_op.create_index('idx_items_status', ['status'], unique=False)
        batch_op.create_index('idx_items_type', ['item_type'], unique=False)
        batch_op.create_index('idx_search', ['item_type', 'status', 'category'], unique=False)
        batch_op.create_index('idx_status', ['status'], unique=False)
        batch_op.create_index('idx_title', ['title'], unique=False)

    op.create_table('notifications',
    sa.Column('notification_id', mysql.INTEGER(unsigned=True), nullable=False),
    sa.Column('user_id', mysql.INTEGER(unsigned=True), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('type', sa.Enum('match', 'claim', 'system', name='notification_types'), nullable=False),
    sa.Column('is_read', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('notification_id')
    )
    op.create_table('user_profiles',
    sa.Column('user_id', mysql.INTEGER(unsigned=True), nullable=False),
    sa.Column('student_id', sa.String(length=20), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('user_id')
    )
    with op.batch_alter_table('permissions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('permission_key', sa.String(length=155), nullable=False))
        batch_op.drop_index(batch_op.f('permission_name'))
        batch_op.create_unique_constraint(None, ['permission_key'])
        batch_op.drop_column('permission_name')

    with op.batch_alter_table('role_permission', schema=None) as batch_op:
        batch_op.alter_column('role_id',
               existing_type=mysql.SMALLINT(display_width=5, unsigned=True),
               type_=mysql.TINYINT(unsigned=True),
               existing_nullable=False)

    with op.batch_alter_table('roles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_admin', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('roles', schema=None) as batch_op:
        batch_op.drop_column('is_admin')

    with op.batch_alter_table('role_permission', schema=None) as batch_op:
        batch_op.alter_column('role_id',
               existing_type=mysql.TINYINT(unsigned=True),
               type_=mysql.SMALLINT(display_width=5, unsigned=True),
               existing_nullable=False)

    with op.batch_alter_table('permissions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('permission_name', mysql.VARCHAR(length=100), nullable=False))
        batch_op.drop_constraint(None, type_='unique')
        batch_op.create_index(batch_op.f('permission_name'), ['permission_name'], unique=True)
        batch_op.drop_column('permission_key')

    op.drop_table('user_profiles')
    op.drop_table('notifications')
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_index('idx_title')
        batch_op.drop_index('idx_status')
        batch_op.drop_index('idx_search')
        batch_op.drop_index('idx_items_type')
        batch_op.drop_index('idx_items_status')
        batch_op.drop_index('idx_items_location')
        batch_op.drop_index('idx_items_item_date')
        batch_op.drop_index('idx_items_category')
        batch_op.drop_index('idx_category')

    op.drop_table('items')
    op.drop_table('admin_profiles')
    op.drop_table('admin_audit_log')
    op.drop_table('users')
    # ### end Alembic commands ###
