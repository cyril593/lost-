from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import Enum, event
from sqlalchemy.orm import validates
from sqlalchemy.dialects.mysql import SMALLINT, TINYINT, INTEGER, BIGINT
from sqlalchemy import LargeBinary
from io import BytesIO
import base64

db = SQLAlchemy()


# Association table for many-to-many role-permission
role_permission = db.Table(
    'role_permission',
    db.Column('role_id', SMALLINT(unsigned=True), db.ForeignKey('roles.role_id'), primary_key=True),
    db.Column('permission_id', SMALLINT(unsigned=True), db.ForeignKey('permissions.permission_id'), primary_key=True)
)

class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(SMALLINT(unsigned=True), primary_key=True)
    role_name = db.Column(db.String(50), nullable=False, unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    permissions = db.relationship('Permission', secondary=role_permission, back_populates='roles')

class Permission(db.Model):
    __tablename__ = 'permissions'
    permission_id = db.Column(SMALLINT(unsigned=True), primary_key=True)
    permission_key = db.Column(db.String(155), nullable=False, unique=True)

    roles = db.relationship('Role', secondary=role_permission, back_populates='permissions')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(97), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    role_id = db.Column(SMALLINT(unsigned=True), db.ForeignKey('roles.role_id'), nullable=False)
    two_factor_secret_key = db.Column(LargeBinary(32))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    role = db.relationship('Role', backref='users')
    admin_profile = db.relationship('AdminProfile', back_populates='admin', uselist=False, cascade='all, delete-orphan')
    user_profile = db.relationship('UserProfile', back_populates='user', uselist=False, cascade='all, delete-orphan')
    items = db.relationship('Item', back_populates='owner')
    notifications = db.relationship('Notification', back_populates='user')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return str(self.user_id)

    @validates('role_id')
    def validate_role(self, key, role_id):
        role = Role.query.get(role_id)
        if role and role.is_admin:
            if self.user_profile is not None:
                raise ValueError('Admins cannot have user profiles')
        return role_id

    @property
    def is_admin(self):
        return self.role and self.role.is_admin

class AdminProfile(db.Model):
    __tablename__ = 'admin_profiles'
    admin_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), primary_key=True)
    requires_2FA = db.Column(db.Boolean, default=True)

    admin = db.relationship('User', back_populates='admin_profile', uselist=False)

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    user_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), primary_key=True)
    student_id = db.Column(db.String(20), nullable=False)

    user = db.relationship('User', back_populates='user_profile', uselist=False)

class AdminAuditLog(db.Model):
    __tablename__ = 'admin_audit_log'
    log_id = db.Column(BIGINT(unsigned=True), primary_key=True)
    admin_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    action_type = db.Column(db.String(255), nullable=False)
    target_id = db.Column(INTEGER(unsigned=True))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    admin_user = db.relationship('User', backref='audit_logs')

class Item(db.Model):
    __tablename__ = 'items'
    item_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    user_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    item_type = db.Column(Enum('lost', 'found', name='item_types'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
    location = db.Column(db.String(100))
    item_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    image_path = db.Column(db.String(255))
    status = db.Column(Enum('pending', 'matched', 'claimed', 'resolved', name='item_status'), default='pending')
    qr_code = db.Column(db.Text, unique=True)

    owner = db.relationship('User', back_populates='items')

    __table_args__ = (
        db.Index('idx_title', 'title'),
        db.Index('idx_search', 'item_type', 'status', 'category'),
        db.Index('idx_items_location', 'location'),
        db.Index('idx_items_item_date', 'item_date')
    )

class Notification(db.Model):
    __tablename__ = 'notifications'
    notification_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    user_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(Enum('match', 'claim', 'system', name='notification_types'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='notifications')

@event.listens_for(AdminProfile, 'before_insert')
def validate_admin_profile(mapper, connection, target):
    user = db.session.get(User, target.admin_id)
    if not user.is_admin:
        raise ValueError('Only admin users can have admin profiles')
    # Remove this line: user.two_factor_enabled = True

@event.listens_for(UserProfile, 'before_insert')
def validate_user_type(mapper, connection, target):
    user = User.query.get(target.user_id)
    if user.role.role_name == 'admin':
        raise ValueError('Admins cannot have user profiles')