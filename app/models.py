

from app import db 
from flask import Flask # You can remove this line if Flask is not directly used here
from flask_sqlalchemy import SQLAlchemy # This import can also be removed if db is imported from 'app'
from flask_migrate import Migrate # This import can also be removed
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import Enum, event
from sqlalchemy.orm import validates
from sqlalchemy.dialects.mysql import SMALLINT, TINYINT, INTEGER, BIGINT
from sqlalchemy import LargeBinary
from io import BytesIO
import base64



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
    permission_name = db.Column(db.String(50), nullable=False, unique=True)

    roles = db.relationship('Role', secondary=role_permission, back_populates='permissions')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(97), nullable=False) # Length 97 for bcrypt hashes
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True) # For account activation/deactivation

    # Foreign key for role
    role_id = db.Column(SMALLINT(unsigned=True), db.ForeignKey('roles.role_id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

    # Relationships to profiles
    user_profile = db.relationship('UserProfile', back_populates='user', uselist=False, cascade='all, delete-orphan')
    admin_profile = db.relationship('AdminProfile', back_populates='admin', uselist=False, cascade='all, delete-orphan')

    # Relationships to items and notifications
    items = db.relationship('Item', back_populates='owner', lazy='dynamic')
    notifications = db.relationship('Notification', back_populates='user', lazy='dynamic')


    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    # Flask-Login integration
    def get_id(self):
        return str(self.user_id)

    @property
    def is_admin(self):
        return self.role and self.role.is_admin

    @property
    def is_regular_user(self):
        return self.role and not self.role.is_admin

    def __repr__(self):
        return f"<User {self.email}>"

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    profile_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    user_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), unique=True, nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    contact_phone = db.Column(db.String(20))
    contact_email = db.Column(db.String(100)) # Could be same as user.email or different

    user = db.relationship('User', back_populates='user_profile')

    def __repr__(self):
        return f"<UserProfile for User {self.user_id}>"

@event.listens_for(UserProfile, 'before_insert')
@event.listens_for(UserProfile, 'before_update')
def validate_user_type(mapper, connection, target):
    user = db.session.get(User, target.user_id)
    if user.is_admin:
        raise ValueError('Admin users cannot have a UserProfile.')

class AdminProfile(db.Model):
    __tablename__ = 'admin_profiles'
    profile_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    admin_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), unique=True, nullable=False)
    # Additional admin-specific fields like 'department', 'extension_number'
    
    admin = db.relationship('User', back_populates='admin_profile')

    def __repr__(self):
        return f"<AdminProfile for Admin {self.admin_id}>"

@event.listens_for(AdminProfile, 'before_insert')
@event.listens_for(AdminProfile, 'before_update')
def validate_admin_profile(mapper, connection, target):
    user = db.session.get(User, target.admin_id)
    if not user.is_admin:
        raise ValueError('Only admin users can have an AdminProfile.')

class AdminAuditLog(db.Model):
    __tablename__ = 'admin_audit_logs'
    log_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    admin_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    admin = db.relationship('User', backref=db.backref('audit_logs', lazy=True))

    def __repr__(self):
        return f"<AdminAuditLog {self.log_id}: {self.action}>"

class Item(db.Model):
    __tablename__ = 'items'
    item_id = db.Column(INTEGER(unsigned=True), primary_key=True)
    user_id = db.Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    item_type = db.Column(Enum('lost', 'found', name='item_types'), nullable=False) # 'lost' or 'found'
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(Enum('electronics', 'documents', 'clothing', 'accessories', 'other', name='item_categories'))
    location = db.Column(db.String(100)) # Where it was lost/found
    item_date = db.Column(db.DateTime, default=datetime.utcnow) # When it was lost/found
    status = db.Column(Enum('pending', 'recovered', 'claimed', name='item_statuses'), default='pending')
    image_path = db.Column(db.String(255))
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
        raise ValueError('Only admin users can have an AdminProfile.')

# Add this event listener to UserProfile as well
@event.listens_for(UserProfile, 'before_insert')
@event.listens_for(UserProfile, 'before_update')
def validate_user_type(mapper, connection, target):
    user = db.session.get(User, target.user_id)
    if user.is_admin:
        raise ValueError('Admin users cannot have a UserProfile.')