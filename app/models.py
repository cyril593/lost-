import secrets
from datetime import datetime, timedelta
from app.extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Enum, event, UniqueConstraint, Column, Integer, String, Boolean, DateTime, Text, Date
from sqlalchemy.orm import validates, relationship
from sqlalchemy.dialects.mysql import SMALLINT, INTEGER
from io import BytesIO
import base64
from flask import current_app # Import current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature # Import itsdangerous

# Association table for many-to-many relationship between roles and permissions
role_permission = db.Table(
    'role_permission',
    db.Column('role_id', SMALLINT(unsigned=True), db.ForeignKey('roles.role_id', ondelete="CASCADE"), primary_key=True),
    db.Column('permission_id', SMALLINT(unsigned=True), db.ForeignKey('permissions.permission_id', ondelete="CASCADE"), primary_key=True)
)

class Permission(db.Model):
    __tablename__ = 'permissions'
    permission_id = Column(SMALLINT(unsigned=True), primary_key=True, autoincrement=True)
    permission_name = Column(String(64), unique=True, nullable=False)

    roles = relationship('Role', secondary=role_permission, back_populates='permissions')

    @staticmethod
    def seed_permissions():
        permissions_to_seed = ['manage_users', 'view_audit_logs', 'resolve_claims']
        for p_name in permissions_to_seed:
            if not Permission.query.filter_by(permission_name=p_name).first():
                db.session.add(Permission(permission_name=p_name))
        db.session.commit()

    def __repr__(self):
        return f"<Permission '{self.permission_name}'>"

class Role(db.Model):
    __tablename__ = 'roles'
    role_id = Column(SMALLINT(unsigned=True), primary_key=True, autoincrement=True)
    role_name = Column(String(64), unique=True, nullable=False)
    description = Column(String(255))

    users = relationship('User', back_populates='role')
    permissions = relationship('Permission', secondary=role_permission, back_populates='roles')

    @staticmethod
    def seed_roles():
        roles_to_seed = {
            'general_user': 'Standard user with basic access.',
            'admin': 'Administrator with full system access.'
        }
        for r_name, r_desc in roles_to_seed.items():
            if not Role.query.filter_by(role_name=r_name).first():
                role = Role(role_name=r_name, description=r_desc)
                db.session.add(role)
                # Assign permissions to admin role
                if r_name == 'admin':
                    manage_users_perm = Permission.query.filter_by(permission_name='manage_users').first()
                    view_audit_logs_perm = Permission.query.filter_by(permission_name='view_audit_logs').first()
                    resolve_claims_perm = Permission.query.filter_by(permission_name='resolve_claims').first()
                    if manage_users_perm:
                        role.permissions.append(manage_users_perm)
                    if view_audit_logs_perm:
                        role.permissions.append(view_audit_logs_perm)
                    if resolve_claims_perm:
                        role.permissions.append(resolve_claims_perm)
        db.session.commit()

    def has_permission(self, permission_name):
        return any(p.permission_name == permission_name for p in self.permissions)

    def __repr__(self):
        return f"<Role '{self.role_name}'>"

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256))
    student_id = Column(String(20), unique=True, nullable=True) # Made nullable to allow non-student users
    is_admin = Column(Boolean, default=False)
    registration_date = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True) # Added for user activation/deactivation
    role_id = Column(SMALLINT(unsigned=True), db.ForeignKey('roles.role_id'), nullable=False)

    # Relationships
    role = relationship('Role', back_populates='users')
    reported_items = relationship('Item', back_populates='reporter', lazy='dynamic', cascade='all, delete-orphan')
    claims = relationship('Claim', back_populates='user', lazy='dynamic', cascade='all, delete-orphan')
    messages_sent = relationship('ClaimMessage', foreign_keys='ClaimMessage.sender_id', back_populates='sender', lazy='dynamic')
    messages_received = relationship('ClaimMessage', foreign_keys='ClaimMessage.receiver_id', back_populates='receiver', lazy='dynamic')
    reviews_given = relationship('ClaimReview', back_populates='reviewer', lazy='dynamic', cascade='all, delete-orphan')
    admin_logs = relationship('AdminAuditLog', back_populates='admin', lazy='dynamic', cascade='all, delete-orphan')

    __table_args__ = (UniqueConstraint('email', name='_email_uc'),)

    @validates('email')
    def validate_email(self, key, email):
        if '@' not in email:
            raise ValueError("Email must contain '@'")
        return email.lower()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Flask-Login integration
    def get_id(self):
        return str(self.user_id)

    def is_active(self):
        return self.is_active

    # Secure password reset tokens
    def get_reset_token(self, expires_sec=1800): # 30 minutes
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.user_id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            user_id = data.get('user_id')
            if user_id is None:
                return None
        except (SignatureExpired, BadTimeSignature):
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"<User {self.email}>"

class Item(db.Model):
    __tablename__ = 'items'
    item_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    user_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False) # Reporter of the item
    item_name = Column(String(100), nullable=False) # e.g., "Blue Backpack"
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=False) # e.g., "Electronics", "Documents", "Clothing"
    item_type = Column(Enum('lost', 'found', name='item_types'), nullable=False) # 'lost' or 'found'
    location_found = Column(String(100), nullable=False) # Where the item was found/lost
    date_found = Column(Date, nullable=False) # When the item was found/lost
    image_filename = Column(String(128), nullable=True) # Filename of the uploaded image
    status = Column(Enum('pending', 'claimed', 'returned', 'archived', name='item_statuses'), default='pending', nullable=False) # e.g., 'pending', 'claimed', 'returned'
    reported_at = Column(DateTime, default=datetime.utcnow)
    qr_code_data = Column(db.Text, nullable=True) # Stores base64 encoded QR code image data

    # Relationships
    reporter = relationship('User', back_populates='reported_items')
    claims = relationship('Claim', back_populates='item', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def qr_code(self):
        """Decode base64 QR code data for displaying in templates."""
        return self.qr_code_data

    @qr_code.setter
    def qr_code(self, data):
        """Set base64 encoded QR code data."""
        self.qr_code_data = data

    def __repr__(self):
        return f"<Item {self.item_name} ({self.item_type})>"

class Claim(db.Model):
    __tablename__ = 'claims'
    claim_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    item_id = Column(INTEGER(unsigned=True), db.ForeignKey('items.item_id'), nullable=False)
    user_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False) # The user making the claim
    reason = Column(Text, nullable=False) # Reason for claiming, detailed description
    reported_at = Column(DateTime, default=datetime.utcnow)
    status = Column(Enum('pending', 'approved', 'rejected', 'resolved', name='claim_statuses'), default='pending', nullable=False) # e.g., 'pending', 'approved', 'rejected', 'resolved'
    resolved_at = Column(DateTime, nullable=True)
    resolution_type = Column(Enum('returned_to_owner', 'kept', 'donated', 'other', name='resolution_types'), nullable=True)
    admin_notes = Column(Text, nullable=True) # Notes added by admin during resolution

    # Relationships
    item = relationship('Item', back_populates='claims')
    user = relationship('User', back_populates='claims')
    messages = relationship('ClaimMessage', back_populates='claim', lazy='dynamic', cascade='all, delete-orphan')
    reviews = relationship('ClaimReview', back_populates='claim', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Claim {self.claim_id} for Item {self.item_id} by User {self.user_id}>"

class ClaimMessage(db.Model):
    __tablename__ = 'claim_messages'
    message_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    claim_id = Column(INTEGER(unsigned=True), db.ForeignKey('claims.claim_id'), nullable=False)
    sender_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    receiver_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False) # The other party in the conversation
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)
    
    claim = relationship('Claim', back_populates='messages')
    sender = relationship('User', foreign_keys=[sender_id], back_populates='messages_sent')
    receiver = relationship('User', foreign_keys=[receiver_id], back_populates='messages_received')

    def __repr__(self):
        return f"<ClaimMessage {self.message_id} (Claim {self.claim_id}) from {self.sender_id} to {self.receiver_id}>"


class ClaimReview(db.Model):
    __tablename__ = 'claim_reviews'
    
    review_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    claim_id = Column(INTEGER(unsigned=True), db.ForeignKey('claims.claim_id'), nullable=False)
    reviewer_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    rating = Column(SMALLINT, nullable=False)  # 1-5 scale
    comments = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    claim = relationship('Claim', back_populates='reviews')
    reviewer = relationship('User', foreign_keys=[reviewer_id], back_populates='reviews_given')

    def __repr__(self):
        return f"<ClaimReview {self.review_id} for Claim {self.claim_id}>"

class AdminAuditLog(db.Model):
    __tablename__ = 'admin_audit_logs'

    log_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    admin_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    action = Column(String(128), nullable=False) # e.g., "User created", "Item deleted", "Claim approved"
    details = Column(Text) # Additional context for the action
    timestamp = Column(DateTime, default=datetime.utcnow)

    admin = relationship('User', back_populates='admin_logs')

    def __repr__(self):
        return f"<AdminAuditLog {self.log_id} by Admin {self.admin_id} - {self.action} at {self.timestamp}>"

# Event listener to seed roles and permissions after tables are created
@event.listens_for(Role.__table__, 'after_create')
def receive_after_create_role(target, connection, **kw):
    # This ensures permissions exist before roles try to link to them
    Permission.seed_permissions()
    Role.seed_roles()

@event.listens_for(Permission.__table__, 'after_create')
def receive_after_create_permission(target, connection, **kw):
    # This might be redundant if Role seed calls Permission.seed_permissions,
    # but ensures permissions are there regardless of call order in initial setup
    Permission.seed_permissions()