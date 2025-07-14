import secrets
from datetime import datetime, timedelta
from app.extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Enum, event, UniqueConstraint, Column, Integer, String, Boolean, DateTime, Text, Date, JSON
from sqlalchemy.orm import validates, relationship, backref
from sqlalchemy.dialects.mysql import SMALLINT, INTEGER
from io import BytesIO
import base64
from flask import current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature


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
        permissions_to_seed = ['manage_users', 'manage_items', 'manage_claims', 'view_audit_logs', 'access_admin_dashboard', 'view_items']
        for perm_name in permissions_to_seed:
            if not Permission.query.filter_by(permission_name=perm_name).first():
                db.session.add(Permission(permission_name=perm_name))
        db.session.commit()

    def __repr__(self):
        return f"<Permission {self.permission_name}>"

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
            'admin': 'Administrator with full access.',
            'general_user': 'Standard user with basic functionalities.'
        }
        for name, desc in roles_to_seed.items():
            role = Role.query.filter_by(role_name=name).first()
            if not role:
                role = Role(role_name=name, description=desc)
                db.session.add(role)
                db.session.flush()

            if name == 'admin':
                all_perms = Permission.query.all()
                for perm in all_perms:
                    if perm not in role.permissions:
                        role.permissions.append(perm)
            elif name == 'general_user':
                view_items_perm = Permission.query.filter_by(permission_name='view_items').first()
                if view_items_perm and view_items_perm not in role.permissions:
                    role.permissions.append(view_items_perm)
        db.session.commit()

    def __repr__(self):
        return f"<Role {self.role_name}>"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    student_id = Column(String(20), unique=True, nullable=True)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)

    role_id = Column(SMALLINT(unsigned=True), db.ForeignKey('roles.role_id'), nullable=False)
    role = relationship('Role', back_populates='users')

    reported_items = relationship('Item', back_populates='reporter', lazy=True, cascade='all, delete-orphan')
    claims_made = relationship('Claim', foreign_keys='Claim.user_id', back_populates='claimant', lazy=True, cascade='all, delete-orphan')
    items_found_claimed_by_others = relationship('Claim', foreign_keys='Claim.finder_id', back_populates='finder', lazy=True)
    messages_sent = relationship('ClaimMessage', back_populates='sender', lazy=True, cascade='all, delete-orphan')
    reviews_given = relationship('ClaimReview', back_populates='reviewer', lazy=True, cascade='all, delete-orphan')
    admin_logs = relationship('AdminAuditLog', back_populates='admin', lazy=True, cascade='all, delete-orphan')
    notifications = relationship('Notification', back_populates='user', lazy=True, cascade='all, delete-orphan')

    @property
    def is_admin(self):
        return self.role and self.role.role_name == 'admin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.user_id)

    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.user_id}, salt='password-reset-salt', expires_sec=expires_sec)

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, salt='password-reset-salt', max_age=1800)
        except (SignatureExpired, BadTimeSignature):
            return None
        return User.query.get(data['user_id'])

    @validates('email')
    def validate_email(self, key, email):
        if not email:
            raise AssertionError('Email cannot be empty')
        if '@' not in email:
            raise AssertionError('Invalid email format')
        return email.lower()

    @validates('name')
    def validate_name(self, key, name):
        if not name:
            raise AssertionError('Name cannot be empty')
        return name

    @property
    def unread_notifications_count(self):
        return Notification.query.filter_by(user_id=self.user_id, is_read=False).count()

    def get_claim_for_item(self, item_id):
        """Helper to get a claim made by this user for a specific item."""
        return Claim.query.filter_by(user_id=self.user_id, item_id=item_id).first()

    def __repr__(self):
        return f"<User {self.email}>"

@event.listens_for(User, 'before_insert')
def set_default_user_role(mapper, connection, target):
    if target.role_id is None:
        general_user_role = Role.query.filter_by(role_name='general_user').first()
        if general_user_role:
            target.role_id = general_user_role.role_id
        else:
            current_app.logger.error("Default 'general_user' role not found during user creation.")
            raise Exception("Default user role not found. Please run 'flask seed_roles'.")


class Item(db.Model):
    __tablename__ = 'items'
    item_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    item_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=False)

    item_type = Column(String(10), nullable=False, default='found')
    location_found = Column(String(100), nullable=False)
    date_found = Column(Date, nullable=False)
    image_filename = Column(String(128), nullable=True)
    status = Column(String(20), default='active', nullable=False)

    posted_at = Column(DateTime, default=datetime.utcnow)

    image_features = Column(JSON, nullable=True)
    qr_code = Column(Text, nullable=True)

    user_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    reporter = relationship('User', back_populates='reported_items')

    claims = relationship('Claim', back_populates='item', lazy=True, cascade='all, delete-orphan')
    notifications = relationship('Notification', back_populates='item', lazy=True, cascade='all, delete-orphan')

    @property
    def active_claim(self):
        """Returns the first pending or under_review claim for this item."""
        return Claim.query.filter_by(item_id=self.item_id).filter(
            Claim.status.in_(['pending', 'under_review'])
        ).first()

    def __repr__(self):
        return f"<Item {self.item_id}: {self.item_name} ({self.item_type})>"

class Claim(db.Model):
    __tablename__ = 'claims'
    claim_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    item_id = Column(INTEGER(unsigned=True), db.ForeignKey('items.item_id'), nullable=False)
    user_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    claim_details = Column(Text, nullable=False)
    status = Column(String(20), default='pending', nullable=False)
    reported_at = Column(DateTime, default=datetime.utcnow)

    finder_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    proof_filename = Column(String(128), nullable=True)

    resolution_type = Column(String(50), nullable=True)
    admin_notes = Column(Text, nullable=True)
    resolved_by_admin_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    item = relationship('Item', back_populates='claims')

    claimant = relationship('User', foreign_keys=[user_id], back_populates='claims_made')
    finder = relationship('User', foreign_keys=[finder_id], back_populates='items_found_claimed_by_others')
    resolved_by_admin = relationship('User', foreign_keys=[resolved_by_admin_id], backref='claims_resolved_by_me', lazy=True)

    messages = relationship('ClaimMessage', back_populates='claim', lazy=True, cascade='all, delete-orphan')
    reviews = relationship('ClaimReview', back_populates='claim', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Claim {self.claim_id} for Item {self.item_id} by User {self.user_id}>"

class ClaimMessage(db.Model):
    __tablename__ = 'claim_messages'
    message_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    claim_id = Column(INTEGER(unsigned=True), db.ForeignKey('claims.claim_id'), nullable=False)
    sender_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    message_text = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    claim = relationship('Claim', back_populates='messages')
    sender = relationship('User', back_populates='messages_sent')

    def __repr__(self):
        return f"<ClaimMessage {self.message_id} on Claim {self.claim_id} by User {self.sender_id}>"

class ClaimReview(db.Model):
    __tablename__ = 'claim_reviews'
    review_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    claim_id = Column(INTEGER(unsigned=True), db.ForeignKey('claims.claim_id'), nullable=False)
    reviewer_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    rating = Column(SMALLINT(unsigned=True))
    review_text = Column(Text)
    reviewed_at = Column(DateTime, default=datetime.utcnow)

    claim = relationship('Claim', back_populates='reviews')
    reviewer = relationship('User', foreign_keys=[reviewer_id], back_populates='reviews_given')

    def __repr__(self):
        return f"<ClaimReview {self.review_id} for Claim {self.claim_id}>"

class AdminAuditLog(db.Model):
    __tablename__ = 'admin_audit_logs'

    log_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    admin_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    action = Column(String(128), nullable=False)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

    admin = relationship('User', back_populates='admin_logs')

    def __repr__(self):
        return f"<AdminAuditLog {self.log_id} by Admin {self.admin_id} - {self.action} at {self.timestamp}>"

class Notification(db.Model):
    __tablename__ = 'notifications'
    notification_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    user_id = Column(INTEGER(unsigned=True), db.ForeignKey('users.user_id'), nullable=False)
    item_id = Column(INTEGER(unsigned=True), db.ForeignKey('items.item_id'), nullable=True)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)

    user = relationship('User', back_populates='notifications')
    item = relationship('Item', back_populates='notifications')

    def __repr__(self):
        return f"<Notification {self.notification_id} for User {self.user_id}>"


@event.listens_for(Role.__table__, 'after_create')
def receive_after_create_role(target, connection, **kw):
    if not Permission.query.first():
        Permission.seed_permissions()
    Role.seed_roles()

@event.listens_for(Permission.__table__, 'after_create')
def receive_after_create_permission(target, connection, **kw):
    if not Permission.query.first():
        Permission.seed_permissions()
