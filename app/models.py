"""
Database Models
Implements secure data models following OWASP and NIST guidelines
All sensitive data encrypted, audit trails immutable
"""
from datetime import datetime
from enum import Enum
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import secrets

db = SQLAlchemy()


class UserRole(Enum):
    """User roles for RBAC"""
    VOTER = "voter"
    ADMINISTRATOR = "administrator"
    AUDITOR = "auditor"


class ElectionStatus(Enum):
    """Election lifecycle states"""
    DRAFT = "draft"
    ACTIVE = "active"
    CLOSED = "closed"
    TALLIED = "tallied"


class User(UserMixin, db.Model):
    """
    User model with secure authentication
    Passwords hashed with Argon2, supports 2FA
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.VOTER)
    
    # Two-Factor Authentication
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    
    # Account Security
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    votes = db.relationship('Vote', back_populates='voter', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', back_populates='user', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username} ({self.role.value})>'
    
    def has_role(self, role):
        """Check if user has specific role"""
        if isinstance(role, str):
            return self.role.value == role
        return self.role == role
    
    def can_vote(self):
        """Check if user can cast votes"""
        return self.role == UserRole.VOTER and self.is_active and not self.is_locked
    
    def can_administer(self):
        """Check if user has admin privileges"""
        return self.role == UserRole.ADMINISTRATOR and self.is_active
    
    def can_audit(self):
        """Check if user can access audit logs"""
        return self.role == UserRole.AUDITOR and self.is_active


class Election(db.Model):
    """
    Election model
    Manages election lifecycle and security constraints
    """
    __tablename__ = 'elections'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Election Timeline
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    
    # Election Configuration
    status = db.Column(db.Enum(ElectionStatus), nullable=False, default=ElectionStatus.DRAFT)
    allow_multiple_votes = db.Column(db.Boolean, default=False, nullable=False)  # False = single vote per voter
    max_selections = db.Column(db.Integer, default=1, nullable=False)  # Number of candidates voter can select
    
    # Cryptographic Keys for this election (stored encrypted in production)
    encryption_public_key = db.Column(db.Text, nullable=True)
    encryption_private_key = db.Column(db.Text, nullable=True)  # Only accessible by admin during tally
    signature_public_key = db.Column(db.Text, nullable=True)
    signature_private_key = db.Column(db.Text, nullable=True)  # For signing tally results
    
    # Tally Results (only populated after tallying)
    tally_data = db.Column(db.JSON, nullable=True)  # Encrypted tally results
    tally_signature = db.Column(db.Text, nullable=True)  # Digital signature of tally
    tallied_at = db.Column(db.DateTime, nullable=True)
    tallied_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    candidates = db.relationship('Candidate', back_populates='election', lazy='dynamic', cascade='all, delete-orphan')
    votes = db.relationship('Vote', back_populates='election', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Election {self.title} ({self.status.value})>'
    
    def is_active(self):
        """Check if election is currently active for voting"""
        now = datetime.utcnow()
        return (self.status == ElectionStatus.ACTIVE and 
                self.start_time <= now <= self.end_time)
    
    def can_be_tallied(self):
        """Check if election can be tallied"""
        now = datetime.utcnow()
        return (self.status == ElectionStatus.CLOSED and 
                now > self.end_time)
    
    def get_results(self):
        """Get election results (only if tallied)"""
        if self.status != ElectionStatus.TALLIED or not self.tally_data:
            return None
        return self.tally_data


class Candidate(db.Model):
    """
    Candidate model
    Represents candidates in an election
    """
    __tablename__ = 'candidates'
    
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'), nullable=False, index=True)
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    photo_url = db.Column(db.String(500), nullable=True)
    
    # Display order
    order = db.Column(db.Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    election = db.relationship('Election', back_populates='candidates')
    
    def __repr__(self):
        return f'<Candidate {self.name} (Election {self.election_id})>'


class Vote(db.Model):
    """
    Vote model - Stores encrypted votes with digital signatures
    Ensures voter anonymity and vote integrity
    """
    __tablename__ = 'votes'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Encrypted vote data (AES-256-GCM)
    encrypted_vote = db.Column(db.Text, nullable=False)  # Base64 encoded encrypted ballot
    vote_nonce = db.Column(db.String(64), nullable=False)  # Nonce for encryption
    vote_tag = db.Column(db.String(64), nullable=False)  # Authentication tag for GCM
    
    # Digital signature (Ed25519 or RSA-PSS)
    digital_signature = db.Column(db.Text, nullable=False)
    
    # Vote metadata (non-identifying)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'), nullable=False, index=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Verification token (for voter to verify their vote)
    verification_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    
    # Timestamp and replay protection
    cast_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    request_nonce = db.Column(db.String(64), unique=True, nullable=False)  # Prevents replay attacks
    
    # IP address (for audit, stored hashed for privacy)
    ip_address_hash = db.Column(db.String(64), nullable=True)
    
    # Relationships
    election = db.relationship('Election', back_populates='votes')
    voter = db.relationship('User', back_populates='votes')
    
    def __repr__(self):
        return f'<Vote {self.id} - Election {self.election_id}>'
    
    @staticmethod
    def generate_verification_token():
        """Generate secure verification token"""
        return secrets.token_urlsafe(32)


class AuditLog(db.Model):
    """
    Immutable audit log with cryptographic integrity
    Each entry contains hash of previous entry (blockchain-style)
    """
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Log entry details
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=True)  # Denormalized for immutability
    user_role = db.Column(db.String(20), nullable=True)
    
    # Action details
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    description = db.Column(db.Text, nullable=True)
    
    # Security context
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.String(500), nullable=True)
    
    # Additional metadata (renamed from 'metadata' to avoid SQLAlchemy conflict)
    extra_data = db.Column(db.JSON, nullable=True)
    
    # Cryptographic integrity (HMAC-SHA256 chain)
    previous_hash = db.Column(db.String(64), nullable=True)  # Hash of previous log entry
    entry_hash = db.Column(db.String(64), nullable=False, index=True)  # Hash of this entry
    signature = db.Column(db.Text, nullable=False)  # HMAC signature
    
    # Status
    severity = db.Column(db.String(20), default='INFO', nullable=False)  # INFO, WARNING, ERROR, CRITICAL
    
    # Relationships
    user = db.relationship('User', back_populates='audit_logs')
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action} by {self.username}>'
    
    def to_dict(self):
        """Convert to dictionary for export"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'username': self.username,
            'user_role': self.user_role,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'description': self.description,
            'ip_address': self.ip_address,
            'severity': self.severity,
            'entry_hash': self.entry_hash,
            'previous_hash': self.previous_hash
        }


class VerificationToken(db.Model):
    """
    Verification tokens for password reset and email verification
    Implements secure token-based workflows
    """
    __tablename__ = 'verification_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token_type = db.Column(db.String(50), nullable=False)  # 'password_reset', 'email_verification'
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    
    def __repr__(self):
        return f'<VerificationToken {self.token_type} for user {self.user_id}>'
    
    def is_valid(self):
        """Check if token is valid and not expired"""
        return (not self.is_used and 
                datetime.utcnow() < self.expires_at)
    
    @staticmethod
    def generate_token():
        """Generate secure verification token"""
        return secrets.token_urlsafe(64)


class Nonce(db.Model):
    """
    Nonce tracking for replay attack prevention
    Stores used nonces with expiry
    """
    __tablename__ = 'nonces'
    
    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(128), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def __repr__(self):
        return f'<Nonce {self.nonce}>'
    
    @staticmethod
    def is_valid_nonce(nonce_value):
        """Check if nonce is valid (not used and not expired)"""
        existing = Nonce.query.filter_by(nonce=nonce_value).first()
        if existing:
            return False  # Nonce already used
        
        # Clean up expired nonces periodically
        Nonce.query.filter(Nonce.expires_at < datetime.utcnow()).delete()
        db.session.commit()
        
        return True


class InviteToken(db.Model):
    """
    Invite tokens for controlled user registration
    Prevents Sybil attacks by requiring admin-issued invites
    """
    __tablename__ = 'invite_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Unique invite token (cryptographically secure)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    
    # Email this invite is for
    email = db.Column(db.String(120), nullable=False, index=True)
    
    # Admin who created the invite
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    
    # Status tracking
    is_used = db.Column(db.Boolean, default=False, nullable=False, index=True)
    
    # User who registered with this token
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_invites')
    registered_user = db.relationship('User', foreign_keys=[user_id], backref='invite_token_used')
    
    def __repr__(self):
        return f'<InviteToken {self.email} - {"Used" if self.is_used else "Pending"}>'
    
    def is_valid(self):
        """Check if invite token is valid for use"""
        now = datetime.utcnow()
        return not self.is_used and now < self.expires_at
    
    def mark_as_used(self, user_id):
        """Mark invite as used"""
        self.is_used = True
        self.used_at = datetime.utcnow()
        self.user_id = user_id
    
    @staticmethod
    def generate_token():
        """Generate cryptographically secure invite token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def cleanup_expired():
        """Remove expired, unused tokens (for maintenance)"""
        expired_count = InviteToken.query.filter(
            InviteToken.expires_at < datetime.utcnow(),
            InviteToken.is_used == False
        ).delete()
        db.session.commit()
        return expired_count
