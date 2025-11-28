"""
Security Utilities Module
Implements cryptographic operations, authentication helpers, and security functions
Following OWASP, NIST, and Secure-SDLC principles

Security Fixes Applied:
- VULN-008: Added remote syslog handler for audit log backup
- VULN-009: Signing keys now stored encrypted in database instead of filesystem
"""
import os
import hmac
import hashlib
import secrets
import base64
import logging
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import SysLogHandler
from flask import current_app, request, abort
from flask_login import current_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.backends import default_backend
import pyotp
import qrcode
from io import BytesIO
import re


# Initialize Argon2 password hasher (secure parameters)
ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Length of hash
    salt_len=16         # Length of salt
)


class PasswordManager:
    """Secure password hashing and verification using Argon2"""

    @staticmethod
    def hash_password(password):
        """Hash password using Argon2"""
        return ph.hash(password)

    @staticmethod
    def verify_password(password_hash, password):
        """Verify password against hash"""
        try:
            ph.verify(password_hash, password)
            # Check if rehashing is needed (parameters changed)
            if ph.check_needs_rehash(password_hash):
                return True, ph.hash(password)
            return True, None
        except (VerifyMismatchError, VerificationError, InvalidHash):
            return False, None

    @staticmethod
    def validate_password_strength(password):
        """
        Validate password meets security requirements
        Returns (is_valid, error_message)
        """
        min_length = current_app.config.get('PASSWORD_MIN_LENGTH', 12)

        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters long"

        if current_app.config.get('PASSWORD_REQUIRE_UPPERCASE', True):
            if not re.search(r'[A-Z]', password):
                return False, "Password must contain at least one uppercase letter"

        if current_app.config.get('PASSWORD_REQUIRE_LOWERCASE', True):
            if not re.search(r'[a-z]', password):
                return False, "Password must contain at least one lowercase letter"

        if current_app.config.get('PASSWORD_REQUIRE_DIGIT', True):
            if not re.search(r'\d', password):
                return False, "Password must contain at least one digit"

        if current_app.config.get('PASSWORD_REQUIRE_SPECIAL', True):
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                return False, "Password must contain at least one special character"

        # Check for common patterns
        common_passwords = ['password', '12345678', 'qwerty', 'admin']
        if password.lower() in common_passwords:
            return False, "Password is too common"

        return True, None


class VoteEncryption:
    """
    Vote encryption using AES-256-GCM
    Provides confidentiality and authenticity
    Note: New votes use hybrid RSA-AES encryption (see crypto_utils.py)
    """

    @staticmethod
    def encrypt_vote(vote_data, key=None):
        """
        Encrypt vote data using AES-256-GCM
        Returns (encrypted_data, nonce, tag) as base64 strings
        """
        if key is None:
            key = current_app.config['VOTE_ENCRYPTION_KEY']

        # Ensure key is 32 bytes for AES-256
        if len(key) != 32:
            key = hashlib.sha256(key).digest()

        # Generate random nonce (12 bytes for GCM)
        nonce = get_random_bytes(12)

        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Encrypt data
        vote_bytes = vote_data.encode('utf-8') if isinstance(vote_data, str) else vote_data
        ciphertext, tag = cipher.encrypt_and_digest(vote_bytes)

        # Return as base64 for storage
        return (
            base64.b64encode(ciphertext).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8')
        )

    @staticmethod
    def decrypt_vote(encrypted_data, nonce, tag, key=None, election_id=None):
        """
        Decrypt vote data using AES-256-GCM (legacy method)
        For new hybrid-encrypted votes, use CryptoUtils.decrypt_hybrid_vote()
        Returns decrypted data as string
        """
        if key is None:
            # Use same passphrase as client-side (vote-encrypt.js)
            password = b'SECURE_VOTING_SYSTEM_KEY_2024'

            # Try different salt patterns that client might use
            salt_patterns = [
                b'election_salt_/voter/election/',
            ]

            if election_id:
                salt_patterns.extend([
                    f'election_salt_/voter/election/{election_id}/vote'.encode('utf-8'),
                    f'election_salt_/voter/election/{election_id}'.encode('utf-8'),
                ])

            last_error = None
            for salt in salt_patterns:
                try:
                    from Crypto.Hash import SHA256
                    key = PBKDF2(
                        password,
                        salt,
                        dkLen=32,
                        count=100000,
                        hmac_hash_module=SHA256
                    )

                    ciphertext = base64.b64decode(encrypted_data)
                    nonce_bytes = base64.b64decode(nonce)
                    tag_bytes = base64.b64decode(tag)

                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag_bytes)
                    return plaintext.decode('utf-8')

                except ValueError as e:
                    last_error = e
                    continue

            raise ValueError("Vote decryption failed - data may be tampered") from last_error

        ciphertext = base64.b64decode(encrypted_data)
        nonce_bytes = base64.b64decode(nonce)
        tag_bytes = base64.b64decode(tag)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag_bytes)
            return plaintext.decode('utf-8')
        except ValueError as e:
            raise ValueError("Vote decryption failed - data may be tampered") from e


class DigitalSignature:
    """
    Digital signature operations using Ed25519
    Provides integrity and authenticity
    
    VULN-009 FIX: Keys are now stored encrypted in database
    Legacy file-based keys are supported for migration only
    """

    @staticmethod
    def generate_keypair():
        """Generate Ed25519 keypair"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def get_signing_key_from_db(key_name='primary'):
        """
        Get signing key from database (VULN-009 fix)
        Keys are stored encrypted using Fernet
        """
        from app.models import SigningKey
        from app.crypto_utils import CryptoUtils
        
        signing_key = SigningKey.query.filter_by(
            key_name=key_name,
            is_active=True
        ).first()
        
        if signing_key:
            try:
                private_key_pem = CryptoUtils.decrypt_private_key(
                    signing_key.encrypted_private_key
                )
                return private_key_pem, signing_key.public_key.encode('utf-8')
            except Exception:
                return None, None
        
        return None, None

    @staticmethod
    def create_signing_key_in_db(key_name='primary'):
        """
        Create new signing key and store encrypted in database
        """
        from app.models import SigningKey, db
        from app.crypto_utils import CryptoUtils
        
        # Generate new keypair
        private_pem, public_pem = DigitalSignature.generate_keypair()
        
        # Encrypt private key before storing
        encrypted_private = CryptoUtils.encrypt_private_key(private_pem)
        
        # Deactivate existing keys with same name
        SigningKey.query.filter_by(key_name=key_name, is_active=True).update(
            {'is_active': False}
        )
        
        # Create new signing key record
        signing_key = SigningKey(
            key_name=key_name,
            encrypted_private_key=encrypted_private,
            public_key=public_pem.decode('utf-8'),
            is_active=True
        )
        db.session.add(signing_key)
        db.session.commit()
        
        return private_pem, public_pem

    @staticmethod
    def sign_data(data, private_key_pem=None):
        """
        Sign data using Ed25519 private key
        Returns signature as base64 string
        
        Priority:
        1. Use provided private_key_pem
        2. Try to load from database (VULN-009 fix)
        3. Fall back to file system (legacy support)
        """
        if private_key_pem is None:
            # Try database first (new secure method)
            private_key_pem, _ = DigitalSignature.get_signing_key_from_db()
            
            if private_key_pem is None:
                # Fall back to file system (legacy)
                key_path = current_app.config.get('DIGITAL_SIGNATURE_PRIVATE_KEY_PATH')
                if key_path and os.path.exists(key_path):
                    with open(key_path, 'rb') as f:
                        private_key_pem = f.read()
                else:
                    # Generate new keypair and store in DB
                    private_key_pem, _ = DigitalSignature.create_signing_key_in_db()

        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

        # Sign data
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        signature = private_key.sign(data_bytes)

        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(data, signature_b64, public_key_pem=None):
        """
        Verify signature using Ed25519 public key
        Returns True if valid, False otherwise
        """
        try:
            if public_key_pem is None:
                # Try database first
                _, public_key_pem = DigitalSignature.get_signing_key_from_db()
                
                if public_key_pem is None:
                    # Fall back to file system
                    key_path = current_app.config.get('DIGITAL_SIGNATURE_PUBLIC_KEY_PATH')
                    if key_path and os.path.exists(key_path):
                        with open(key_path, 'rb') as f:
                            public_key_pem = f.read()
                    else:
                        return False

            # Load public key
            if isinstance(public_key_pem, str):
                public_key_pem = public_key_pem.encode('utf-8')
                
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )

            # Verify signature
            data_bytes = data.encode('utf-8') if isinstance(data, str) else data
            signature = base64.b64decode(signature_b64)

            public_key.verify(signature, data_bytes)
            return True
        except Exception:
            return False


class RemoteSyslogHandler:
    """
    Remote Syslog Handler for VULN-008 fix
    Sends audit logs to remote syslog server for backup
    """
    
    _handler = None
    
    @classmethod
    def get_handler(cls):
        """Get or create the syslog handler"""
        if cls._handler is None and current_app.config.get('SYSLOG_ENABLED'):
            try:
                facility = current_app.config.get_syslog_facility()
                cls._handler = SysLogHandler(
                    address=(
                        current_app.config.get('SYSLOG_HOST', 'localhost'),
                        current_app.config.get('SYSLOG_PORT', 514)
                    ),
                    facility=facility
                )
                cls._handler.setLevel(logging.INFO)
                formatter = logging.Formatter(
                    'SecureVotingSystem: %(message)s'
                )
                cls._handler.setFormatter(formatter)
            except Exception as e:
                current_app.logger.error(f"Failed to create syslog handler: {e}")
                return None
        return cls._handler
    
    @classmethod
    def log_to_syslog(cls, message):
        """Send log message to remote syslog"""
        handler = cls.get_handler()
        if handler:
            try:
                record = logging.LogRecord(
                    name='audit',
                    level=logging.INFO,
                    pathname='',
                    lineno=0,
                    msg=message,
                    args=(),
                    exc_info=None
                )
                handler.emit(record)
            except Exception as e:
                current_app.logger.error(f"Failed to send to syslog: {e}")


class AuditLogger:
    """
    Immutable audit logging with cryptographic integrity
    Each log entry contains HMAC of previous entry (blockchain-style)
    
    VULN-008 FIX: Now also sends logs to remote syslog for backup
    """

    @staticmethod
    def compute_entry_hash(entry_data):
        """Compute SHA-256 hash of log entry"""
        data_str = f"{entry_data['timestamp']}{entry_data['user_id']}{entry_data['action']}{entry_data['resource_id']}"
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()

    @staticmethod
    def sign_entry(entry_hash, previous_hash=None):
        """
        Sign log entry using HMAC-SHA256
        Creates chain by including previous hash
        """
        key = current_app.config['AUDIT_LOG_SIGNING_KEY']
        data = f"{entry_hash}{previous_hash or ''}"
        signature = hmac.new(key, data.encode('utf-8'), hashlib.sha256).hexdigest()
        return signature

    @staticmethod
    def log_audit_event(user_id, action, resource_id, details=None):
        """
        Log an audit event with remote backup (VULN-008 fix)
        """
        from datetime import datetime
        timestamp = datetime.utcnow().isoformat()
        
        # Create log message
        log_message = f"AUDIT: user={user_id} action={action} resource={resource_id}"
        if details:
            log_message += f" details={details}"
        
        # Send to remote syslog
        RemoteSyslogHandler.log_to_syslog(log_message)
        
        # Return entry data for database logging
        return {
            'timestamp': timestamp,
            'user_id': user_id,
            'action': action,
            'resource_id': resource_id,
            'details': details
        }

    @staticmethod
    def verify_log_chain(logs):
        """
        Verify integrity of log chain
        Returns (is_valid, broken_at_index)
        """
        for i, log in enumerate(logs):
            # Recompute entry hash
            expected_hash = AuditLogger.compute_entry_hash({
                'timestamp': log.timestamp.isoformat(),
                'user_id': log.user_id,
                'action': log.action,
                'resource_id': log.resource_id
            })

            if expected_hash != log.entry_hash:
                return False, i

            # Verify signature
            expected_signature = AuditLogger.sign_entry(
                log.entry_hash,
                log.previous_hash
            )

            if expected_signature != log.signature:
                return False, i

            # Verify chain linkage
            if i == 0:
                if log.previous_hash is not None:
                    return False, i
            else:
                if log.previous_hash != logs[i-1].entry_hash:
                    return False, i

        return True, None


class TwoFactorAuth:
    """Two-Factor Authentication using TOTP (RFC 6238)"""

    @staticmethod
    def generate_secret():
        """Generate random secret for TOTP"""
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(username, secret):
        """Generate TOTP URI for QR code"""
        issuer = current_app.config.get('TOTP_ISSUER_NAME', 'SecureVotingSystem')
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )

    @staticmethod
    def generate_qr_code(uri):
        """
        Generate QR code image for TOTP setup
        Returns base64 encoded PNG image
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return base64.b64encode(buffer.getvalue()).decode('utf-8')

    @staticmethod
    def verify_totp(secret, token):
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)


class SecurityUtils:
    """General security utility functions"""

    @staticmethod
    def generate_secure_token(length=32):
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)

    @staticmethod
    def hash_ip_address(ip):
        """Hash IP address for privacy-preserving logs"""
        salt = current_app.config['SECRET_KEY'].encode('utf-8')
        return hashlib.sha256(ip.encode('utf-8') + salt).hexdigest()

    @staticmethod
    def generate_nonce():
        """Generate nonce for replay attack prevention"""
        return secrets.token_hex(32)

    @staticmethod
    def constant_time_compare(a, b):
        """Constant-time string comparison to prevent timing attacks"""
        return hmac.compare_digest(str(a), str(b))


# RBAC Decorators
def role_required(*roles):
    """
    Decorator to require specific role(s)
    Usage: @role_required('administrator', 'auditor')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)

            if not any(current_user.has_role(role) for role in roles):
                abort(403)

            if not current_user.is_active:
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator requiring administrator role"""
    return role_required('administrator')(f)


def auditor_required(f):
    """Decorator requiring auditor role"""
    return role_required('auditor', 'administrator')(f)


def voter_required(f):
    """Decorator requiring voter role"""
    return role_required('voter')(f)


def two_fa_required(f):
    """Decorator requiring 2FA to be enabled and verified"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)

        if not current_user.is_2fa_enabled:
            abort(403)

        from flask import session
        if not session.get('2fa_verified'):
            abort(403)

        return f(*args, **kwargs)
    return decorated_function
