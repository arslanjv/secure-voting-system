"""
Security Utilities Module
Implements cryptographic operations, authentication helpers, and security functions
Following OWASP, NIST, and UMLSec principles
"""
import os
import hmac
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from functools import wraps
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
        Decrypt vote data using AES-256-GCM
        Uses same key derivation as client-side encryption (PBKDF2)
        Returns decrypted data as string
        """
        if key is None:
            # Use same passphrase as client-side (vote-encrypt.js)
            password = b'SECURE_VOTING_SYSTEM_KEY_2024'
            
            # Try different salt patterns that client might use
            # Client uses: 'election_salt_' + window.location.pathname
            # Possible paths: /voter/election/2/vote or /voter/election/2
            salt_patterns = [
                b'election_salt_/voter/election/',  # Base path
            ]
            
            # Add election-specific salts if election_id provided
            if election_id:
                salt_patterns.extend([
                    f'election_salt_/voter/election/{election_id}/vote'.encode('utf-8'),
                    f'election_salt_/voter/election/{election_id}'.encode('utf-8'),
                ])
            
            # Try each salt pattern
            last_error = None
            for salt in salt_patterns:
                try:
                    # Derive key using PBKDF2 (same as client)
                    from Crypto.Hash import SHA256
                    key = PBKDF2(
                        password, 
                        salt, 
                        dkLen=32,  # 256 bits for AES-256
                        count=100000,  # Same iteration count as client
                        hmac_hash_module=SHA256
                    )
                    
                    # Decode from base64
                    ciphertext = base64.b64decode(encrypted_data)
                    nonce_bytes = base64.b64decode(nonce)
                    tag_bytes = base64.b64decode(tag)
                    
                    # Create cipher
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
                    
                    # Decrypt and verify
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag_bytes)
                    return plaintext.decode('utf-8')
                    
                except ValueError as e:
                    last_error = e
                    continue  # Try next salt pattern
            
            # If all patterns failed, raise the last error
            raise ValueError("Vote decryption failed - data may be tampered") from last_error
        
        # If key provided, use it directly
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
    def sign_data(data, private_key_pem=None):
        """
        Sign data using Ed25519 private key
        Returns signature as base64 string
        """
        if private_key_pem is None:
            # Load from config or generate
            key_path = current_app.config.get('DIGITAL_SIGNATURE_PRIVATE_KEY_PATH')
            if key_path and os.path.exists(key_path):
                with open(key_path, 'rb') as f:
                    private_key_pem = f.read()
            else:
                # Generate new keypair (for development)
                private_key_pem, _ = DigitalSignature.generate_keypair()
        
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
                key_path = current_app.config.get('DIGITAL_SIGNATURE_PUBLIC_KEY_PATH')
                if key_path and os.path.exists(key_path):
                    with open(key_path, 'rb') as f:
                        public_key_pem = f.read()
                else:
                    return False
            
            # Load public key
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


class AuditLogger:
    """
    Immutable audit logging with cryptographic integrity
    Each log entry contains HMAC of previous entry (blockchain-style)
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
                # First entry must have no previous hash
                if log.previous_hash is not None:
                    return False, i
            else:
                # Subsequent entries must link to previous entry
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
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    @staticmethod
    def verify_totp(secret, token):
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 1 step before/after


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
                abort(401)  # Unauthorized
            
            if not any(current_user.has_role(role) for role in roles):
                abort(403)  # Forbidden
            
            if not current_user.is_active:
                abort(403)  # Account inactive
            
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
            abort(403)  # 2FA not enabled
        
        # Check session for 2FA verification
        from flask import session
        if not session.get('2fa_verified'):
            abort(403)  # 2FA not verified this session
        
        return f(*args, **kwargs)
    return decorated_function
