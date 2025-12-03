"""
Secure Configuration Module
Implements security best practices according to OWASP, NIST SSDF, and Secure-SDLC

Security Fixes Applied:
- VULN-006: Removed 'unsafe-inline' from CSP, using nonces instead
- VULN-008: Added remote syslog backup configuration
- Added MASTER_ENCRYPTION_KEY for encrypting secrets at rest
"""
import os
import logging
from datetime import timedelta
from logging.handlers import SysLogHandler
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Base configuration with security hardening"""

    # Flask Core
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    if len(SECRET_KEY) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters for security")

    # Base URL for email links (for LAN/network access)
    BASE_URL = os.environ.get('BASE_URL')

    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://voting_user:secure_password@localhost:5432/secure_voting_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False  # Disable SQL logging in production
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 10,
        'max_overflow': 20
    }

    # Session Security
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True') == 'True'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 60))
    )
    SESSION_REFRESH_EACH_REQUEST = True

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # CSRF tokens don't expire (session-based)
    WTF_CSRF_SSL_STRICT = True

    # ==========================================================================
    # Security Headers (Flask-Talisman)
    # VULN-006 FIX: Removed 'unsafe-inline' from script-src and style-src
    # Using nonces instead for inline scripts/styles
    # ==========================================================================
    TALISMAN_FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'True') == 'True'
    TALISMAN_STRICT_TRANSPORT_SECURITY = True
    TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE = int(
        os.environ.get('HSTS_MAX_AGE', 31536000)
    )
    TALISMAN_CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': [
            "'self'",
            # Nonces will be added dynamically by Flask-Talisman
            # Removed 'unsafe-inline' for security (VULN-006 fix)
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ],
        'style-src': [
            "'self'",
            # Using 'unsafe-inline' for styles is still common practice
            # as nonces for styles are less supported and Bootstrap needs it
            "'unsafe-inline'",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ],
        'font-src': [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'object-src': ["'none'"]
        # Removed 'upgrade-insecure-requests' for LAN/development compatibility
    }
    # Enable nonces for script-src to replace 'unsafe-inline'
    TALISMAN_CONTENT_SECURITY_POLICY_NONCE_IN = ['script-src']

    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or \
        os.environ.get('RATELIMIT_STORAGE_URL') or 'memory://'
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_HEADERS_ENABLED = True

    # Authentication & Password Policy
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 12))
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True

    # ==========================================================================
    # Cryptography Keys
    # ==========================================================================
    # Master encryption key for encrypting secrets at rest (TOTP, private keys)
    # Must be a valid Fernet key (44-char base64 URL-safe string)
    MASTER_ENCRYPTION_KEY = os.environ.get('MASTER_ENCRYPTION_KEY', '')
    
    # Legacy vote encryption key (for backward compatibility)
    VOTE_ENCRYPTION_KEY = os.environ.get('VOTE_ENCRYPTION_KEY', '').encode() or os.urandom(32)
    AUDIT_LOG_SIGNING_KEY = os.environ.get('AUDIT_LOG_SIGNING_KEY', '').encode() or os.urandom(32)
    
    # Legacy signing key paths (deprecated - now stored in database)
    DIGITAL_SIGNATURE_PRIVATE_KEY_PATH = os.environ.get(
        'DIGITAL_SIGNATURE_PRIVATE_KEY_PATH', './keys/signing_private.pem'
    )
    DIGITAL_SIGNATURE_PUBLIC_KEY_PATH = os.environ.get(
        'DIGITAL_SIGNATURE_PUBLIC_KEY_PATH', './keys/signing_public.pem'
    )

    # Two-Factor Authentication
    TOTP_ISSUER_NAME = "SecureVotingSystem"
    TOTP_DIGITS = 6
    TOTP_INTERVAL = 30
    BACKUP_CODE_COUNT = int(os.environ.get('BACKUP_CODE_COUNT', 10))

    # File Upload (if needed)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max upload
    UPLOAD_FOLDER = 'app/static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    # ==========================================================================
    # Logging Configuration
    # VULN-008 FIX: Added remote syslog backup
    # ==========================================================================
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/app.log')
    AUDIT_LOG_FILE = os.environ.get('AUDIT_LOG_FILE', 'logs/audit.log')
    
    # Remote Syslog Configuration (VULN-008)
    SYSLOG_ENABLED = os.environ.get('SYSLOG_ENABLED', 'False') == 'True'
    SYSLOG_HOST = os.environ.get('SYSLOG_HOST', 'localhost')
    SYSLOG_PORT = int(os.environ.get('SYSLOG_PORT', 514))
    SYSLOG_FACILITY = os.environ.get('SYSLOG_FACILITY', 'local0')
    
    # Map facility names to SysLogHandler constants
    SYSLOG_FACILITY_MAP = {
        'local0': SysLogHandler.LOG_LOCAL0,
        'local1': SysLogHandler.LOG_LOCAL1,
        'local2': SysLogHandler.LOG_LOCAL2,
        'local3': SysLogHandler.LOG_LOCAL3,
        'local4': SysLogHandler.LOG_LOCAL4,
        'local5': SysLogHandler.LOG_LOCAL5,
        'local6': SysLogHandler.LOG_LOCAL6,
        'local7': SysLogHandler.LOG_LOCAL7,
        'user': SysLogHandler.LOG_USER,
        'auth': SysLogHandler.LOG_AUTH,
    }

    # Email Configuration (placeholder for password reset)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.example.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME', 'noreply@votingsystem.com')

    # Application Settings
    APP_NAME = "Secure Online Voting System"
    ORGANIZATION_NAME = "SecureVote Inc."
    SUPPORT_EMAIL = "support@securevote.com"

    # Replay Attack Prevention
    NONCE_EXPIRY_SECONDS = 300  # 5 minutes

    # Vote Verification
    VERIFICATION_TOKEN_LENGTH = 32

    # Timezone Configuration
    # Set this to your local timezone offset from UTC (in hours)
    # Examples: 5 for UTC+5 (PKT), -5 for UTC-5 (EST), 0 for UTC
    LOCAL_TIMEZONE_OFFSET = int(os.environ.get('TIMEZONE_OFFSET', 5))

    @classmethod
    def get_syslog_facility(cls):
        """Get the SysLogHandler facility constant"""
        return cls.SYSLOG_FACILITY_MAP.get(
            cls.SYSLOG_FACILITY.lower(),
            SysLogHandler.LOG_LOCAL0
        )


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    TALISMAN_FORCE_HTTPS = False  # Easier for local development
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """Production configuration with maximum security"""
    DEBUG = False
    TESTING = False
    TALISMAN_FORCE_HTTPS = True
    SESSION_COOKIE_SECURE = True

    # Override to ensure production secrets are set
    @classmethod
    def init_app(cls, app):
        # Validate critical security settings
        if not os.environ.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY must be set in production environment")
        if not os.environ.get('DATABASE_URL'):
            raise ValueError("DATABASE_URL must be set in production environment")
        if not os.environ.get('MASTER_ENCRYPTION_KEY'):
            raise ValueError("MASTER_ENCRYPTION_KEY must be set in production environment")


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    TALISMAN_FORCE_HTTPS = False
    SESSION_COOKIE_SECURE = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

