#!/usr/bin/env python3
"""
Migration Script: Move signing keys from filesystem to database (VULN-009 fix)

This script migrates existing Ed25519 signing keys from the filesystem
to the database with encryption at rest using Fernet.

IMPORTANT: Run this script ONCE after deploying the security update.
Make sure MASTER_ENCRYPTION_KEY is set in environment before running.

Usage:
    python scripts/migrate_signing_keys.py
"""
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def create_app():
    """Create Flask app for migration context"""
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///voting.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'migration-key')
    app.config['MASTER_ENCRYPTION_KEY'] = os.environ.get('MASTER_ENCRYPTION_KEY', '')
    app.config['DIGITAL_SIGNATURE_PRIVATE_KEY_PATH'] = os.environ.get(
        'DIGITAL_SIGNATURE_PRIVATE_KEY_PATH', './keys/signing_private.pem'
    )
    app.config['DIGITAL_SIGNATURE_PUBLIC_KEY_PATH'] = os.environ.get(
        'DIGITAL_SIGNATURE_PUBLIC_KEY_PATH', './keys/signing_public.pem'
    )
    
    return app


def migrate_signing_keys():
    """Migrate signing keys from filesystem to database"""
    app = create_app()
    
    with app.app_context():
        from app.models import db, SigningKey
        from app.crypto_utils import CryptoUtils
        
        # Initialize database
        db.init_app(app)
        
        # Verify encryption key is set
        if not app.config['MASTER_ENCRYPTION_KEY']:
            print("ERROR: MASTER_ENCRYPTION_KEY not set in environment!")
            print("Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
            return False
        
        private_key_path = app.config['DIGITAL_SIGNATURE_PRIVATE_KEY_PATH']
        public_key_path = app.config['DIGITAL_SIGNATURE_PUBLIC_KEY_PATH']
        
        # Check if keys exist in filesystem
        if not os.path.exists(private_key_path):
            print(f"No private key found at {private_key_path}")
            print("If this is a new installation, no migration is needed.")
            print("Keys will be generated automatically on first use.")
            return True
        
        if not os.path.exists(public_key_path):
            print(f"No public key found at {public_key_path}")
            return False
        
        # Check if already migrated
        existing_key = SigningKey.query.filter_by(key_name='primary', is_active=True).first()
        if existing_key:
            print("Signing key already exists in database. Skipping migration.")
            return True
        
        print("Reading signing keys from filesystem...")
        
        try:
            with open(private_key_path, 'rb') as f:
                private_key_pem = f.read()
            
            with open(public_key_path, 'rb') as f:
                public_key_pem = f.read()
            
            # Validate keys by loading them
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            print("Keys loaded and validated successfully.")
            
        except Exception as e:
            print(f"ERROR: Failed to read or validate keys: {e}")
            return False
        
        # Encrypt private key
        print("Encrypting private key...")
        try:
            encrypted_private = CryptoUtils.encrypt_private_key(private_key_pem)
        except Exception as e:
            print(f"ERROR: Failed to encrypt private key: {e}")
            return False
        
        # Create database record
        print("Storing encrypted key in database...")
        try:
            signing_key = SigningKey(
                key_name='primary',
                encrypted_private_key=encrypted_private,
                public_key=public_key_pem.decode('utf-8'),
                is_active=True
            )
            db.session.add(signing_key)
            db.session.commit()
            
            print(f"Signing key migrated successfully (ID: {signing_key.id})")
            
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: Failed to store key in database: {e}")
            return False
        
        # Verify migration
        print("\nVerifying migration...")
        try:
            decrypted = CryptoUtils.decrypt_private_key(signing_key.encrypted_private_key)
            if decrypted == private_key_pem:
                print("Verification successful - decrypted key matches original.")
            else:
                print("WARNING: Decrypted key doesn't match original!")
                return False
        except Exception as e:
            print(f"ERROR: Verification failed: {e}")
            return False
        
        # Recommend deleting filesystem keys
        print("\n" + "=" * 60)
        print("IMPORTANT SECURITY STEP")
        print("=" * 60)
        print("\nThe signing keys have been securely migrated to the database.")
        print("For security, you should now delete the filesystem key files:")
        print(f"\n  rm {private_key_path}")
        print(f"  rm {public_key_path}")
        print("\nMake sure to backup your MASTER_ENCRYPTION_KEY securely!")
        print("Without it, you cannot decrypt the keys in the database.")
        
        return True


def verify_migration():
    """Verify that signing key migration was successful"""
    app = create_app()
    
    with app.app_context():
        from app.models import db, SigningKey
        from app.crypto_utils import CryptoUtils
        from app.security import DigitalSignature
        
        db.init_app(app)
        
        # Check database for signing key
        signing_key = SigningKey.query.filter_by(key_name='primary', is_active=True).first()
        
        if not signing_key:
            print("No signing key found in database.")
            print("Run migration first or keys will be generated on first use.")
            return True
        
        print(f"Found signing key in database (ID: {signing_key.id})")
        print(f"  Created: {signing_key.created_at}")
        print(f"  Active: {signing_key.is_active}")
        
        # Try to use the key
        print("\nTesting signing key...")
        try:
            test_data = "Test message for signature verification"
            signature = DigitalSignature.sign_data(test_data)
            print(f"  Signature created: {signature[:40]}...")
            
            verified = DigitalSignature.verify_signature(test_data, signature)
            if verified:
                print("  Signature verification: PASSED")
            else:
                print("  Signature verification: FAILED")
                return False
                
        except Exception as e:
            print(f"  ERROR: {e}")
            return False
        
        print("\nSigning key migration verified successfully!")
        return True


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate signing keys to database')
    parser.add_argument('--verify', action='store_true', help='Verify migration was successful')
    args = parser.parse_args()
    
    if args.verify:
        success = verify_migration()
    else:
        print("=" * 60)
        print("Signing Key Migration Script (VULN-009 Fix)")
        print("=" * 60)
        print("\nThis will migrate filesystem signing keys to the database")
        print("with encryption at rest.")
        print("Make sure you have a backup before proceeding!\n")
        
        confirm = input("Continue with migration? [y/N]: ")
        if confirm.lower() == 'y':
            success = migrate_signing_keys()
        else:
            print("Migration cancelled.")
            success = True
    
    sys.exit(0 if success else 1)
