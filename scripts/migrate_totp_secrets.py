#!/usr/bin/env python3
"""
Migration Script: Encrypt existing TOTP secrets at rest (VULN-003 fix)

This script migrates existing plaintext TOTP secrets to encrypted format
using Fernet symmetric encryption with a master key.

IMPORTANT: Run this script ONCE after deploying the security update.
Make sure MASTER_ENCRYPTION_KEY is set in environment before running.

Usage:
    python scripts/migrate_totp_secrets.py
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
    
    return app


def migrate_totp_secrets():
    """Migrate plaintext TOTP secrets to encrypted format"""
    app = create_app()
    
    with app.app_context():
        from app.models import db, User
        from app.crypto_utils import CryptoUtils
        
        # Initialize database
        db.init_app(app)
        
        # Verify encryption key is set
        if not app.config['MASTER_ENCRYPTION_KEY']:
            print("ERROR: MASTER_ENCRYPTION_KEY not set in environment!")
            print("Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
            return False
        
        # Find users with 2FA enabled
        users_with_2fa = User.query.filter(
            User.is_2fa_enabled == True,
            User.totp_secret.isnot(None)
        ).all()
        
        if not users_with_2fa:
            print("No users with 2FA enabled found. Nothing to migrate.")
            return True
        
        print(f"Found {len(users_with_2fa)} users with 2FA to migrate...")
        
        migrated = 0
        skipped = 0
        errors = 0
        
        for user in users_with_2fa:
            try:
                # Check if already encrypted (starts with 'gAAAAA' for Fernet)
                if user.totp_secret and user.totp_secret.startswith('gAAAAA'):
                    print(f"  User {user.username}: Already encrypted, skipping")
                    skipped += 1
                    continue
                
                # Get the plaintext secret
                plaintext_secret = user.totp_secret
                
                if not plaintext_secret:
                    print(f"  User {user.username}: No TOTP secret, skipping")
                    skipped += 1
                    continue
                
                # Encrypt the secret
                encrypted_secret = CryptoUtils.encrypt_totp_secret(plaintext_secret)
                
                # Update in database (using raw update to avoid property setter recursion)
                user._totp_secret_encrypted = encrypted_secret
                
                print(f"  User {user.username}: Migrated successfully")
                migrated += 1
                
            except Exception as e:
                print(f"  User {user.username}: ERROR - {e}")
                errors += 1
        
        # Commit all changes
        if migrated > 0:
            db.session.commit()
            print(f"\nMigration complete:")
            print(f"  Migrated: {migrated}")
            print(f"  Skipped:  {skipped}")
            print(f"  Errors:   {errors}")
        else:
            print("\nNo secrets needed migration.")
        
        return errors == 0


def verify_migration():
    """Verify that migration was successful"""
    app = create_app()
    
    with app.app_context():
        from app.models import db, User
        from app.crypto_utils import CryptoUtils
        
        db.init_app(app)
        
        users_with_2fa = User.query.filter(
            User.is_2fa_enabled == True,
            User.totp_secret.isnot(None)
        ).all()
        
        print(f"\nVerifying {len(users_with_2fa)} users...")
        
        all_valid = True
        for user in users_with_2fa:
            try:
                # Try to decrypt using the property getter
                decrypted = user.totp_secret
                if decrypted and len(decrypted) == 32:  # Valid base32 TOTP secret
                    print(f"  User {user.username}: OK")
                else:
                    print(f"  User {user.username}: INVALID - decrypted value is not a valid TOTP secret")
                    all_valid = False
            except Exception as e:
                print(f"  User {user.username}: FAILED - {e}")
                all_valid = False
        
        if all_valid:
            print("\nAll secrets verified successfully!")
        else:
            print("\nSome secrets failed verification. Check errors above.")
        
        return all_valid


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate TOTP secrets to encrypted format')
    parser.add_argument('--verify', action='store_true', help='Verify migration was successful')
    args = parser.parse_args()
    
    if args.verify:
        success = verify_migration()
    else:
        print("=" * 60)
        print("TOTP Secret Migration Script (VULN-003 Fix)")
        print("=" * 60)
        print("\nThis will encrypt all plaintext TOTP secrets in the database.")
        print("Make sure you have a backup before proceeding!\n")
        
        confirm = input("Continue with migration? [y/N]: ")
        if confirm.lower() == 'y':
            success = migrate_totp_secrets()
        else:
            print("Migration cancelled.")
            success = True
    
    sys.exit(0 if success else 1)
