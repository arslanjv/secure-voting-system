"""
Initialize Invite Token System
Creates the invite_tokens table in existing database
Run this once to add invite functionality to existing system
"""
from app import create_app
from app.models import db, InviteToken

def init_invites():
    """Initialize invite token table"""
    app = create_app()
    
    with app.app_context():
        try:
            # Create invite_tokens table
            print("Creating invite_tokens table...")
            db.create_all()
            print("✓ invite_tokens table created successfully!")
            
            # Check if table exists and is accessible
            count = InviteToken.query.count()
            print(f"✓ Table verification: {count} invite tokens currently in database")
            
            print("\n" + "="*60)
            print("Invite System Initialization Complete!")
            print("="*60)
            print("\nNext steps:")
            print("1. Restart your Flask application")
            print("2. Login as admin and navigate to Invites section")
            print("3. Create invite tokens for new users")
            print("4. Share registration links with invited users")
            print("\nNote: Existing users can still login normally.")
            print("Only NEW registrations require invite tokens.")
            
        except Exception as e:
            print(f"✗ Error: {e}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    init_invites()
