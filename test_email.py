"""
Test Email Configuration
Run this to verify your email settings work before using the invite system
"""
from app import create_app
from flask import url_for
import sys

def test_email_config():
    """Test email configuration and connectivity"""
    app = create_app()
    
    with app.app_context():
        # Check if email is configured
        mail_server = app.config.get('MAIL_SERVER')
        mail_username = app.config.get('MAIL_USERNAME')
        mail_password = app.config.get('MAIL_PASSWORD')
        
        print("="*60)
        print("EMAIL CONFIGURATION TEST")
        print("="*60)
        
        print(f"\nMAIL_SERVER: {mail_server}")
        print(f"MAIL_PORT: {app.config.get('MAIL_PORT')}")
        print(f"MAIL_USERNAME: {mail_username}")
        print(f"MAIL_PASSWORD: {'*' * len(mail_password) if mail_password else 'NOT SET'}")
        print(f"MAIL_USE_TLS: {app.config.get('MAIL_USE_TLS')}")
        
        if not all([mail_server, mail_username, mail_password]):
            print("\n❌ ERROR: Email not fully configured!")
            print("Please set MAIL_SERVER, MAIL_USERNAME, and MAIL_PASSWORD in .env file")
            return False
        
        print("\n✅ Email configuration found")
        
        # Test email sending
        print("\n" + "="*60)
        print("TESTING EMAIL SEND")
        print("="*60)
        
        test_email = input(f"\nEnter email address to send test to (or press Enter for {mail_username}): ").strip()
        if not test_email:
            test_email = mail_username
        
        print(f"\nSending test email to: {test_email}")
        print("Please wait...")
        
        from app.email_utils import send_invite_email
        
        test_token = "TEST-TOKEN-123456789"
        test_url = "http://localhost:5000/auth/register?token=" + test_token
        
        success, error = send_invite_email(test_email, test_token, test_url)
        
        print("\n" + "="*60)
        if success:
            print("✅ SUCCESS! Email sent successfully")
            print(f"Check inbox of {test_email}")
            print("Don't forget to check spam/junk folder")
        else:
            print("❌ FAILED! Email could not be sent")
            print(f"\nError: {error}")
            print("\nCommon solutions:")
            print("1. Check internet connection")
            print("2. For Gmail: Use App Password (not regular password)")
            print("   - Go to https://myaccount.google.com/apppasswords")
            print("   - Generate new app password")
            print("3. Check firewall isn't blocking SMTP (port 587)")
            print("4. Verify email credentials are correct")
            print("5. Try different email provider")
        print("="*60)
        
        return success

if __name__ == '__main__':
    try:
        test_email_config()
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
