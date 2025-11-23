"""
Email Utility Functions
Handles sending invite emails via SMTP
"""
from flask import current_app, url_for, render_template_string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)


def send_invite_email(recipient_email, invite_token, registration_url):
    """
    Send registration invite email to user
    
    Args:
        recipient_email: Email address to send to
        invite_token: Invite token string
        registration_url: Full registration URL with token
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    try:
        # Email configuration from Flask config
        mail_server = current_app.config.get('MAIL_SERVER')
        mail_port = current_app.config.get('MAIL_PORT')
        mail_username = current_app.config.get('MAIL_USERNAME')
        mail_password = current_app.config.get('MAIL_PASSWORD')
        mail_use_tls = current_app.config.get('MAIL_USE_TLS', True)
        mail_sender = current_app.config.get('MAIL_DEFAULT_SENDER')
        app_name = current_app.config.get('APP_NAME', 'Secure Online Voting System')
        
        # Validate email configuration
        if not all([mail_server, mail_username, mail_password]):
            logger.warning("Email not configured. Registration link displayed in UI instead.")
            return False, "Email not configured. Please share the registration link manually."
        
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'Registration Invite - {app_name}'
        msg['From'] = mail_sender
        msg['To'] = recipient_email
        
        # Plain text version
        text_body = f"""
Hello,

You have been invited to register for {app_name}.

Click the link below to complete your registration:
{registration_url}

This invite link will expire in 24 hours.

If you did not request this invitation, please ignore this email.

Best regards,
{app_name} Team
"""
        
        # HTML version
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background-color: #0d6efd;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px 5px 0 0;
        }}
        .content {{
            background-color: #f8f9fa;
            padding: 30px;
            border: 1px solid #dee2e6;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }}
        .button {{
            display: inline-block;
            background-color: #198754;
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #6c757d;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Registration Invite</h1>
    </div>
    <div class="content">
        <h2>Hello,</h2>
        <p>You have been invited to register for <strong>{app_name}</strong>.</p>
        <p>Click the button below to complete your registration:</p>
        <div style="text-align: center;">
            <a href="{registration_url}" class="button">Complete Registration</a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background-color: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 12px;">
            {registration_url}
        </p>
        <div class="warning">
            <strong>⏰ Important:</strong> This invite link will expire in 24 hours.
        </div>
        <p>If you did not request this invitation, please ignore this email.</p>
    </div>
    <div class="footer">
        <p>© {app_name} - Secure Online Voting Platform</p>
    </div>
</body>
</html>
"""
        
        # Attach both versions
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        if mail_use_tls:
            server = smtplib.SMTP(mail_server, mail_port)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(mail_server, mail_port)
        
        server.login(mail_username, mail_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Invite email sent successfully to {recipient_email}")
        return True, None
        
    except smtplib.SMTPAuthenticationError:
        error_msg = "Email authentication failed. Please check email credentials."
        logger.error(f"SMTP authentication error: {error_msg}")
        return False, error_msg
    
    except smtplib.SMTPConnectError as e:
        error_msg = f"Cannot connect to email server. Check MAIL_SERVER and internet connection."
        logger.error(f"SMTP connection error: {error_msg} - {str(e)}")
        return False, error_msg
        
    except smtplib.SMTPException as e:
        error_msg = f"Email sending failed: {str(e)}"
        logger.error(f"SMTP error: {error_msg}")
        return False, error_msg
    
    except OSError as e:
        if 'getaddrinfo failed' in str(e):
            error_msg = "Cannot resolve email server hostname. Check MAIL_SERVER setting or internet connection."
        else:
            error_msg = f"Network error: {str(e)}"
        logger.error(f"OS/Network error: {error_msg}")
        return False, error_msg
        
    except Exception as e:
        error_msg = f"Unexpected error sending email: {str(e)}"
        logger.error(f"Email error: {error_msg}")
        return False, error_msg


def send_bulk_invite_emails(invite_data_list):
    """
    Send multiple invite emails
    
    Args:
        invite_data_list: List of dicts with keys: email, token, url
    
    Returns:
        tuple: (success_count: int, failed_emails: list, error_messages: list)
    """
    success_count = 0
    failed_emails = []
    error_messages = []
    
    for invite_data in invite_data_list:
        success, error = send_invite_email(
            invite_data['email'],
            invite_data['token'],
            invite_data['url']
        )
        
        if success:
            success_count += 1
        else:
            failed_emails.append(invite_data['email'])
            error_messages.append(f"{invite_data['email']}: {error}")
    
    return success_count, failed_emails, error_messages
