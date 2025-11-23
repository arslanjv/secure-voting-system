# Email Configuration Guide for Invite System

## Overview
The invite system now **automatically sends registration emails** to invited users. You need to configure email settings for this to work.

## Quick Setup

### 1. Create/Edit `.env` File
Copy `.env.example` to `.env` in your project root:
```bash
copy .env.example .env
```

### 2. Configure Email Settings

#### Option A: Gmail (Recommended for Development)

1. **Enable 2-Factor Authentication** on your Gmail account:
   - Go to https://myaccount.google.com/security
   - Enable "2-Step Verification"

2. **Generate App Password**:
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" and your device
   - Copy the 16-character password

3. **Update `.env` file**:
```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=xxxx xxxx xxxx xxxx
```

#### Option B: Outlook/Hotmail

```env
MAIL_SERVER=smtp-mail.outlook.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@outlook.com
MAIL_PASSWORD=your-password-here
```

#### Option C: Yahoo Mail

```env
MAIL_SERVER=smtp.mail.yahoo.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@yahoo.com
MAIL_PASSWORD=your-app-password
```

**Note**: Yahoo also requires app password generation similar to Gmail.

#### Option D: SendGrid (Professional/Production)

1. Sign up at https://sendgrid.com (free tier: 100 emails/day)
2. Create an API key
3. Configure:

```env
MAIL_SERVER=smtp.sendgrid.net
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=apikey
MAIL_PASSWORD=your-sendgrid-api-key
```

## How It Works

### Single Invite Flow:
1. Admin enters email address
2. Clicks "Send Invite Email"
3. System generates token (expires in 24 hours)
4. **Email sent automatically** with registration link
5. User receives email and clicks link
6. Registration form opens with token pre-filled

### Bulk Invite Flow:
1. Admin pastes multiple emails (one per line)
2. Clicks "Send Invite Emails"
3. System generates tokens for all valid emails
4. **Emails sent automatically** to all recipients
5. Admin sees success/failure report
6. Users receive emails and register

## Email Template

Users will receive a professional HTML email with:
- Clear "Complete Registration" button
- Registration link (also as plain text)
- 24-hour expiration notice
- Your organization name
- Responsive design (works on mobile)

## Fallback Mode

If email is **not configured**:
- Invites are still created in database
- Registration link shown in admin UI
- Admin must manually copy/paste link to users
- Flash message: "Email not configured. Please share the registration link manually."

## Testing Email Configuration

### Test Single Invite:
1. Login as admin
2. Go to Invites → Invite Single User
3. Enter your own email address
4. Click "Send Invite Email"
5. Check your inbox (and spam folder)

### Verify Email Works:
```python
# Run in Flask shell (python -c "from app import create_app; app = create_app(); ...")
from app.email_utils import send_invite_email
from flask import url_for

# Test email
success, error = send_invite_email(
    'test@example.com',
    'test-token-123',
    'http://localhost:5000/auth/register?token=test-token-123'
)

print(f"Success: {success}")
if error:
    print(f"Error: {error}")
```

## Common Issues

### Gmail: "Less secure app access"
**Solution**: Use App Password (not regular password). Gmail blocks regular passwords when 2FA is enabled.

### Yahoo: Authentication failed
**Solution**: Generate app password at https://login.yahoo.com/account/security

### Outlook: SMTP error
**Solution**: Ensure 2FA is disabled OR use app password if 2FA is enabled.

### Email not received
**Checks**:
1. Check spam/junk folder
2. Verify email address is correct
3. Check Flask logs: `logs/app.log`
4. Test with different email provider

### Port blocked (corporate network)
**Solution**: Try port 465 (SSL) instead of 587 (TLS):
```env
MAIL_PORT=465
MAIL_USE_TLS=False
```

## Security Best Practices

1. **Never commit `.env` to Git**:
   - Already in `.gitignore`
   - Contains sensitive passwords

2. **Use environment variables in production**:
   ```bash
   export MAIL_USERNAME=admin@example.com
   export MAIL_PASSWORD=secret-password
   ```

3. **Rotate credentials regularly**:
   - Change email password every 90 days
   - Generate new app passwords if compromised

4. **Limit email sending**:
   - Free tiers have daily limits
   - Monitor usage to avoid blocking

## Production Recommendations

### Use Professional Email Service:
- **SendGrid**: 100 emails/day free
- **Mailgun**: 5,000 emails/month free
- **Amazon SES**: $0.10 per 1,000 emails
- **Postmark**: Reliable transactional emails

### Why Professional Service?
- ✅ Higher deliverability rates
- ✅ Better spam score
- ✅ Detailed analytics
- ✅ No personal account risk
- ✅ Better security
- ✅ Scales automatically

## Configuration Checklist

- [ ] `.env` file created (copied from `.env.example`)
- [ ] `MAIL_SERVER` configured
- [ ] `MAIL_PORT` set correctly
- [ ] `MAIL_USERNAME` set to valid email
- [ ] `MAIL_PASSWORD` set (app password if Gmail/Yahoo)
- [ ] `MAIL_USE_TLS` set to True for port 587
- [ ] Tested with single invite
- [ ] Verified email received
- [ ] Checked spam folder
- [ ] Tested bulk invite (if needed)

## Support

If emails still don't work after configuration:
1. Check `logs/app.log` for detailed errors
2. Test email credentials with external tool
3. Verify firewall/network allows SMTP
4. Try alternative email provider
5. Use fallback mode (manual link sharing)

## Default Settings

- **Token expiry**: 24 hours (1 day)
- **Email format**: HTML + plain text fallback
- **Auto-retry**: No (shows error immediately)
- **Queue**: Synchronous sending (instant)

---

**Note**: Email configuration is optional but highly recommended. Without email, admins must manually copy registration links to users.
