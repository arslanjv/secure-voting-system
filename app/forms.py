"""
Flask Forms with CSRF Protection
All forms include validation, sanitization, and security measures
"""
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, TextAreaField, BooleanField,
    SelectField, IntegerField, DateTimeLocalField, SelectMultipleField,
    SubmitField, HiddenField
)
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, Optional,
    ValidationError, Regexp
)
from datetime import datetime
import bleach


class SecureForm(FlaskForm):
    """Base form with additional security"""

    def sanitize_string(self, value):
        """Sanitize string input to prevent XSS"""
        if value is None:
            return None
        return bleach.clean(value, tags=[], strip=True)


class LoginForm(SecureForm):
    """Login form with username/email and password"""
    username = StringField('Username or Email', validators=[
        DataRequired(message='Username or email is required'),
        Length(min=3, max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

    def validate_username(self, field):
        field.data = self.sanitize_string(field.data)


class TwoFactorForm(SecureForm):
    """
    Two-factor authentication token form
    Accepts either:
    - 6-digit TOTP code
    - 8-character backup code (alphanumeric uppercase)
    """
    token = StringField('Authentication Code', validators=[
        DataRequired(message='Authentication code is required'),
        Length(min=6, max=8, message='Code must be 6 digits or 8-character backup code')
    ])
    submit = SubmitField('Verify')

    def validate_token(self, field):
        """Validate token format - either TOTP or backup code"""
        value = field.data.strip().upper()
        
        # Check if it's a 6-digit TOTP code
        if len(value) == 6 and value.isdigit():
            field.data = value
            return
        
        # Check if it's an 8-character backup code (alphanumeric)
        if len(value) == 8 and value.isalnum():
            field.data = value
            return
        
        raise ValidationError('Invalid code format. Enter a 6-digit TOTP code or 8-character backup code.')


class RegistrationForm(SecureForm):
    """User registration form with invite token requirement"""
    invite_token = StringField('Invite Token', validators=[
        DataRequired(message='Invite token is required'),
        Length(min=32, max=64, message='Invalid invite token format')
    ])
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=80, message='Username must be between 3 and 80 characters'),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username must contain only letters, numbers, and underscores')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address'),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=12, message='Password must be at least 12 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_username(self, field):
        field.data = self.sanitize_string(field.data)

    def validate_email(self, field):
        field.data = self.sanitize_string(field.data)

    def validate_invite_token(self, field):
        """Validate invite token exists and is valid"""
        from app.models import InviteToken
        token = InviteToken.query.filter_by(token=field.data).first()
        if not token:
            raise ValidationError('Invalid invite token')
        if not token.is_valid():
            if token.is_used:
                raise ValidationError('This invite token has already been used')
            else:
                raise ValidationError('This invite token has expired')
        # Store token object for use in route
        self.invite_token_obj = token


class PasswordResetRequestForm(SecureForm):
    """Request password reset"""
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    submit = SubmitField('Request Password Reset')


class PasswordResetForm(SecureForm):
    """Reset password with token"""
    password = PasswordField('New Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=12, message='Password must be at least 12 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')


class ProfileUpdateForm(SecureForm):
    """Update user profile"""
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address'),
        Length(max=120)
    ])
    current_password = PasswordField('Current Password (required to save changes)', validators=[
        DataRequired(message='Current password is required')
    ])
    new_password = PasswordField('New Password (optional)', validators=[
        Optional(),
        Length(min=12, message='Password must be at least 12 characters')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Update Profile')


class InviteSingleUserForm(SecureForm):
    """Invite single user for registration"""
    email = StringField('Email Address', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address'),
        Length(max=120)
    ])
    submit = SubmitField('Send Invite Email')

    def validate_email(self, field):
        field.data = self.sanitize_string(field.data)
        # Check if user already exists
        from app.models import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('User with this email already exists')
        # Check if pending invite exists
        from app.models import InviteToken
        existing = InviteToken.query.filter_by(email=field.data, is_used=False).first()
        if existing and existing.is_valid():
            raise ValidationError('Valid invite already exists for this email')


class InviteBulkUsersForm(SecureForm):
    """Invite multiple users via email list or CSV"""
    emails = TextAreaField('Email Addresses (one per line)', validators=[
        Optional()
    ])
    submit = SubmitField('Send Invite Emails')


class Enable2FAForm(SecureForm):
    """Enable two-factor authentication"""
    token = StringField('Authentication Code', validators=[
        DataRequired(message='Authentication code is required'),
        Length(min=6, max=6, message='Code must be 6 digits'),
        Regexp(r'^\d{6}$', message='Code must be 6 digits')
    ])
    submit = SubmitField('Enable 2FA')


class RegenerateBackupCodesForm(SecureForm):
    """Regenerate 2FA backup codes"""
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Password is required to regenerate backup codes')
    ])
    submit = SubmitField('Regenerate Backup Codes')


class ElectionForm(SecureForm):
    """Create/edit election form"""
    title = StringField('Election Title', validators=[
        DataRequired(message='Title is required'),
        Length(min=5, max=200, message='Title must be between 5 and 200 characters')
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=5000, message='Description must not exceed 5000 characters')
    ])
    start_time = DateTimeLocalField('Start Time', format='%Y-%m-%dT%H:%M', validators=[
        DataRequired(message='Start time is required')
    ])
    end_time = DateTimeLocalField('End Time', format='%Y-%m-%dT%H:%M', validators=[
        DataRequired(message='End time is required')
    ])
    max_selections = IntegerField('Maximum Candidates to Select', validators=[
        DataRequired(message='Maximum selections is required'),
        ],
        default=1
    )
    allow_multiple_votes = BooleanField('Allow voters to change their vote')
    submit = SubmitField('Save Election')

    def validate_title(self, field):
        field.data = self.sanitize_string(field.data)

    def validate_description(self, field):
        if field.data:
            field.data = self.sanitize_string(field.data)

    def validate_end_time(self, field):
        if field.data and self.start_time.data:
            if field.data <= self.start_time.data:
                raise ValidationError('End time must be after start time')

    def validate_max_selections(self, field):
        if field.data and field.data < 1:
            raise ValidationError('Maximum selections must be at least 1')


class CandidateForm(SecureForm):
    """Add/edit candidate form"""
    name = StringField('Candidate Name', validators=[
        DataRequired(message='Name is required'),
        Length(min=2, max=200, message='Name must be between 2 and 200 characters')
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=2000, message='Description must not exceed 2000 characters')
    ])
    photo_url = StringField('Photo URL', validators=[
        Optional(),
        Length(max=500)
    ])
    order = IntegerField('Display Order', validators=[
        Optional()
    ], default=0)
    submit = SubmitField('Save Candidate')

    def validate_name(self, field):
        field.data = self.sanitize_string(field.data)

    def validate_description(self, field):
        if field.data:
            field.data = self.sanitize_string(field.data)


class VoteForm(SecureForm):
    """
    Vote submission form
    Dynamic - candidates populated at runtime
    Now supports hybrid encryption with RSA-wrapped AES key
    """
    # Encrypted vote data (prepared client-side with AES-256-GCM)
    encrypted_vote = HiddenField('Encrypted Vote', validators=[
        DataRequired(message='Vote data is required')
    ])
    vote_nonce = HiddenField('Vote Nonce', validators=[
        DataRequired(message='Vote nonce is required')
    ])
    vote_tag = HiddenField('Vote Tag', validators=[
        DataRequired(message='Vote tag is required')
    ])
    # RSA-encrypted AES key (new for hybrid encryption)
    encrypted_key = HiddenField('Encrypted Key', validators=[
        Optional()  # Optional for backward compatibility with legacy votes
    ])
    digital_signature = HiddenField('Digital Signature', validators=[
        DataRequired(message='Digital signature is required')
    ])
    request_nonce = HiddenField('Request Nonce', validators=[
        DataRequired(message='Request nonce is required')
    ])

    # Visible candidate selection (for JS to encrypt)
    candidate_ids = SelectMultipleField('Select Candidate(s)', coerce=int, validators=[
        DataRequired(message='Please select at least one candidate')
    ])

    submit = SubmitField('Cast Vote')


class VerifyVoteForm(SecureForm):
    """Vote verification form"""
    verification_token = StringField('Verification Token', validators=[
        DataRequired(message='Verification token is required'),
        Length(min=20, max=100)
    ])
    submit = SubmitField('Verify Vote')


class TallyElectionForm(SecureForm):
    """Confirm election tally"""
    confirm = BooleanField('I confirm that I want to tally this election', validators=[
        DataRequired(message='Please confirm to proceed')
    ])
    admin_password = PasswordField('Admin Password (for verification)', validators=[
        DataRequired(message='Password is required')
    ])
    submit = SubmitField('Tally Election')


class AdminCreateUserForm(SecureForm):
    """Admin form to create users"""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=80),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username must contain only letters, numbers, and underscores')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    password = PasswordField('Temporary Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=12)
    ])
    role = SelectField('Role', choices=[
        ('voter', 'Voter'),
        ('administrator', 'Administrator'),
        ('auditor', 'Auditor')
    ], validators=[DataRequired()])
    submit = SubmitField('Create User')


class ExportAuditLogForm(SecureForm):
    """Export audit log"""
    start_date = DateTimeLocalField('Start Date', format='%Y-%m-%dT%H:%M', validators=[
        Optional()
    ])
    end_date = DateTimeLocalField('End Date', format='%Y-%m-%dT%H:%M', validators=[
        Optional()
    ])
    action_filter = StringField('Action Filter (optional)', validators=[
        Optional(),
        Length(max=100)
    ])
    submit = SubmitField('Export Audit Log')
