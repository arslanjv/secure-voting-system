"""
Authentication Routes
Login, logout, registration, 2FA, password reset
Implements secure authentication following OWASP guidelines

SECURITY FIXES:
- VULN-004: Fixed username enumeration - identical error messages for all login failures
- VULN-007: Added 2FA backup codes generation and verification
- VULN-010: Session invalidation on password change
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, current_user, login_required
from app.models import db, User, AuditLog, VerificationToken, UserRole, BackupCode
from app.forms import (
    LoginForm, RegistrationForm, TwoFactorForm, Enable2FAForm,
    PasswordResetRequestForm, PasswordResetForm, ProfileUpdateForm
)
from app.security import (
    PasswordManager, TwoFactorAuth, SecurityUtils, AuditLogger
)
from app.crypto_utils import CryptoUtils
from datetime import datetime, timedelta
from app import limiter

auth_bp = Blueprint('auth', __name__)

# Generic error message to prevent username enumeration (VULN-004 fix)
GENERIC_LOGIN_ERROR = 'Invalid username/email or password'


def log_audit(action, description, severity='INFO', resource_type=None, resource_id=None):
    """Helper to create audit log entry"""
    try:
        # Get previous log entry for chaining
        previous_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        previous_hash = previous_log.entry_hash if previous_log else None

        # Create timestamp ONCE to ensure consistency
        timestamp = datetime.utcnow()

        # Create log entry data
        entry_data = {
            'timestamp': timestamp.isoformat(),
            'user_id': current_user.id if current_user.is_authenticated else None,
            'action': action,
            'resource_id': resource_id
        }
        
        # Compute hash and signature
        entry_hash = AuditLogger.compute_entry_hash(entry_data)
        signature = AuditLogger.sign_entry(entry_hash, previous_hash)

        # Create audit log
        audit_log = AuditLog(
            timestamp=timestamp,
            user_id=current_user.id if current_user.is_authenticated else None,
            username=current_user.username if current_user.is_authenticated else 'anonymous',
            user_role=current_user.role.value if current_user.is_authenticated else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:500] if request.user_agent else None,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            signature=signature,
            severity=severity
        )

        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Audit log error: {str(e)}")


def generate_backup_codes_for_user(user):
    """
    Generate and store backup codes for a user.
    VULN-007 FIX: Provides 2FA backup codes for account recovery.
    
    Args:
        user: User object
        
    Returns:
        list: List of plaintext backup codes (to display to user once)
    """
    # Delete existing unused backup codes
    BackupCode.query.filter_by(user_id=user.id, used=False).delete()
    
    # Generate new backup codes
    codes = CryptoUtils.generate_backup_codes(count=10)
    
    # Store hashed versions
    for code in codes:
        code_hash = CryptoUtils.hash_backup_code(code)
        backup_code = BackupCode(
            user_id=user.id,
            code_hash=code_hash,
            used=False
        )
        db.session.add(backup_code)
    
    db.session.commit()
    
    return codes


def verify_session_version(user):
    """
    Check if session version matches user's current version.
    VULN-010 FIX: Invalidate sessions on password change.
    
    Returns:
        bool: True if session is valid, False if invalidated
    """
    stored_version = session.get('session_version')
    if stored_version is None:
        # First time - store the version
        session['session_version'] = user.session_version
        return True
    
    return stored_version == user.session_version


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Login route with rate limiting"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()

    if form.validate_on_submit():
        # Find user by username or email
        user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.username.data)
        ).first()

        # VULN-004 FIX: Use identical timing and message for all failure cases
        if user is None:
            # Perform dummy password check to prevent timing attacks
            PasswordManager.verify_password(
                '$argon2id$v=19$m=65536,t=3,p=4$dummy_salt$dummy_hash_for_timing',
                form.password.data
            )
            flash(GENERIC_LOGIN_ERROR, 'danger')
            log_audit('LOGIN_FAILED', f'Login attempt with unknown user', 'WARNING')
            return render_template('auth/login.html', form=form)

        # Check if account is locked
        if user.is_locked:
            # Still use generic message to prevent enumeration
            flash(GENERIC_LOGIN_ERROR, 'danger')
            log_audit('LOGIN_BLOCKED', f'Login attempt on locked account', 'WARNING')
            return render_template('auth/login.html', form=form)

        # Verify password
        is_valid, new_hash = PasswordManager.verify_password(user.password_hash, form.password.data)

        if not is_valid:
            # Increment failed attempts
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()

            # Lock account after max attempts
            if user.failed_login_attempts >= current_app.config['MAX_LOGIN_ATTEMPTS']:
                user.is_locked = True
                log_audit('ACCOUNT_LOCKED', f'Account locked after max attempts', 'CRITICAL')

            db.session.commit()
            
            # VULN-004 FIX: Generic error message
            flash(GENERIC_LOGIN_ERROR, 'danger')
            log_audit('LOGIN_FAILED', f'Failed login attempt', 'WARNING')
            return render_template('auth/login.html', form=form)

        # Password is valid - check if needs rehashing
        if new_hash:
            user.password_hash = new_hash

        # Reset failed attempts
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()

        # If 2FA is enabled, redirect to 2FA verification
        if user.is_2fa_enabled:
            session['pending_user_id'] = user.id
            session['2fa_verified'] = False
            db.session.commit()
            return redirect(url_for('auth.verify_2fa'))

        # Login user
        login_user(user, remember=form.remember_me.data)
        session['2fa_verified'] = True  # Mark as verified if no 2FA
        session['session_version'] = user.session_version  # Store session version
        session.permanent = form.remember_me.data

        db.session.commit()

        log_audit('LOGIN_SUCCESS', f'User logged in: {user.username}', 'INFO')
        
        flash('Login successful!', 'success')

        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)

        # Role-based redirect
        if user.has_role('administrator'):
            return redirect(url_for('admin.dashboard'))
        elif user.has_role('auditor'):
            return redirect(url_for('auditor.dashboard'))
        else:
            return redirect(url_for('voter.dashboard'))

    return render_template('auth/login.html', form=form)


@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_2fa():
    """Two-factor authentication verification with backup code support"""
    pending_user_id = session.get('pending_user_id')

    if not pending_user_id:
        flash('Invalid session. Please login again.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.get(pending_user_id)
    if not user or not user.is_2fa_enabled:
        session.pop('pending_user_id', None)
        flash('Invalid session. Please login again.', 'danger')
        return redirect(url_for('auth.login'))

    form = TwoFactorForm()

    if form.validate_on_submit():
        token = form.token.data
        verified = False
        used_backup = False
        
        # First try TOTP verification
        if TwoFactorAuth.verify_totp(user.totp_secret, token):
            verified = True
        # Then try backup code (VULN-007 fix)
        elif len(token) == 8 and BackupCode.verify_code(user.id, token):
            verified = True
            used_backup = True
        
        if verified:
            # Login user
            login_user(user)
            session['2fa_verified'] = True
            session['session_version'] = user.session_version
            session.pop('pending_user_id', None)

            if used_backup:
                log_audit('2FA_BACKUP_USED', f'Backup code used for 2FA: {user.username}', 'WARNING')
                remaining_codes = user.get_unused_backup_codes_count()
                flash(f'Logged in with backup code. {remaining_codes} backup codes remaining.', 'warning')
            else:
                log_audit('2FA_SUCCESS', f'2FA verified for user: {user.username}', 'INFO')
                flash('Two-factor authentication successful!', 'success')

            # Role-based redirect
            if user.has_role('administrator'):
                return redirect(url_for('admin.dashboard'))
            elif user.has_role('auditor'):
                return redirect(url_for('auditor.dashboard'))
            else:
                return redirect(url_for('voter.dashboard'))
        else:
            flash('Invalid authentication code. Please try again.', 'danger')
            log_audit('2FA_FAILED', f'Invalid 2FA code for user: {user.username}', 'WARNING')

    # Show backup code hint
    backup_count = user.get_unused_backup_codes_count()
    
    return render_template('auth/verify_2fa.html', form=form, backup_codes_available=backup_count > 0)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with invite token requirement"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegistrationForm()

    # Pre-fill token from URL parameter
    if request.method == 'GET' and 'token' in request.args:
        form.invite_token.data = request.args.get('token')

    if form.validate_on_submit():
        # Get validated invite token object from form
        invite_token = form.invite_token_obj

        # Verify email matches invite token
        if form.email.data != invite_token.email:
            flash(f'Email must match invited address: {invite_token.email}', 'danger')
            return render_template('auth/register.html', form=form)

        # Check if username already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists', 'danger')
            return render_template('auth/register.html', form=form)

        # Check if email already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'danger')
            return render_template('auth/register.html', form=form)

        # Validate password strength
        is_valid, error_msg = PasswordManager.validate_password_strength(form.password.data)
        if not is_valid:
            flash(error_msg, 'danger')
            return render_template('auth/register.html', form=form)

        # Create user
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=PasswordManager.hash_password(form.password.data),
            role=UserRole.VOTER,
            is_active=True
        )

        db.session.add(user)
        db.session.flush()  # Get user.id before marking token

        # Mark invite token as used
        invite_token.mark_as_used(user.id)

        db.session.commit()

        log_audit('USER_REGISTERED', f'New user registered: {user.username} via invite token', 'INFO')

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout route"""
    username = current_user.username

    logout_user()
    session.clear()  # Clear all session data

    log_audit('LOGOUT', f'User logged out: {username}', 'INFO')

    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page"""
    # VULN-010 FIX: Check session version
    if not verify_session_version(current_user):
        logout_user()
        session.clear()
        flash('Your session has been invalidated. Please login again.', 'warning')
        return redirect(url_for('auth.login'))
    
    form = ProfileUpdateForm(obj=current_user)

    if form.validate_on_submit():
        # Verify current password
        is_valid, _ = PasswordManager.verify_password(
            current_user.password_hash,
            form.current_password.data
        )

        if not is_valid:
            flash('Current password is incorrect', 'danger')
            return render_template('auth/profile.html', form=form)

        # Update email
        if form.email.data != current_user.email:
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already in use', 'danger')
                return render_template('auth/profile.html', form=form)
            current_user.email = form.email.data
            log_audit('EMAIL_UPDATED', f'Email updated for user: {current_user.username}', 'INFO')

        # Update password if provided
        if form.new_password.data:
            is_valid, error_msg = PasswordManager.validate_password_strength(form.new_password.data)
            if not is_valid:
                flash(error_msg, 'danger')
                return render_template('auth/profile.html', form=form)

            current_user.password_hash = PasswordManager.hash_password(form.new_password.data)
            
            # VULN-010 FIX: Invalidate all other sessions on password change
            current_user.invalidate_sessions()
            session['session_version'] = current_user.session_version  # Update current session
            
            log_audit('PASSWORD_CHANGED', f'Password changed for user: {current_user.username}', 'INFO')
            flash('Password updated. All other sessions have been logged out.', 'success')

        current_user.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('auth.profile'))

    # Get backup codes count for display
    backup_codes_count = current_user.get_unused_backup_codes_count() if current_user.is_2fa_enabled else 0

    return render_template('auth/profile.html', form=form, backup_codes_count=backup_codes_count)


@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Setup two-factor authentication with backup codes"""
    if current_user.is_2fa_enabled:
        flash('2FA is already enabled', 'info')
        return redirect(url_for('auth.profile'))

    form = Enable2FAForm()

    # Generate or retrieve TOTP secret
    if not session.get('temp_totp_secret'):
        secret = TwoFactorAuth.generate_secret()
        session['temp_totp_secret'] = secret
    else:
        secret = session['temp_totp_secret']

    # Generate QR code
    totp_uri = TwoFactorAuth.get_totp_uri(current_user.username, secret)
    qr_code = TwoFactorAuth.generate_qr_code(totp_uri)

    if form.validate_on_submit():
        # Verify token
        if TwoFactorAuth.verify_totp(secret, form.token.data):
            current_user.totp_secret = secret
            current_user.is_2fa_enabled = True
            
            # VULN-007 FIX: Generate backup codes
            backup_codes = generate_backup_codes_for_user(current_user)
            
            db.session.commit()

            session.pop('temp_totp_secret', None)

            log_audit('2FA_ENABLED', f'2FA enabled for user: {current_user.username}', 'INFO')

            # Show backup codes to user (only time they'll see them)
            return render_template('auth/backup_codes.html', backup_codes=backup_codes)
        else:
            flash('Invalid code. Please try again.', 'danger')

    return render_template('auth/setup_2fa.html', form=form, qr_code=qr_code, secret=secret)


@auth_bp.route('/regenerate-backup-codes', methods=['POST'])
@login_required
def regenerate_backup_codes():
    """Regenerate backup codes for 2FA"""
    if not current_user.is_2fa_enabled:
        flash('2FA is not enabled', 'danger')
        return redirect(url_for('auth.profile'))
    
    # Generate new backup codes
    backup_codes = generate_backup_codes_for_user(current_user)
    
    log_audit('BACKUP_CODES_REGENERATED', f'Backup codes regenerated for user: {current_user.username}', 'WARNING')
    
    flash('New backup codes generated. Save these codes securely!', 'success')
    return render_template('auth/backup_codes.html', backup_codes=backup_codes)


@auth_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication"""
    if not current_user.is_2fa_enabled:
        flash('2FA is not enabled', 'info')
        return redirect(url_for('auth.profile'))

    current_user.is_2fa_enabled = False
    current_user.totp_secret = None
    
    # Delete backup codes
    BackupCode.query.filter_by(user_id=current_user.id).delete()
    
    db.session.commit()

    log_audit('2FA_DISABLED', f'2FA disabled for user: {current_user.username}', 'WARNING')

    flash('Two-factor authentication disabled', 'info')
    return redirect(url_for('auth.profile'))


# Import current_app for config access
from flask import current_app
