"""
Admin Routes
Election management, candidate CRUD, tallying system
Implements secure admin panel with RBAC
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, send_file
from flask_login import login_required, current_user
from app.models import db, Election, Candidate, Vote, User, AuditLog, ElectionStatus, UserRole
from app.forms import (
    ElectionForm, CandidateForm, TallyElectionForm, AdminCreateUserForm,
    InviteSingleUserForm, InviteBulkUsersForm
)
from app.security import (
    admin_required, PasswordManager, VoteEncryption, DigitalSignature,
    AuditLogger, SecurityUtils
)
from wtforms.validators import Optional, Length
from datetime import datetime
from app import limiter
import json
import csv
from io import StringIO, BytesIO

admin_bp = Blueprint('admin', __name__)


def log_audit(action, description, severity='INFO', resource_type=None, resource_id=None):
    """Helper to create audit log entry"""
    try:
        previous_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        previous_hash = previous_log.entry_hash if previous_log else None
        
        # Create timestamp ONCE to ensure consistency between hash and database
        timestamp = datetime.utcnow()
        
        entry_data = {
            'timestamp': timestamp.isoformat(),
            'user_id': current_user.id,
            'action': action,
            'resource_id': resource_id
        }
        
        entry_hash = AuditLogger.compute_entry_hash(entry_data)
        signature = AuditLogger.sign_entry(entry_hash, previous_hash)
        
        audit_log = AuditLog(
            timestamp=timestamp,  # Use same timestamp as hash
            user_id=current_user.id,
            username=current_user.username,
            user_role=current_user.role.value,
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
        current_app.logger.error(f"Audit log error: {str(e)}")


@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard"""
    # Statistics
    total_elections = Election.query.count()
    active_elections = Election.query.filter_by(status=ElectionStatus.ACTIVE).count()
    total_users = User.query.count()
    total_votes = Vote.query.count()
    
    # Recent elections
    recent_elections = Election.query.order_by(Election.created_at.desc()).distinct().limit(10).all()
    
    # Recent audit logs
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    
    return render_template('admin/dashboard.html',
                          total_elections=total_elections,
                          active_elections=active_elections,
                          total_users=total_users,
                          total_votes=total_votes,
                          recent_elections=recent_elections,
                          recent_logs=recent_logs)


@admin_bp.route('/elections')
@login_required
@admin_required
def list_elections():
    """List all elections"""
    elections = Election.query.order_by(Election.created_at.desc()).all()
    return render_template('admin/elections.html', elections=elections)


@admin_bp.route('/elections/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_election():
    """Create new election"""
    form = ElectionForm()
    
    if form.validate_on_submit():
        # Convert local datetime to UTC
        from datetime import timedelta
        offset = timedelta(hours=current_app.config.get('LOCAL_TIMEZONE_OFFSET', 0))
        start_time_utc = form.start_time.data - offset
        end_time_utc = form.end_time.data - offset
        
        election = Election(
            title=form.title.data,
            description=form.description.data,
            start_time=start_time_utc,
            end_time=end_time_utc,
            max_selections=form.max_selections.data,
            allow_multiple_votes=form.allow_multiple_votes.data,
            status=ElectionStatus.DRAFT,
            created_by=current_user.id
        )
        
        db.session.add(election)
        db.session.commit()
        
        log_audit('ELECTION_CREATED', 
                 f'Election created: {election.title}',
                 'INFO', 'election', election.id)
        
        flash('Election created successfully!', 'success')
        return redirect(url_for('admin.edit_election', election_id=election.id))
    
    return render_template('admin/election_form.html', form=form, election=None)


@admin_bp.route('/elections/<int:election_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_election(election_id):
    """Edit election"""
    election = Election.query.get_or_404(election_id)
    
    # Can't edit if votes have been cast
    if election.votes.count() > 0:
        flash('Cannot edit election after votes have been cast', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    # Convert UTC times to local for display in form
    from datetime import timedelta
    offset = timedelta(hours=current_app.config.get('LOCAL_TIMEZONE_OFFSET', 0))
    
    # Create form with election data
    form = ElectionForm(obj=election)
    
    # For GET requests, convert UTC times to local time for display
    if request.method == 'GET':
        form.start_time.data = election.start_time + offset
        form.end_time.data = election.end_time + offset
    
    if form.validate_on_submit():
        # Convert local datetime to UTC before saving
        start_time_utc = form.start_time.data - offset
        end_time_utc = form.end_time.data - offset
        
        election.title = form.title.data
        election.description = form.description.data
        election.start_time = start_time_utc
        election.end_time = end_time_utc
        election.max_selections = form.max_selections.data
        election.allow_multiple_votes = form.allow_multiple_votes.data
        election.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        log_audit('ELECTION_UPDATED', 
                 f'Election updated: {election.title}',
                 'INFO', 'election', election.id)
        
        flash('Election updated successfully!', 'success')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    return render_template('admin/election_form.html', form=form, election=election)


@admin_bp.route('/elections/<int:election_id>')
@login_required
@admin_required
def view_election(election_id):
    """View election details"""
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).order_by(Candidate.order).all()
    vote_count = Vote.query.filter_by(election_id=election_id).count()
    
    return render_template('admin/election_detail.html',
                          election=election,
                          candidates=candidates,
                          vote_count=vote_count)


@admin_bp.route('/elections/<int:election_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_election(election_id):
    """Delete election (only if no votes cast)"""
    election = Election.query.get_or_404(election_id)
    
    # Can't delete if votes have been cast
    if election.votes.count() > 0:
        flash('Cannot delete election after votes have been cast', 'danger')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    election_title = election.title
    
    try:
        # Delete associated candidates first
        Candidate.query.filter_by(election_id=election_id).delete()
        
        # Delete the election
        db.session.delete(election)
        db.session.commit()
        
        log_audit('ELECTION_DELETED', 
                 f'Election deleted: {election_title}',
                 'WARNING', 'election', election_id)
        
        flash(f'Election "{election_title}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting election: {str(e)}")
        flash('An error occurred while deleting the election', 'danger')
    
    return redirect(url_for('admin.list_elections'))


@admin_bp.route('/elections/<int:election_id>/activate', methods=['POST'])
@login_required
@admin_required
def activate_election(election_id):
    """Activate election"""
    election = Election.query.get_or_404(election_id)
    
    if election.status != ElectionStatus.DRAFT:
        flash('Only draft elections can be activated', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    if election.candidates.count() == 0:
        flash('Cannot activate election without candidates', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    # Generate encryption keys for this election
    from app.security import VoteEncryption, DigitalSignature
    from Crypto.Random import get_random_bytes
    import base64
    
    # Generate AES-256 encryption key
    encryption_key = get_random_bytes(32)  # 256 bits
    election.encryption_private_key = base64.b64encode(encryption_key).decode('utf-8')
    election.encryption_public_key = base64.b64encode(encryption_key).decode('utf-8')  # Symmetric encryption
    
    # Generate Ed25519 signature keypair
    sig_private_key, sig_public_key = DigitalSignature.generate_keypair()
    election.signature_private_key = sig_private_key
    election.signature_public_key = sig_public_key
    
    election.status = ElectionStatus.ACTIVE
    db.session.commit()
    
    log_audit('ELECTION_ACTIVATED', 
             f'Election activated: {election.title}',
             'INFO', 'election', election.id)
    
    flash('Election activated successfully! Encryption and signature keys generated.', 'success')
    return redirect(url_for('admin.view_election', election_id=election_id))


@admin_bp.route('/elections/<int:election_id>/close', methods=['POST'])
@login_required
@admin_required
def close_election(election_id):
    """Close election"""
    election = Election.query.get_or_404(election_id)
    
    if election.status != ElectionStatus.ACTIVE:
        flash('Only active elections can be closed', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    election.status = ElectionStatus.CLOSED
    db.session.commit()
    
    log_audit('ELECTION_CLOSED', 
             f'Election closed: {election.title}',
             'INFO', 'election', election.id)
    
    flash('Election closed successfully!', 'success')
    return redirect(url_for('admin.view_election', election_id=election_id))


@admin_bp.route('/elections/<int:election_id>/tally', methods=['GET', 'POST'])
@login_required
@admin_required
@limiter.limit("3 per hour")
def tally_election(election_id):
    """Tally election results"""
    election = Election.query.get_or_404(election_id)
    
    if not election.can_be_tallied():
        flash('Election cannot be tallied yet', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    form = TallyElectionForm()
    
    if form.validate_on_submit():
        # Verify admin password
        is_valid, _ = PasswordManager.verify_password(
            current_user.password_hash,
            form.admin_password.data
        )
        
        if not is_valid:
            flash('Invalid password', 'danger')
            return render_template('admin/tally_election.html', form=form, election=election)
        
        try:
            # Decrypt and tally votes
            votes = Vote.query.filter_by(election_id=election_id).all()
            
            if len(votes) == 0:
                flash('No votes to tally', 'warning')
                return redirect(url_for('admin.view_election', election_id=election_id))
            
            # Tally results
            tally = {}
            decryption_errors = 0
            
            for vote in votes:
                try:
                    # Decrypt vote (pass election_id for correct salt)
                    decrypted_data = VoteEncryption.decrypt_vote(
                        vote.encrypted_vote,
                        vote.vote_nonce,
                        vote.vote_tag,
                        election_id=election_id
                    )
                    
                    # Parse candidate IDs
                    candidate_ids = json.loads(decrypted_data)
                    
                    # Count votes
                    for candidate_id in candidate_ids:
                        tally[candidate_id] = tally.get(candidate_id, 0) + 1
                        
                except Exception as e:
                    current_app.logger.error(f"Vote decryption error: {str(e)}")
                    decryption_errors += 1
            
            # Get all candidates for this election
            candidates = Candidate.query.filter_by(election_id=election_id).all()
            candidate_map = {c.id: c for c in candidates}
            
            # Build candidate_votes array with full candidate info
            candidate_votes = []
            for candidate_id, vote_count in tally.items():
                candidate = candidate_map.get(candidate_id)
                if candidate:
                    candidate_votes.append({
                        'id': candidate.id,
                        'name': candidate.name,
                        'description': candidate.description or '',
                        'votes': vote_count
                    })
            
            # Include candidates with zero votes
            for candidate in candidates:
                if candidate.id not in tally:
                    candidate_votes.append({
                        'id': candidate.id,
                        'name': candidate.name,
                        'description': candidate.description or '',
                        'votes': 0
                    })
            
            # Create results structure
            results = {
                'candidate_votes': candidate_votes,
                'total_votes': len(votes),
                'decryption_errors': decryption_errors,
                'timestamp': datetime.utcnow().isoformat(),
                'tallied_by': current_user.username,
                'tallied_at': datetime.utcnow().isoformat()
            }
            
            # Sign results
            results_json = json.dumps(results, sort_keys=True)
            signature = DigitalSignature.sign_data(results_json)
            
            # Store results
            election.tally_data = results
            election.tally_signature = signature
            election.tallied_at = datetime.utcnow()
            election.tallied_by = current_user.id
            election.status = ElectionStatus.TALLIED
            
            db.session.commit()
            
            log_audit('ELECTION_TALLIED', 
                     f'Election tallied: {election.title}',
                     'INFO', 'election', election.id)
            
            flash('Election tallied successfully!', 'success')
            return redirect(url_for('admin.view_results', election_id=election_id))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Tally error: {str(e)}")
            flash('An error occurred while tallying the election', 'danger')
            return redirect(url_for('admin.view_election', election_id=election_id))
    
    vote_count = Vote.query.filter_by(election_id=election_id).count()
    return render_template('admin/tally_election.html', 
                          form=form, 
                          election=election,
                          vote_count=vote_count)


@admin_bp.route('/elections/<int:election_id>/retally', methods=['POST'])
@login_required
@admin_required
@limiter.limit("2 per hour")
def retally_election(election_id):
    """Reset election to closed status and clear tally data"""
    election = Election.query.get_or_404(election_id)
    
    if election.status != ElectionStatus.TALLIED:
        flash('Only tallied elections can be re-tallied', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    # Clear tally data
    election.tally_data = None
    election.tally_signature = None
    election.tallied_at = None
    election.tallied_by = None
    election.status = ElectionStatus.CLOSED
    
    db.session.commit()
    
    log_audit('ELECTION_RETALLY_RESET', 
             f'Election reset for re-tally: {election.title}',
             'INFO', 'election', election.id)
    
    flash('Election reset successfully. You can now tally again.', 'success')
    return redirect(url_for('admin.tally_election', election_id=election_id))


@admin_bp.route('/elections/<int:election_id>/results')
@login_required
@admin_required
def view_results(election_id):
    """View election results"""
    election = Election.query.get_or_404(election_id)
    
    if election.status != ElectionStatus.TALLIED:
        flash('Results not available yet', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    results = election.get_results()
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    candidate_map = {c.id: c for c in candidates}
    
    return render_template('admin/results.html',
                          election=election,
                          results=results,
                          candidate_map=candidate_map)


@admin_bp.route('/elections/<int:election_id>/results/export')
@login_required
@admin_required
def export_results(election_id):
    """Export election results as CSV"""
    election = Election.query.get_or_404(election_id)
    
    if election.status != ElectionStatus.TALLIED:
        flash('Results not available yet', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    results = election.get_results()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['Election', election.title])
    writer.writerow(['Tallied At', election.tallied_at.isoformat()])
    writer.writerow(['Total Votes', results['total_votes']])
    writer.writerow([])
    writer.writerow(['Candidate', 'Votes', 'Percentage'])
    
    # Sort by votes descending
    sorted_candidates = sorted(results['candidate_votes'], key=lambda x: x['votes'], reverse=True)
    total_votes = results['total_votes']
    
    for candidate_data in sorted_candidates:
        percentage = (candidate_data['votes'] / total_votes * 100) if total_votes > 0 else 0
        writer.writerow([
            candidate_data['name'],
            candidate_data['votes'],
            f"{percentage:.2f}%"
        ])
    
    # Return as downloadable file
    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'election_{election_id}_results.csv'
    )
    return send_file(
        StringIO(output.getvalue()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'election_{election_id}_results.csv'
    )


@admin_bp.route('/elections/<int:election_id>/candidates/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_candidate(election_id):
    """Add candidate to election"""
    election = Election.query.get_or_404(election_id)
    
    if election.votes.count() > 0:
        flash('Cannot add candidates after votes have been cast', 'warning')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    form = CandidateForm()
    
    if form.validate_on_submit():
        candidate = Candidate(
            election_id=election_id,
            name=form.name.data,
            description=form.description.data,
            photo_url=form.photo_url.data,
            order=form.order.data
        )
        
        db.session.add(candidate)
        db.session.commit()
        
        log_audit('CANDIDATE_ADDED', 
                 f'Candidate added: {candidate.name} to election {election.title}',
                 'INFO', 'candidate', candidate.id)
        
        flash('Candidate added successfully!', 'success')
        return redirect(url_for('admin.view_election', election_id=election_id))
    
    return render_template('admin/candidate_form.html', form=form, election=election, candidate=None)


@admin_bp.route('/candidates/<int:candidate_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_candidate(candidate_id):
    """Edit candidate"""
    candidate = Candidate.query.get_or_404(candidate_id)
    election = candidate.election
    
    if election.votes.count() > 0:
        flash('Cannot edit candidates after votes have been cast', 'warning')
        return redirect(url_for('admin.view_election', election_id=election.id))
    
    form = CandidateForm(obj=candidate)
    
    if form.validate_on_submit():
        candidate.name = form.name.data
        candidate.description = form.description.data
        candidate.photo_url = form.photo_url.data
        candidate.order = form.order.data
        
        db.session.commit()
        
        log_audit('CANDIDATE_UPDATED', 
                 f'Candidate updated: {candidate.name}',
                 'INFO', 'candidate', candidate.id)
        
        flash('Candidate updated successfully!', 'success')
        return redirect(url_for('admin.view_election', election_id=election.id))
    
    return render_template('admin/candidate_form.html', form=form, election=election, candidate=candidate)


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete user (only if no votes cast)"""
    user = User.query.get_or_404(user_id)
    
    # Can't delete yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin.list_users'))
    
    # Can't delete if user has cast votes
    if user.votes.count() > 0:
        flash(f'Cannot delete user "{user.username}" - they have cast votes. You can deactivate the account instead.', 'danger')
        return redirect(url_for('admin.edit_user', user_id=user_id))
    
    username = user.username
    
    try:
        db.session.delete(user)
        db.session.commit()
        
        log_audit('USER_DELETED', 
                 f'User deleted: {username}',
                 'WARNING', 'user', user_id)
        
        flash(f'User "{username}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting user: {str(e)}")
        flash('An error occurred while deleting the user', 'danger')
    
    return redirect(url_for('admin.list_users'))


@admin_bp.route('/candidates/<int:candidate_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_candidate(candidate_id):
    """Delete candidate"""
    candidate = Candidate.query.get_or_404(candidate_id)
    election = candidate.election
    
    if election.votes.count() > 0:
        flash('Cannot delete candidates after votes have been cast', 'warning')
        return redirect(url_for('admin.view_election', election_id=election.id))
    
    candidate_name = candidate.name
    election_id = election.id
    
    db.session.delete(candidate)
    db.session.commit()
    
    log_audit('CANDIDATE_DELETED', 
             f'Candidate deleted: {candidate_name}',
             'WARNING', 'candidate', candidate_id)
    
    flash('Candidate deleted successfully!', 'success')
    return redirect(url_for('admin.view_election', election_id=election_id))


@admin_bp.route('/users')
@login_required
@admin_required
def list_users():
    """List all users"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    """Create new user"""
    form = AdminCreateUserForm()
    
    if form.validate_on_submit():
        # Check if username exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists', 'danger')
            return render_template('admin/user_form.html', form=form)
        
        # Check if email exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', 'danger')
            return render_template('admin/user_form.html', form=form)
        
        # Validate password
        is_valid, error_msg = PasswordManager.validate_password_strength(form.password.data)
        if not is_valid:
            flash(error_msg, 'danger')
            return render_template('admin/user_form.html', form=form)
        
        # Create user
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=PasswordManager.hash_password(form.password.data),
            role=UserRole[form.role.data.upper()],
            is_active=True
        )
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('USER_CREATED', 
                 f'User created: {user.username} ({user.role.value})',
                 'INFO', 'user', user.id)
        
        flash('User created successfully!', 'success')
        return redirect(url_for('admin.list_users'))
    
    return render_template('admin/user_form.html', form=form)


@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit existing user"""
    user = User.query.get_or_404(user_id)
    
    # Create a form without password requirement for editing
    form = AdminCreateUserForm(obj=user)
    # Make password optional for editing
    form.password.validators = [Optional(), Length(min=12)]
    form.password.label.text = 'New Password (leave blank to keep current)'
    form.submit.label.text = 'Update User'
    
    if request.method == 'GET':
        # Pre-populate form
        form.username.data = user.username
        form.email.data = user.email
        form.role.data = user.role.value
    
    if form.validate_on_submit():
        # Check if username exists (excluding current user)
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user and existing_user.id != user_id:
            flash('Username already exists', 'danger')
            return render_template('admin/user_form.html', form=form, user=user, edit_mode=True)
        
        # Check if email exists (excluding current user)
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user and existing_user.id != user_id:
            flash('Email already exists', 'danger')
            return render_template('admin/user_form.html', form=form, user=user, edit_mode=True)
        
        # Update user
        user.username = form.username.data
        user.email = form.email.data
        user.role = UserRole[form.role.data.upper()]
        
        # Update password if provided
        if form.password.data:
            is_valid, error_msg = PasswordManager.validate_password_strength(form.password.data)
            if not is_valid:
                flash(error_msg, 'danger')
                return render_template('admin/user_form.html', form=form, user=user, edit_mode=True)
            user.password_hash = PasswordManager.hash_password(form.password.data)
        
        db.session.commit()
        
        log_audit('USER_UPDATED', 
                 f'User updated: {user.username} ({user.role.value})',
                 'INFO', 'user', user.id)
        
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin.list_users'))
    
    return render_template('admin/user_form.html', form=form, user=user, edit_mode=True)


@admin_bp.route('/invites')
@login_required
@admin_required
def list_invites():
    """List all invite tokens"""
    page = request.args.get('page', 1, type=int)
    filter_status = request.args.get('status', 'all')
    
    from app.models import InviteToken
    
    query = InviteToken.query
    
    # Filter by status
    if filter_status == 'pending':
        query = query.filter_by(is_used=False).filter(InviteToken.expires_at > datetime.utcnow())
    elif filter_status == 'used':
        query = query.filter_by(is_used=True)
    elif filter_status == 'expired':
        query = query.filter_by(is_used=False).filter(InviteToken.expires_at <= datetime.utcnow())
    
    invites = query.order_by(InviteToken.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    log_audit('INVITES_VIEWED', f'Admin viewed invites list (status: {filter_status})', 'INFO')
    
    return render_template('admin/invites_list.html', invites=invites, filter_status=filter_status)


@admin_bp.route('/invites/single', methods=['GET', 'POST'])
@login_required
@admin_required
def invite_single():
    """Invite single user"""
    from app.forms import InviteSingleUserForm
    from app.models import InviteToken
    from app.email_utils import send_invite_email
    from datetime import timedelta
    
    form = InviteSingleUserForm()
    
    if form.validate_on_submit():
        # Generate invite token with 1 day expiry
        token = InviteToken.generate_token()
        expires_at = datetime.utcnow() + timedelta(days=1)
        
        invite = InviteToken(
            token=token,
            email=form.email.data,
            created_by=current_user.id,
            expires_at=expires_at,
            is_used=False
        )
        
        db.session.add(invite)
        db.session.commit()
        
        # Generate registration URL
        registration_url = url_for('auth.register', token=token, _external=True)
        
        # Send email automatically
        success, error = send_invite_email(form.email.data, token, registration_url)
        
        log_audit('INVITE_CREATED', 
                 f'Single invite created for: {invite.email}',
                 'INFO', 'invite', invite.id)
        
        if success:
            flash(f'✅ Invite email sent successfully to {invite.email}', 'success')
        else:
            flash(f'⚠️ Invite created but email failed to send', 'warning')
            flash(f'Error: {error}', 'danger')
            flash(f'Manual link: {registration_url}', 'info')
            if 'getaddrinfo failed' in str(error) or 'resolve' in str(error).lower():
                flash('💡 Tip: Check your internet connection and MAIL_SERVER setting in .env', 'info')
            elif 'authentication' in str(error).lower():
                flash('💡 Tip: For Gmail, use App Password from https://myaccount.google.com/apppasswords', 'info')
        
        return redirect(url_for('admin.list_invites'))
    
    return render_template('admin/invite_single.html', form=form)


@admin_bp.route('/invites/bulk', methods=['GET', 'POST'])
@login_required
@admin_required
def invite_bulk():
    """Invite multiple users"""
    from app.forms import InviteBulkUsersForm
    from app.models import InviteToken, User
    from app.email_utils import send_bulk_invite_emails
    from datetime import timedelta
    import re
    
    form = InviteBulkUsersForm()
    
    if form.validate_on_submit():
        emails_text = form.emails.data.strip()
        if not emails_text:
            flash('Please provide at least one email address', 'danger')
            return render_template('admin/invite_bulk.html', form=form)
        
        # Parse emails (one per line)
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        emails = [line.strip() for line in emails_text.split('\n') if line.strip()]
        
        # Validate and filter emails
        valid_emails = []
        errors = []
        
        for email in emails:
            if not email_pattern.match(email):
                errors.append(f'Invalid email format: {email}')
                continue
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                errors.append(f'User already exists: {email}')
                continue
            
            # Check if valid invite exists
            existing = InviteToken.query.filter_by(email=email, is_used=False).first()
            if existing and existing.is_valid():
                errors.append(f'Valid invite already exists: {email}')
                continue
            
            valid_emails.append(email)
        
        # Create invites with 1 day expiry
        created_invites = []
        expires_at = datetime.utcnow() + timedelta(days=1)
        
        for email in valid_emails:
            token = InviteToken.generate_token()
            invite = InviteToken(
                token=token,
                email=email,
                created_by=current_user.id,
                expires_at=expires_at,
                is_used=False
            )
            db.session.add(invite)
            created_invites.append(invite)
        
        db.session.commit()
        
        # Send emails automatically
        invite_data_list = [
            {
                'email': inv.email,
                'token': inv.token,
                'url': url_for('auth.register', token=inv.token, _external=True)
            }
            for inv in created_invites
        ]
        
        success_count, failed_emails, error_messages = send_bulk_invite_emails(invite_data_list)
        
        log_audit('INVITES_BULK_CREATED', 
                 f'Bulk invites created: {len(created_invites)} invites, {success_count} emails sent',
                 'INFO')
        
        if success_count > 0:
            flash(f'{success_count} invite emails sent successfully', 'success')
        
        if failed_emails:
            flash(f'{len(failed_emails)} emails failed to send. Invites created but need manual sharing.', 'warning')
            for error_msg in error_messages[:5]:  # Show first 5 errors
                flash(error_msg, 'danger')
        
        if errors:
            flash(f'{len(errors)} emails skipped during validation.', 'info')
            for error in errors[:10]:  # Show first 10 errors
                flash(error, 'danger')
        
        return redirect(url_for('admin.list_invites'))
    
    return render_template('admin/invite_bulk.html', form=form)


@admin_bp.route('/invites/<int:invite_id>/revoke', methods=['POST'])
@login_required
@admin_required
def revoke_invite(invite_id):
    """Revoke an unused invite token"""
    from app.models import InviteToken
    
    invite = InviteToken.query.get_or_404(invite_id)
    
    if invite.is_used:
        flash('Cannot revoke used invite token', 'danger')
        return redirect(url_for('admin.list_invites'))
    
    # Mark as expired by setting expiry to past
    invite.expires_at = datetime.utcnow()
    db.session.commit()
    
    log_audit('INVITE_REVOKED', 
             f'Invite revoked for: {invite.email}',
             'WARNING', 'invite', invite.id)
    
    flash(f'Invite for {invite.email} has been revoked', 'success')
    return redirect(url_for('admin.list_invites'))


@admin_bp.route('/invites/<int:invite_id>/resend', methods=['POST'])
@login_required
@admin_required
def resend_invite(invite_id):
    """Get registration URL for an invite"""
    from app.models import InviteToken
    
    invite = InviteToken.query.get_or_404(invite_id)
    
    if invite.is_used:
        flash('This invite has already been used', 'danger')
        return redirect(url_for('admin.list_invites'))
    
    if not invite.is_valid():
        flash('This invite has expired', 'danger')
        return redirect(url_for('admin.list_invites'))
    
    # Generate registration URL
    registration_url = url_for('auth.register', token=invite.token, _external=True)
    
    log_audit('INVITE_RESENT', 
             f'Registration link retrieved for: {invite.email}',
             'INFO', 'invite', invite.id)
    
    flash(f'Registration link: {registration_url}', 'info')
    return redirect(url_for('admin.list_invites'))
