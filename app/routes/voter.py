"""
Voter Routes
Voting interface, vote submission, verification
Implements secure voting with encryption and anonymity

SECURITY FIXES:
- VULN-001: Server-side RSA key generation for vote encryption
- VULN-002: Server-side random salt generation
- VULN-005: Rate limiting on nonce generation
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from app.models import db, Election, Candidate, Vote, AuditLog, Nonce, ElectionStatus, ElectionKeyPair
from app.forms import VoteForm, VerifyVoteForm
from app.security import (
    VoteEncryption, DigitalSignature, SecurityUtils, AuditLogger, voter_required
)
from app.crypto_utils import CryptoUtils
from datetime import datetime, timedelta
from app import limiter
import json

voter_bp = Blueprint('voter', __name__)


def log_audit(action, description, severity='INFO', resource_type=None, resource_id=None):
    """Helper to create audit log entry"""
    try:
        previous_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        previous_hash = previous_log.entry_hash if previous_log else None

        # Create timestamp ONCE to ensure consistency
        timestamp = datetime.utcnow()

        entry_data = {
            'timestamp': timestamp.isoformat(),
            'user_id': current_user.id if current_user.is_authenticated else None,
            'action': action,
            'resource_id': resource_id
        }

        entry_hash = AuditLogger.compute_entry_hash(entry_data)
        signature = AuditLogger.sign_entry(entry_hash, previous_hash)

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
        current_app.logger.error(f"Audit log error: {str(e)}")


@voter_bp.route('/dashboard')
@login_required
@voter_required
def dashboard():
    """Voter dashboard showing available elections"""
    # Get active elections
    now = datetime.utcnow()
    active_elections = Election.query.filter(
        Election.status == ElectionStatus.ACTIVE,
        Election.start_time <= now,
        Election.end_time >= now
    ).all()

    # Get elections user has voted in
    voted_election_ids = [v.election_id for v in current_user.votes.all()]

    # Get upcoming elections
    upcoming_elections = Election.query.filter(
        Election.status == ElectionStatus.ACTIVE,
        Election.start_time > now
    ).order_by(Election.start_time).limit(5).all()

    # Get past elections with results
    past_elections = Election.query.filter(
        Election.status == ElectionStatus.TALLIED
    ).order_by(Election.tallied_at.desc()).limit(5).all()

    return render_template('voter/dashboard.html',
                          active_elections=active_elections,
                          voted_election_ids=voted_election_ids,
                          upcoming_elections=upcoming_elections,
                          past_elections=past_elections)


@voter_bp.route('/election/<int:election_id>')
@login_required
@voter_required
def view_election(election_id):
    """View election details and candidates"""
    election = Election.query.get_or_404(election_id)

    # Check if election is active
    if not election.is_active():
        flash('This election is not currently active', 'warning')
        return redirect(url_for('voter.dashboard'))

    # Check if user already voted
    existing_vote = Vote.query.filter_by(
        election_id=election_id,
        voter_id=current_user.id
    ).first()

    if existing_vote and not election.allow_multiple_votes:
        flash('You have already voted in this election', 'info')
        return redirect(url_for('voter.view_receipt', vote_id=existing_vote.id))

    # Get candidates
    candidates = Candidate.query.filter_by(election_id=election_id).order_by(Candidate.order).all()

    return render_template('voter/election.html',
                          election=election,
                          candidates=candidates,
                          has_voted=existing_vote is not None,
                          vote=existing_vote)


@voter_bp.route('/election/<int:election_id>/vote', methods=['GET', 'POST'])
@login_required
@voter_required
def cast_vote(election_id):
    """Cast vote in an election"""
    election = Election.query.get_or_404(election_id)

    # Security checks
    if not election.is_active():
        flash('This election is not currently active', 'danger')
        return redirect(url_for('voter.dashboard'))

    # Check if user already voted
    existing_vote = Vote.query.filter_by(
        election_id=election_id,
        voter_id=current_user.id
    ).first()

    if existing_vote and not election.allow_multiple_votes:
        flash('You have already voted in this election', 'danger')
        return redirect(url_for('voter.dashboard'))

    # Get candidates
    candidates = Candidate.query.filter_by(election_id=election_id).order_by(Candidate.order).all()

    form = VoteForm()
    form.candidate_ids.choices = [(c.id, c.name) for c in candidates]

    if form.validate_on_submit():
        try:
            # Validate request nonce (replay attack prevention)
            nonce_value = form.request_nonce.data
            if not Nonce.is_valid_nonce(nonce_value):
                flash('Invalid or expired request. Please try again.', 'danger')
                log_audit('VOTE_REPLAY_ATTEMPT',
                         f'Replay attack attempt by user {current_user.username} on election {election_id}',
                         'CRITICAL', 'election', election_id)
                return redirect(url_for('voter.cast_vote', election_id=election_id))

            # Store nonce
            nonce = Nonce(
                nonce=nonce_value,
                expires_at=datetime.utcnow() + timedelta(seconds=current_app.config['NONCE_EXPIRY_SECONDS'])
            )
            db.session.add(nonce)

            # Validate number of selections
            selected_candidates = form.candidate_ids.data
            if len(selected_candidates) > election.max_selections:
                flash(f'You can only select up to {election.max_selections} candidate(s)', 'danger')
                return render_template('voter/vote.html', form=form, election=election, candidates=candidates)

            # Verify all selected candidates belong to this election
            valid_candidate_ids = [c.id for c in candidates]
            if not all(cid in valid_candidate_ids for cid in selected_candidates):
                flash('Invalid candidate selection', 'danger')
                return redirect(url_for('voter.cast_vote', election_id=election_id))

            # If replacing vote, delete old one
            if existing_vote and election.allow_multiple_votes:
                db.session.delete(existing_vote)
                log_audit('VOTE_REPLACED',
                         f'Vote replaced by user {current_user.username} in election {election_id}',
                         'INFO', 'election', election_id)

            # Check for encrypted_key field (new hybrid encryption)
            encrypted_key = request.form.get('encrypted_key', '')
            encryption_version = 2 if encrypted_key else 1

            # Create vote record
            vote = Vote(
                encrypted_vote=form.encrypted_vote.data,
                vote_nonce=form.vote_nonce.data,
                vote_tag=form.vote_tag.data,
                encrypted_key=encrypted_key if encrypted_key else None,
                digital_signature=form.digital_signature.data,
                election_id=election_id,
                voter_id=current_user.id,
                verification_token=Vote.generate_verification_token(),
                request_nonce=nonce_value,
                ip_address_hash=SecurityUtils.hash_ip_address(request.remote_addr),
                encryption_version=encryption_version
            )

            db.session.add(vote)
            db.session.commit()

            log_audit('VOTE_CAST',
                     f'Vote cast by user {current_user.username} in election {election_id} (encryption v{encryption_version})',
                     'INFO', 'election', election_id)

            flash('Your vote has been cast successfully!', 'success')
            return redirect(url_for('voter.view_receipt', vote_id=vote.id))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Vote casting error: {str(e)}")
            flash('An error occurred while casting your vote. Please try again.', 'danger')
            return redirect(url_for('voter.cast_vote', election_id=election_id))

    return render_template('voter/vote.html', form=form, election=election, candidates=candidates)


@voter_bp.route('/receipt/<int:vote_id>')
@login_required
@voter_required
def view_receipt(vote_id):
    """View vote receipt with verification token"""
    vote = Vote.query.get_or_404(vote_id)

    # Ensure user owns this vote
    if vote.voter_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('voter.dashboard'))

    election = vote.election

    return render_template('voter/receipt.html', vote=vote, election=election)


@voter_bp.route('/verify', methods=['GET', 'POST'])
def verify_vote():
    """Public vote verification page"""
    form = VerifyVoteForm()

    if form.validate_on_submit():
        token = form.verification_token.data

        vote = Vote.query.filter_by(verification_token=token).first()

        if not vote:
            flash('Invalid verification token', 'danger')
            return render_template('voter/verify.html', form=form)

        election = vote.election

        # Return verification info (without revealing voter identity)
        return render_template('voter/verification_result.html',
                             vote=vote,
                             election=election,
                             verified=True)

    return render_template('voter/verify.html', form=form)


@voter_bp.route('/results/<int:election_id>')
@login_required
def view_results(election_id):
    """View election results (only if tallied)"""
    election = Election.query.get_or_404(election_id)

    if election.status != ElectionStatus.TALLIED:
        flash('Results are not yet available', 'warning')
        return redirect(url_for('voter.dashboard'))

    # Get results
    results = election.get_results()

    if not results:
        flash('Results are not available', 'warning')
        return redirect(url_for('voter.dashboard'))

    # Get candidates
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    candidate_map = {c.id: c for c in candidates}

    return render_template('voter/results.html',
                          election=election,
                          results=results,
                          candidate_map=candidate_map)


@voter_bp.route('/api/generate-nonce')
@login_required
@voter_required
@limiter.limit("60 per minute")  # VULN-005 FIX: Rate limit nonce generation
def generate_nonce():
    """API endpoint to generate nonce for vote submission"""
    nonce = SecurityUtils.generate_nonce()
    return jsonify({'nonce': nonce})


@voter_bp.route('/api/election/<int:election_id>/public-key')
@login_required
@voter_required
@limiter.limit("30 per minute")
def get_election_public_key(election_id):
    """
    Get election public key for client-side vote encryption.
    
    SECURITY FIXES:
    - VULN-001: Generate RSA-4096 key pair per election (server-side)
    - VULN-002: Generate random salt server-side
    
    Returns:
        JSON with public_key (PEM), salt (base64), and election_id
    """
    election = Election.query.get_or_404(election_id)

    if not election.is_active():
        return jsonify({'error': 'Election not active'}), 400
    
    # Check if user has already voted (and multiple votes not allowed)
    if not election.allow_multiple_votes:
        existing_vote = Vote.query.filter_by(
            election_id=election_id,
            voter_id=current_user.id
        ).first()
        if existing_vote:
            return jsonify({'error': 'You have already voted in this election'}), 400

    # Get or create key pair for this election
    keypair = ElectionKeyPair.query.filter_by(election_id=election_id).first()
    
    if not keypair:
        try:
            # Generate new RSA-4096 key pair
            current_app.logger.info(f"Generating RSA keypair for election {election_id}")
            private_pem, public_pem = CryptoUtils.generate_rsa_keypair()
            
            # Encrypt private key before storage
            master_key = current_app.config.get('MASTER_ENCRYPTION_KEY')
            if not master_key:
                current_app.logger.error("MASTER_ENCRYPTION_KEY not configured")
                return jsonify({'error': 'Server configuration error'}), 500
            
            encrypted_private = CryptoUtils.encrypt_private_key(private_pem, master_key)
            
            # Store keypair
            keypair = ElectionKeyPair(
                election_id=election_id,
                encrypted_private_key=encrypted_private,
                public_key=public_pem
            )
            db.session.add(keypair)
            db.session.commit()
            
            log_audit('KEYPAIR_GENERATED',
                     f'RSA keypair generated for election {election_id}',
                     'INFO', 'election', election_id)
                     
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Keypair generation error: {str(e)}")
            return jsonify({'error': 'Failed to generate encryption keys'}), 500

    # Generate random salt for this request (VULN-002 fix)
    salt = CryptoUtils.generate_random_salt()

    return jsonify({
        'public_key': keypair.public_key,
        'salt': salt,
        'election_id': election_id
    })
