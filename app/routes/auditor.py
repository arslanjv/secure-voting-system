"""
Auditor Routes
Read-only access to audit logs and verification tools
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, current_app
from flask_login import login_required, current_user
from app.models import db, AuditLog, Election, Vote, User
from app.forms import ExportAuditLogForm
from app.security import auditor_required, AuditLogger
from datetime import datetime
import csv
from io import StringIO, BytesIO

auditor_bp = Blueprint('auditor', __name__)


@auditor_bp.route('/dashboard')
@login_required
@auditor_required
def dashboard():
    """Auditor dashboard"""
    # Statistics
    total_logs = AuditLog.query.count()
    total_elections = Election.query.count()
    total_votes = Vote.query.count()
    
    # Recent critical/warning logs
    critical_logs = AuditLog.query.filter(
        AuditLog.severity.in_(['CRITICAL', 'WARNING'])
    ).order_by(AuditLog.timestamp.desc()).limit(20).all()
    
    # Recent audit logs
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    
    return render_template('auditor/dashboard.html',
                          total_logs=total_logs,
                          total_elections=total_elections,
                          total_votes=total_votes,
                          critical_logs=critical_logs,
                          recent_logs=recent_logs)


@auditor_bp.route('/logs')
@login_required
@auditor_required
def view_logs():
    """View all audit logs with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filters
    action_filter = request.args.get('action', '')
    severity_filter = request.args.get('severity', '')
    user_filter = request.args.get('user', '')
    
    query = AuditLog.query
    
    if action_filter:
        query = query.filter(AuditLog.action.contains(action_filter))
    
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    
    if user_filter:
        query = query.filter(AuditLog.username.contains(user_filter))
    
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('auditor/logs.html', 
                          logs=logs,
                          action_filter=action_filter,
                          severity_filter=severity_filter,
                          user_filter=user_filter)


@auditor_bp.route('/logs/<int:log_id>')
@login_required
@auditor_required
def view_log_detail(log_id):
    """View detailed audit log entry"""
    log = AuditLog.query.get_or_404(log_id)
    
    # Get previous and next log for chain verification
    previous_log = AuditLog.query.filter(AuditLog.id < log_id).order_by(AuditLog.id.desc()).first()
    next_log = AuditLog.query.filter(AuditLog.id > log_id).order_by(AuditLog.id).first()
    
    return render_template('auditor/log_detail.html',
                          log=log,
                          previous_log=previous_log,
                          next_log=next_log)


@auditor_bp.route('/verify-chain', methods=['GET', 'POST'])
@login_required
@auditor_required
def verify_chain():
    """Verify integrity of audit log chain"""
    try:
        # Get all logs in order
        logs = AuditLog.query.order_by(AuditLog.id).all()
        
        if len(logs) == 0:
            flash('No audit logs to verify', 'info')
            return redirect(url_for('auditor.dashboard'))
        
        # Verify chain
        is_valid, broken_at = AuditLogger.verify_log_chain(logs)
        
        if is_valid:
            flash(f'Audit log chain verified successfully! Total logs: {len(logs)}', 'success')
        else:
            flash(f'Audit log chain integrity violation detected at log ID {logs[broken_at].id}!', 'danger')
        
        return render_template('auditor/verify_chain.html',
                              is_valid=is_valid,
                              broken_at=broken_at,
                              total_logs=len(logs),
                              logs=logs)
        
    except Exception as e:
        current_app.logger.error(f"Chain verification error: {str(e)}")
        flash('Error verifying audit log chain', 'danger')
        return redirect(url_for('auditor.dashboard'))


@auditor_bp.route('/export', methods=['GET', 'POST'])
@login_required
@auditor_required
def export_logs():
    """Export audit logs as CSV"""
    form = ExportAuditLogForm()
    
    if form.validate_on_submit():
        try:
            query = AuditLog.query
            
            # Apply filters
            if form.start_date.data:
                query = query.filter(AuditLog.timestamp >= form.start_date.data)
            
            if form.end_date.data:
                query = query.filter(AuditLog.timestamp <= form.end_date.data)
            
            if form.action_filter.data:
                query = query.filter(AuditLog.action.contains(form.action_filter.data))
            
            logs = query.order_by(AuditLog.timestamp).all()
            
            # Create CSV
            output = StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                'ID', 'Timestamp', 'User', 'Role', 'Action', 
                'Resource Type', 'Resource ID', 'Description',
                'IP Address', 'Severity', 'Entry Hash', 'Previous Hash'
            ])
            
            # Data
            for log in logs:
                writer.writerow([
                    log.id,
                    log.timestamp.isoformat(),
                    log.username or 'N/A',
                    log.user_role or 'N/A',
                    log.action,
                    log.resource_type or 'N/A',
                    log.resource_id or 'N/A',
                    log.description or 'N/A',
                    log.ip_address or 'N/A',
                    log.severity,
                    log.entry_hash,
                    log.previous_hash or 'N/A'
                ])
            
            # Return as downloadable file
            output.seek(0)
            return send_file(
                BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'audit_logs_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
            )
            
        except Exception as e:
            current_app.logger.error(f"Export error: {str(e)}")
            flash('Error exporting audit logs', 'danger')
            return redirect(url_for('auditor.export_logs'))
    
    return render_template('auditor/export.html', form=form)


@auditor_bp.route('/elections')
@login_required
@auditor_required
def view_elections():
    """View all elections (read-only)"""
    elections = Election.query.order_by(Election.created_at.desc()).all()
    return render_template('auditor/elections.html', elections=elections)


@auditor_bp.route('/elections/<int:election_id>')
@login_required
@auditor_required
def view_election(election_id):
    """View election details (read-only)"""
    from app.models import Candidate
    
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    vote_count = Vote.query.filter_by(election_id=election_id).count()
    
    return render_template('auditor/election_detail.html',
                          election=election,
                          candidates=candidates,
                          vote_count=vote_count)


@auditor_bp.route('/users')
@login_required
@auditor_required
def view_users():
    """View all users (read-only)"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('auditor/users.html', users=users)
