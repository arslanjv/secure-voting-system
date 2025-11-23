"""
Main Routes
Public pages, home, about, etc.
"""
from flask import Blueprint, render_template
from flask_login import current_user
from app.models import Election, ElectionStatus
from datetime import datetime

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Home page"""
    # Show active elections count
    active_count = Election.query.filter(
        Election.status == ElectionStatus.ACTIVE,
        Election.start_time <= datetime.utcnow(),
        Election.end_time >= datetime.utcnow()
    ).count()
    
    return render_template('main/index.html', active_elections=active_count)


@main_bp.route('/about')
def about():
    """About page"""
    return render_template('main/about.html')


@main_bp.route('/security')
def security():
    """Security information page"""
    return render_template('main/security.html')


@main_bp.route('/help')
def help():
    """Help and FAQ page"""
    return render_template('main/help.html')
