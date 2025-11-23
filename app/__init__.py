"""
Application Factory and Initialization
Creates and configures the Flask application with all security measures
"""
from flask import Flask
from flask_login import LoginManager
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import config
import os
import logging
from logging.handlers import RotatingFileHandler


# Initialize extensions (without app)
login_manager = LoginManager()
talisman = Talisman()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)


def create_app(config_name=None):
    """
    Application factory pattern
    Creates and configures Flask application instance
    """
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize logging
    setup_logging(app)
    
    # Initialize extensions
    init_extensions(app)
    
    # Create database tables
    with app.app_context():
        from app.models import db
        db.create_all()
        app.logger.info('Database tables created')
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Setup security measures
    setup_security(app)
    
    # Register template filters
    register_template_filters(app)
    
    app.logger.info(f'Application started in {config_name} mode')
    
    return app


def init_extensions(app):
    """Initialize Flask extensions"""
    from app.models import db, User
    
    # Database
    db.init_app(app)
    
    # Login Manager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Flask-Talisman (Security Headers)
    talisman.init_app(
        app,
        force_https=app.config['TALISMAN_FORCE_HTTPS'],
        strict_transport_security=app.config['TALISMAN_STRICT_TRANSPORT_SECURITY'],
        strict_transport_security_max_age=app.config['TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE'],
        content_security_policy=app.config['TALISMAN_CONTENT_SECURITY_POLICY'],
        content_security_policy_nonce_in=app.config['TALISMAN_CONTENT_SECURITY_POLICY_NONCE_IN']
    )
    
    # Rate Limiter
    limiter.init_app(app)
    
    # CSRF Protection (handled by Flask-WTF forms)
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect()
    csrf.init_app(app)
    
    app.logger.info('Extensions initialized')


def register_blueprints(app):
    """Register application blueprints"""
    from app.routes.auth import auth_bp
    from app.routes.voter import voter_bp
    from app.routes.admin import admin_bp
    from app.routes.auditor import auditor_bp
    from app.routes.main import main_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(voter_bp, url_prefix='/voter')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(auditor_bp, url_prefix='/auditor')
    
    app.logger.info('Blueprints registered')


def register_error_handlers(app):
    """Register custom error handlers"""
    from flask import render_template
    
    @app.errorhandler(400)
    def bad_request(e):
        return render_template('errors/400.html'), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        return render_template('errors/401.html'), 401
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return render_template('errors/429.html'), 429
    
    @app.errorhandler(500)
    def internal_server_error(e):
        app.logger.error(f'Internal server error: {str(e)}')
        return render_template('errors/500.html'), 500
    
    app.logger.info('Error handlers registered')


def setup_security(app):
    """Setup additional security measures"""
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('keys', exist_ok=True)
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'app/static/uploads'), exist_ok=True)
    
    # Generate cryptographic keys if they don't exist
    from app.security import DigitalSignature
    
    private_key_path = app.config['DIGITAL_SIGNATURE_PRIVATE_KEY_PATH']
    public_key_path = app.config['DIGITAL_SIGNATURE_PUBLIC_KEY_PATH']
    
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        app.logger.warning('Generating new digital signature keypair')
        private_pem, public_pem = DigitalSignature.generate_keypair()
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        app.logger.info('Digital signature keypair generated')
    
    # Session configuration
    app.config['SESSION_COOKIE_SECURE'] = app.config.get('SESSION_COOKIE_SECURE', True)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    
    app.logger.info('Security measures configured')


def setup_logging(app):
    """Setup application logging"""
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Application log
    if not app.debug:
        file_handler = RotatingFileHandler(
            app.config.get('LOG_FILE', 'logs/app.log'),
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
        app.logger.addHandler(file_handler)
    
    app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
    app.logger.info('Logging configured')


def register_template_filters(app):
    """Register custom Jinja2 template filters"""
    from datetime import timedelta
    
    @app.template_filter('to_local_time')
    def to_local_time(utc_datetime):
        """Convert UTC datetime to local timezone for display"""
        if utc_datetime is None:
            return None
        offset = timedelta(hours=app.config.get('LOCAL_TIMEZONE_OFFSET', 0))
        return utc_datetime + offset
    
    @app.template_filter('format_local_datetime')
    def format_local_datetime(utc_datetime, format='%Y-%m-%d %H:%M'):
        """Convert UTC to local time and format for display"""
        if utc_datetime is None:
            return 'N/A'
        local_time = to_local_time(utc_datetime)
        return local_time.strftime(format)
    
    app.logger.info('Template filters registered')
