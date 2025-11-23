"""
Application Entry Point
Run this file to start the Flask application
"""
from app import create_app
import os

app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    # Development server (do NOT use in production)
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app.config['DEBUG']
    )
