"""
Application Entry Point
Run this file to start the Flask application

For HTTPS (required for LAN access):
1. Run: python generate_cert.py (once, to create certificates)
2. Run: python run.py (will auto-detect cert.pem and use HTTPS)
"""
from app import create_app
import os

app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    # Check if SSL certificates exist
    ssl_context = None
    cert_file = 'cert.pem'
    key_file = 'key.pem'
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = (cert_file, key_file)
        print("\n" + "="*60)
        print("HTTPS ENABLED - Using SSL certificates")
        print("="*60)
        print("Access the app at:")
        print("  https://localhost:5000")
        print("  https://127.0.0.1:5000")
        print("  https://<your-lan-ip>:5000")
        print("\nNOTE: Users must accept the browser security warning")
        print("      (click 'Advanced' -> 'Proceed' in Chrome)")
        print("="*60 + "\n")
    else:
        print("\n" + "="*60)
        print("WARNING: Running without HTTPS")
        print("="*60)
        print("Web Crypto API will ONLY work on localhost!")
        print("To enable HTTPS for LAN access, run:")
        print("  python generate_cert.py")
        print("Then restart: python run.py")
        print("="*60 + "\n")
    
    # Development server (do NOT use in production)
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=app.config['DEBUG'],
        ssl_context=ssl_context,
        threaded=True,
        use_reloader=False
    )
