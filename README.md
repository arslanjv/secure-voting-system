# Secure Online Voting System

A production-ready, military-grade secure online voting system built with Flask, implementing **hybrid RSA-4096 + AES-256-GCM** end-to-end encryption, cryptographic verification, invite-based registration and comprehensive security measures following OWASP Top 10, NIST SSDF and UMLSec principles.

##  Security Features

### Cryptographic Security
- **Hybrid RSA-4096 + AES-256-GCM Encryption**: Military-grade vote encryption with per-vote unique keys
- **Ed25519 Digital Signatures**: Cryptographic integrity for tally results (64-byte signatures)
- **Argon2id Password Hashing**: Winner of Password Hashing Competition (memory-hard, GPU-resistant)
- **TOTP Two-Factor Authentication**: RFC 6238 compliant with encrypted secrets at rest
- **Backup Codes**: 10 one-time recovery codes (hashed with Argon2)
- **Immutable Audit Trail**: HMAC-SHA256 blockchain-style cryptographic log chaining
- **Fernet Encryption**: AES-128-CBC for secrets at rest (TOTP, private keys)
- **Invite Token System**: Cryptographically secure one-time-use registration tokens

### Application Security
- **HTTPS/TLS Support**: Self-signed certificate generation included
- **CSRF Protection**: Flask-WTF on all forms
- **XSS Prevention**: CSP headers with nonces, bleach sanitization, Jinja2 auto-escaping
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **Secure Sessions**: HttpOnly, Secure, SameSite=Strict cookies
- **Replay Attack Prevention**: Nonce-based request validation
- **Rate Limiting**: Flask-Limiter on authentication endpoints
- **Account Lockout**: Configurable failed login attempt threshold

### Privacy & Anonymity
- **Voter Anonymity**: No linkage between voter identity and encrypted ballots
- **Individual Verifiability**: Unique verification tokens for vote confirmation
- **Zero-Knowledge Verification**: Confirm vote recorded without revealing choice
- **Controlled Access**: Admin-issued invites prevent unauthorized registration

##  Requirements

- Python 3.11+ (tested on Python 3.12.0, 3.13.1)
- SQLite (development) or PostgreSQL 12+ (production)
- Modern browser with Web Crypto API support
- Email account with SMTP access (Gmail, Outlook, etc.) for invite system

##  Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/arslanjv/secure-voting-system.git
cd secure-voting-system
```

### 2. Create Virtual Environment

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment Configuration

Create `.env` file from template:

```bash
# Windows
copy .env.example .env

# Linux/Mac
cp .env.example .env
```

Edit `.env` file with your settings:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-minimum-32-characters-long
FLASK_ENV=development

# Database (SQLite for development)
DATABASE_URL=sqlite:///instance/voting.db

# Email Configuration (REQUIRED for invite system)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password

# Master Encryption Key (for Fernet - TOTP secrets, private keys)
MASTER_ENCRYPTION_KEY=your-fernet-key-here

# Base URL for invite emails (use your LAN IP for network testing)
BASE_URL=http://localhost:5000

# Timezone (hours offset from UTC)
TIMEZONE_OFFSET=5
```

### 5. Generate Security Keys

```bash
# Generate SECRET_KEY
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"

# Generate MASTER_ENCRYPTION_KEY (Fernet)
python -c "from cryptography.fernet import Fernet; print('MASTER_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```

### 6. Initialize Database

```bash
python init_db.py --with-sample-data
```

### 7. Run Application

**HTTP (Development):**
```bash
python run.py
```
Visit: `http://localhost:5000`

**HTTPS (Recommended for testing encryption):**
```bash
# Generate SSL certificates first
python generate_cert.py

# Run with HTTPS
python run.py
```
Visit: `https://localhost:5001`

**Production:**
```bash
gunicorn -w 4 -b 0.0.0.0:8000 --certfile=cert.pem --keyfile=key.pem run:app
```

##  Project Structure

```
secure-voting-system/
 app/
    __init__.py              # Application factory with security config
    models.py                # Database models (User, Election, Vote, ElectionKeyPair, etc.)
    security.py              # Cryptographic utilities (Argon2, Ed25519, TOTP, AuditLogger)
    crypto_utils.py          # Hybrid encryption (RSA-4096 + AES-256-GCM)
    forms.py                 # WTForms with validation
    email_utils.py           # Email sending functions
    routes/
       admin.py             # Admin routes (elections, invites, users, tally)
       auditor.py           # Auditor routes (audit logs, chain verification)
       auth.py              # Authentication routes (login, register, 2FA)
       main.py              # Public routes
       voter.py             # Voter routes (cast votes, verify)
    static/
       js/
           vote-encrypt.js  # Client-side hybrid RSA+AES encryption
    templates/               # Jinja2 templates
 instance/                    # SQLite database (auto-created)
 keys/                        # Signing keys (auto-generated)
 logs/                        # Application logs
 config.py                    # Configuration classes
 run.py                       # Application entry point (HTTP/HTTPS)
 generate_cert.py             # SSL certificate generator
 init_db.py                   # Database initialization
 requirements.txt             # Python dependencies
 test_owasp_security.py       # OWASP Top 10 security tests (55 tests)
 test_security_fixes.py       # Vulnerability fix verification
 test_endpoints.py            # Endpoint security tests (45 tests)
 test_complete.py             # Complete test suite
 EVALUATION_REPORT.md         # Security evaluation report
 THREAT_MODELING_REPORT.md    # STRIDE threat analysis
 CRITIQUE_REPORT.md           # Self-assessment critique
 README.md                    # This file
```

##  Security Architecture

### Encryption Flow (Hybrid RSA + AES-GCM)

```

                    VOTE ENCRYPTION FLOW                             

                                                                     
   Client (Browser)                    Server (Flask)                
                                      
                                                                     
   1. Request public key > RSA-4096 Public Key         
                         < (per election)              
                                                                     
   2. Generate random AES-256 key                                    
                                                                     
   3. Encrypt vote with AES-256-GCM                                  
      (ciphertext + authentication tag)                              
                                                                     
   4. Encrypt AES key with RSA-OAEP                                  
      (using election public key)                                    
                                                                     
   5. Send encrypted package > Store in database           
      - encrypted_vote (AES ciphertext)                              
      - encrypted_key (RSA-encrypted AES key)                        
      - vote_nonce (IV)                                              
      - vote_tag (GCM auth tag)                                      
                                                                     
   During Tally:                                                     
                                                        
   6. Admin initiates tally > Decrypt RSA private key      
                                        (Fernet-encrypted in DB)     
                                                                     
   7. Decrypt AES key with RSA-OAEP                                  
                                                                     
   8. Decrypt vote with AES-GCM                                      
      (verify authentication tag)                                    
                                                                     
   9. Sign results with Ed25519                                      
                                                                     

```

### Password Security (Argon2id)

```python
# Configuration (OWASP recommended)
PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MB RAM required
    parallelism=4,      # 4 parallel threads
    hash_len=32,        # 256-bit output
    salt_len=16         # 128-bit random salt
)
```

### Two-Factor Authentication (TOTP)

- **Standard**: RFC 6238 (Time-based One-Time Password)
- **Secret Storage**: Fernet-encrypted at rest (VULN-003 fix)
- **Backup Codes**: 10 codes, Argon2-hashed (VULN-007 fix)
- **Time Window**: 30 seconds tolerance

##  Testing

### Run All Security Tests

```bash
# OWASP Top 10 Security Audit (55 tests)
python test_owasp_security.py

# Security Fixes Verification
python test_security_fixes.py

# Endpoint Security Tests (45 tests)
python test_endpoints.py

# Complete Test Suite
python test_complete.py
```

### SAST Security Scanning

```bash
# Bandit - Python SAST
bandit -r app/

# pip-audit - CVE vulnerability scan
pip-audit
```

### Sample Test Output

```
OWASP SECURITY AUDIT - Secure Online Voting System
======================================================================

[A01:2021] Broken Access Control         5/5 PASSED
[A02:2021] Cryptographic Failures        6/6 PASSED
[A03:2021] Injection                     4/4 PASSED
[A04:2021] Insecure Design               5/5 PASSED
[A05:2021] Security Misconfiguration     7/7 PASSED
[A06:2021] Vulnerable Components         3/3 PASSED
[A07:2021] Authentication Failures       6/6 PASSED
[A08:2021] Software Integrity            3/3 PASSED
[A09:2021] Logging & Monitoring          4/4 PASSED
[A10:2021] SSRF Prevention               1/1 PASSED
[API Security] OWASP API Top 10          5/5 PASSED
[CWE] Common Weakness Enumeration        6/6 PASSED

Total Tests: 55 | Passed: 55 (100.0%) | Failed: 0
 ALL SECURITY TESTS PASSED!
```

##  Default Credentials

| Role | Username | Password |
|------|----------|----------|
| Administrator | `admin` | `SecureAdmin2024!` |
| Auditor | `auditor` | `SecureAuditor2024!` |
| Voter | `voter1` | `VoterPass12024!` |
| Voter | `voter2` | `VoterPass22024!` |
| Voter | `voter3` | `VoterPass32024!` |

*Created with `python init_db.py --with-sample-data`*

##  Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Backend | Python Flask | 3.0.0 | Web framework |
| Database | SQLAlchemy | 2.0.23 | ORM |
| Auth | Flask-Login | 0.6.3 | Session management |
| 2FA | pyotp | 2.9.0 | TOTP authentication |
| Encryption | PyCryptodome | 3.19.0 | AES-256-GCM |
| Signatures | cryptography | 43.0.1+ | RSA-4096, Ed25519, Fernet |
| Passwords | Argon2 | 23.1.0 | Password hashing |
| CSRF | Flask-WTF | 1.2.1 | CSRF protection |
| Rate Limit | Flask-Limiter | 3.5.0 | Request throttling |
| Headers | Flask-Talisman | 1.1.0 | Security headers |
| Sanitization | bleach | 6.1.0 | XSS prevention |
| Frontend | Bootstrap 5 | 5.3.2 | UI framework |
| Client Crypto | Web Crypto API | Native | Client-side encryption |

##  Security Vulnerabilities Fixed

| ID | Vulnerability | CWE | Severity | Status |
|----|--------------|-----|----------|--------|
| VULN-001 | Hardcoded encryption keys | CWE-798 | Critical |  Fixed |
| VULN-002 | Weak key derivation | CWE-328 | High |  Fixed |
| VULN-003 | Unencrypted TOTP secrets | CWE-312 | High |  Fixed |
| VULN-004 | Username enumeration | CWE-203 | Medium |  Fixed |
| VULN-005 | Missing CSP nonces | CWE-79 | Medium |  Fixed |
| VULN-006 | XSS in error messages | CWE-79 | Medium |  Fixed |
| VULN-007 | No 2FA backup codes | CWE-308 | Medium |  Fixed |
| VULN-008 | Audit logs not backed up | CWE-778 | Low |  Fixed |
| VULN-009 | Signing keys on filesystem | CWE-312 | Medium |  Fixed |
| VULN-010 | No session version control | CWE-613 | Medium |  Fixed |

##  Security Reports

- **[EVALUATION_REPORT.md](EVALUATION_REPORT.md)** - Complete security evaluation
- **[THREAT_MODELING_REPORT.md](THREAT_MODELING_REPORT.md)** - STRIDE threat analysis
- **[CRITIQUE_REPORT.md](CRITIQUE_REPORT.md)** - Self-assessment critique

##  Security Compliance

-  OWASP Top 10 (2021) - All categories addressed
-  OWASP API Security Top 10 (2023)
-  NIST SSDF - Secure Software Development Framework
-  CWE/SANS Top 25 - Common weaknesses mitigated
-  Individual Verifiability
-  Voter Anonymity

##  License

Copyright  2025. All rights reserved.

---

**Built with security in mind. Every line audited. Every feature hardened.**
**55 OWASP tests | 45 endpoint tests | 0 CVE vulnerabilities**
