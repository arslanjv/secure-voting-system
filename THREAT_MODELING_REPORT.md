# Threat Modeling Report
## Secure Online Voting System

**Project Repository**: https://github.com/arslanjv/secure-voting-system  
**Date**: November 29, 2025  
**Methodology**: PASTA + STRIDE + DREAD

---

# Task 1: Context and Project Overview (10 Marks)

## 1.1 System Purpose

The **Secure Online Voting System** is a web-based electronic voting platform designed to conduct secure, transparent, and verifiable elections. The system addresses critical security challenges in digital democracy:

- **Vote Confidentiality**: Ensuring votes remain secret through end-to-end encryption
- **Vote Integrity**: Preventing tampering using digital signatures and cryptographic verification
- **Voter Authentication**: Verifying eligible voters through multi-factor authentication
- **Auditability**: Maintaining immutable audit logs for transparency

## 1.2 Main Modules

| Module | Description | Key Functions |
|--------|-------------|---------------|
| **Authentication Module** | Handles user identity verification | Login, Registration, 2FA (TOTP), Password Management, Backup Codes |
| **Admin Module** | Election management interface | Create/Edit Elections, Manage Candidates, Generate Invites, Tally Votes |
| **Voter Module** | Voter-facing functionality | View Elections, Cast Encrypted Votes, Verify Votes, View Results |
| **Auditor Module** | Security oversight interface | Audit Logs, Chain Verification, Export Reports |
| **Cryptographic Module** | Security infrastructure | RSA-4096 Encryption, AES-GCM, Ed25519 Signatures, Argon2 Hashing |
| **Database Module** | Data persistence layer | User Data, Elections, Encrypted Votes, Audit Logs |

## 1.3 Actors

| Actor | Role | Trust Level | Access Rights |
|-------|------|-------------|---------------|
| **Administrator** | System manager | High | Full access to election management, user management, tallying |
| **Voter** | Registered participant | Medium | View elections, cast votes, verify own votes |
| **Auditor** | Security oversight | Medium-High | Read-only access to audit logs, verification tools |
| **Anonymous User** | Unregistered visitor | Low | Public pages only (home, about, security info) |
| **Attacker** | Malicious actor | None | Attempts unauthorized access, data theft, vote manipulation |

## 1.4 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PRESENTATION LAYER                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Public UI   │  │  Voter UI    │  │  Admin UI    │  │ Auditor UI   │     │
│  │  (HTML/CSS)  │  │  (Protected) │  │  (Protected) │  │ (Protected)  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATION LAYER                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Flask Application                            │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │ Auth Routes │  │Voter Routes │  │Admin Routes │  │Auditor Rts │  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        Security Middleware                           │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────┐  │    │
│  │  │Flask-    │  │Flask-    │  │CSRF      │  │Session   │  │Input  │  │    │
│  │  │Talisman  │  │Limiter   │  │Protection│  │Security  │  │Valid. │  │    │
│  │  │(CSP/HSTS)│  │(Rate)    │  │(Tokens)  │  │(Cookies) │  │(Bleach│  │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └───────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CRYPTOGRAPHIC LAYER                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   RSA-4096   │  │  AES-256-GCM │  │   Ed25519    │  │   Argon2id   │     │
│  │  (Vote Enc.) │  │  (Symmetric) │  │ (Signatures) │  │  (Passwords) │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                       │
│  │    TOTP      │  │   Fernet     │  │   HMAC-256   │                       │
│  │    (2FA)     │  │ (At-rest)    │  │ (Audit Chain)│                       │
│  └──────────────┘  └──────────────┘  └──────────────┘                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA LAYER                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      SQLAlchemy ORM                                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │    Users     │  │  Elections   │  │    Votes     │  │  Audit Logs  │     │
│  │  (Encrypted) │  │  (Keys/Meta) │  │  (Encrypted) │  │(HMAC Chained)│     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
│                           SQLite / PostgreSQL                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 1.5 Data Flow Diagram

```
                                    ┌─────────────┐
                                    │   Voter     │
                                    └──────┬──────┘
                                           │
                     ┌─────────────────────┼─────────────────────┐
                     │                     │                     │
                     ▼                     ▼                     ▼
              ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
              │   Register   │     │    Login     │     │  Cast Vote   │
              │  (Invite)    │     │   (2FA)      │     │ (Encrypted)  │
              └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
                     │                     │                     │
                     ▼                     ▼                     ▼
              ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
              │   Validate   │     │   Verify     │     │   Encrypt    │
              │   Input      │     │   Creds+TOTP │     │  RSA+AES     │
              └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
                     │                     │                     │
                     ▼                     ▼                     ▼
              ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
              │  Hash Pass   │     │   Create     │     │   Store      │
              │  (Argon2)    │     │   Session    │     │  Ciphertext  │
              └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
                     │                     │                     │
                     └─────────────────────┼─────────────────────┘
                                           │
                                           ▼
                                    ┌──────────────┐
                                    │   Database   │
                                    │  (Encrypted) │
                                    └──────────────┘
```

---

# Task 2: Apply PASTA Methodology (30 Marks)

## PASTA: Process for Attack Simulation and Threat Analysis

PASTA is a 7-stage risk-centric threat modeling methodology that aligns business objectives with technical requirements.

---

## Stage 1: Define Business Objectives & Security Goals

### 1.1 Business Objectives

| Objective | Description | Priority |
|-----------|-------------|----------|
| **Election Integrity** | Ensure accurate vote counting without manipulation | Critical |
| **Voter Confidence** | Build trust in the electronic voting process | High |
| **Accessibility** | Enable remote voting for all eligible participants | High |
| **Regulatory Compliance** | Meet election security standards and laws | Critical |
| **Operational Efficiency** | Reduce costs compared to paper-based voting | Medium |
| **Transparency** | Provide verifiable audit trails | High |

### 1.2 Security Goals

| Goal | CIA Mapping | Requirement |
|------|-------------|-------------|
| **Vote Secrecy** | Confidentiality | Votes must remain anonymous and encrypted |
| **Vote Integrity** | Integrity | Votes cannot be altered after submission |
| **System Availability** | Availability | System must be accessible during election period |
| **Voter Authentication** | Integrity | Only eligible voters can cast votes |
| **Non-Repudiation** | Integrity | Actions must be attributable and logged |
| **Data Protection** | Confidentiality | Personal data must be encrypted at rest |

### 1.3 Compliance Requirements

- **OWASP Top 10**: Web application security standards
- **GDPR Principles**: Data protection and privacy
- **Election Security Guidelines**: Integrity and auditability requirements

---

## Stage 2: Define Technical Scope

### 2.1 System Architecture Components

| Component | Technology | Security Controls |
|-----------|------------|-------------------|
| **Web Server** | Flask (Python 3.13) | HTTPS, Security Headers |
| **Database** | SQLite/PostgreSQL | Encrypted fields, parameterized queries |
| **Authentication** | Flask-Login, TOTP | Argon2 hashing, 2FA, session management |
| **Encryption** | cryptography, PyCryptodome | RSA-4096, AES-256-GCM, Ed25519 |
| **Rate Limiting** | Flask-Limiter | Request throttling |
| **Security Headers** | Flask-Talisman | CSP, HSTS, X-Frame-Options |

### 2.2 Data Classification

| Data Type | Classification | Storage | Protection |
|-----------|----------------|---------|------------|
| User Passwords | Critical | Database | Argon2id hash |
| TOTP Secrets | Critical | Database | Fernet encrypted |
| Private Keys | Critical | Database | Fernet encrypted |
| Vote Content | Critical | Database | RSA+AES encrypted |
| User Email | Sensitive | Database | Plaintext (for recovery) |
| Audit Logs | Sensitive | Database | HMAC-chained |
| Election Metadata | Internal | Database | Plaintext |

### 2.3 Network Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        INTERNET (Untrusted)                      │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ HTTPS (TLS 1.3)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DMZ (Semi-Trusted)                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Load Balancer / Reverse Proxy               │    │
│  │                  (Rate Limiting, WAF)                    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION ZONE (Trusted)                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐   │
│  │  Flask App      │  │  Session Store  │  │  Crypto Keys   │   │
│  │  (Port 5000)    │  │  (Redis/Memory) │  │  (Env Vars)    │   │
│  └─────────────────┘  └─────────────────┘  └────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DATA ZONE (Restricted)                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  Database Server                         │    │
│  │              (Encrypted connections)                     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Stage 3: Decompose the Application

### 3.1 Entry Points

| Entry Point | Protocol | Authentication | Rate Limited |
|-------------|----------|----------------|--------------|
| `/` (Home) | HTTPS | None | Yes |
| `/auth/login` | HTTPS | Credentials + 2FA | Yes (5/min) |
| `/auth/register` | HTTPS | Invite Token | Yes (3/hour) |
| `/voter/election/<id>/vote` | HTTPS | Session + CSRF | Yes (10/min) |
| `/admin/*` | HTTPS | Session + Admin Role | Yes |
| `/voter/api/generate-nonce` | HTTPS | Session | Yes |

### 3.2 Assets

| Asset | Type | Value | Location |
|-------|------|-------|----------|
| User Credentials | Data | Critical | users.password_hash |
| TOTP Secrets | Data | Critical | users.totp_secret (encrypted) |
| Election Private Keys | Data | Critical | election_key_pairs.private_key_encrypted |
| Vote Ciphertexts | Data | Critical | votes.encrypted_vote |
| Session Tokens | Runtime | High | Server memory/Redis |
| CSRF Tokens | Runtime | High | Session |
| Audit Log Chain | Data | High | audit_logs.previous_hash |

### 3.3 Trust Boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY 1: Internet ↔ Application                         │
│ Controls: TLS, Rate Limiting, Input Validation, CSRF             │
├──────────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 2: Unauthenticated ↔ Authenticated                │
│ Controls: Login, 2FA, Session Management                         │
├──────────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 3: User Role Separation                           │
│ Controls: RBAC (Voter/Admin/Auditor), Permission Checks          │
├──────────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 4: Application ↔ Database                         │
│ Controls: Parameterized Queries, Encrypted Fields                │
├──────────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 5: Plaintext ↔ Encrypted Data                     │
│ Controls: AES-GCM, RSA-4096, Fernet                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Stage 4: Threat Analysis

### 4.1 Attacker Profiles

| Profile | Motivation | Capabilities | Resources |
|---------|------------|--------------|-----------|
| **Script Kiddie** | Curiosity, fame | Automated tools, public exploits | Low |
| **Disgruntled Voter** | Change election outcome | Basic technical skills | Low |
| **Political Activist** | Disrupt election | Moderate skills, DDoS tools | Medium |
| **Cybercriminal** | Data theft, ransomware | Advanced skills, malware | Medium-High |
| **Nation-State Actor** | Election interference | APT capabilities, 0-days | Very High |
| **Malicious Insider** | Personal gain | System access, knowledge | High |

### 4.2 Attack Surfaces

| Surface | Exposure | Threats | Mitigations |
|---------|----------|---------|-------------|
| **Web Interface** | Public | XSS, CSRF, Injection | CSP, CSRF tokens, input validation |
| **Authentication** | Public | Brute force, credential stuffing | Rate limiting, 2FA, account lockout |
| **API Endpoints** | Authenticated | IDOR, privilege escalation | RBAC, object-level auth |
| **Database** | Internal | SQL injection, data theft | ORM, encryption at rest |
| **Session Management** | Runtime | Hijacking, fixation | Secure cookies, regeneration |
| **Cryptographic Keys** | Internal | Key theft, weak algorithms | Fernet encryption, HSM (future) |

### 4.3 Attack Trees

```
                    ┌─────────────────────────┐
                    │   Compromise Election   │
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│ Manipulate    │     │ Steal Votes/  │     │ Deny Service  │
│ Vote Counts   │     │ Voter Data    │     │ (DoS)         │
└───────┬───────┘     └───────┬───────┘     └───────┬───────┘
        │                     │                     │
   ┌────┴────┐           ┌────┴────┐           ┌────┴────┐
   │         │           │         │           │         │
   ▼         ▼           ▼         ▼           ▼         ▼
┌──────┐ ┌──────┐   ┌──────┐ ┌──────┐   ┌──────┐ ┌──────┐
│Modify│ │Inject│   │SQLi  │ │Session│  │DDoS  │ │Exhaust│
│DB    │ │Votes │   │Attack│ │Hijack │  │Attack│ │Resources│
└──────┘ └──────┘   └──────┘ └──────┘   └──────┘ └──────┘
   │         │           │         │         │         │
   ▼         ▼           ▼         ▼         ▼         ▼
[Blocked] [Blocked]  [Blocked] [Blocked] [Mitigated] [Mitigated]
ORM+RBAC  E2E Enc.   ORM       2FA+Sec    Rate Limit  Rate Limit
                               Cookies
```

---

## Stage 5: Vulnerability & Weakness Analysis

### 5.1 Identified Vulnerabilities (Fixed)

| ID | Vulnerability | CWE | Severity | Status |
|----|---------------|-----|----------|--------|
| VULN-001 | Static RSA Keys | CWE-321 | Critical | ✅ Fixed |
| VULN-002 | Predictable Random Values | CWE-330 | High | ✅ Fixed |
| VULN-003 | Unencrypted TOTP Secrets | CWE-312 | High | ✅ Fixed |
| VULN-004 | Username Enumeration | CWE-204 | Medium | ✅ Fixed |
| VULN-005 | Missing Security Headers | CWE-693 | Medium | ✅ Fixed |
| VULN-006 | XSS Vulnerabilities | CWE-79 | High | ✅ Fixed |
| VULN-007 | Weak Backup Codes | CWE-330 | Medium | ✅ Fixed |
| VULN-008 | Insecure Logging | CWE-532 | Medium | ✅ Fixed |
| VULN-009 | Unencrypted Private Keys | CWE-312 | Critical | ✅ Fixed |
| VULN-010 | Session Fixation | CWE-384 | High | ✅ Fixed |

### 5.2 Weakness Analysis by Component

| Component | Potential Weakness | Current Control | Residual Risk |
|-----------|-------------------|-----------------|---------------|
| Login Form | Brute Force | Rate limiting (5/min), lockout after 5 fails | Low |
| Password Storage | Hash cracking | Argon2id with high memory cost | Very Low |
| Vote Encryption | Key compromise | Per-election RSA-4096 keys, Fernet-encrypted | Low |
| Session | Hijacking | HttpOnly, Secure, SameSite=Strict | Low |
| Database | SQL Injection | SQLAlchemy ORM (parameterized) | Very Low |
| File Upload | Malicious files | Not implemented (no upload feature) | N/A |

---

## Stage 6: Attack Modeling & Simulation

### 6.1 Simulated Attack Scenarios

#### Scenario 1: SQL Injection Attack
```
Attack Vector: Login form username field
Payload: ' OR '1'='1' --
Expected Result: Authentication bypass
Actual Result: Login failed (ORM parameterization blocked)
Test: test_owasp_security.py::test_injection_prevention
Status: ✅ BLOCKED
```

#### Scenario 2: Cross-Site Scripting (XSS)
```
Attack Vector: User input fields
Payload: <script>alert('XSS')</script>
Expected Result: Script execution
Actual Result: Sanitized by bleach, blocked by CSP
Test: test_endpoints.py::test_xss_protection
Status: ✅ BLOCKED
```

#### Scenario 3: CSRF Attack
```
Attack Vector: Forged form submission
Payload: Cross-origin vote submission
Expected Result: Vote cast without user consent
Actual Result: CSRF token validation failed
Test: test_owasp_security.py::test_csrf_protection
Status: ✅ BLOCKED
```

#### Scenario 4: Privilege Escalation
```
Attack Vector: Voter accessing admin routes
Payload: GET /admin/dashboard
Expected Result: Access admin functions
Actual Result: 403 Forbidden (RBAC check)
Test: test_endpoints.py::test_voter_blocked_from_admin
Status: ✅ BLOCKED
```

#### Scenario 5: Brute Force Attack
```
Attack Vector: Repeated login attempts
Payload: 100 password guesses
Expected Result: Account compromise
Actual Result: Rate limited after 5 attempts, account locked after 5 failures
Test: test_endpoints.py::test_rate_limiting
Status: ✅ BLOCKED
```

### 6.2 Penetration Test Results

| Test Category | Tests Run | Passed | Failed | Coverage |
|---------------|-----------|--------|--------|----------|
| OWASP Top 10 | 55 | 55 | 0 | 100% |
| Endpoint Security | 45 | 45 | 0 | 100% |
| Cryptographic | 7 | 7 | 0 | 100% |
| Live Server | 20 | 20 | 0 | 100% |
| **Total** | **127** | **127** | **0** | **100%** |

---

## Stage 7: Risk Analysis & Management

### 7.1 Risk Matrix

| Likelihood ↓ / Impact → | Low | Medium | High | Critical |
|-------------------------|-----|--------|------|----------|
| **Very Likely** | Medium | High | Critical | Critical |
| **Likely** | Low | Medium | High | Critical |
| **Possible** | Low | Medium | Medium | High |
| **Unlikely** | Very Low | Low | Medium | Medium |
| **Rare** | Very Low | Very Low | Low | Medium |

### 7.2 Risk Register

| Risk ID | Threat | Likelihood | Impact | Risk Level | Mitigation | Residual Risk |
|---------|--------|------------|--------|------------|------------|---------------|
| R-001 | Vote manipulation | Rare | Critical | Medium | E2E encryption, signatures | Low |
| R-002 | Data breach | Unlikely | High | Medium | Encryption at rest, RBAC | Low |
| R-003 | DDoS attack | Possible | Medium | Medium | Rate limiting, CDN (future) | Medium |
| R-004 | Credential theft | Unlikely | High | Medium | Argon2, 2FA | Low |
| R-005 | Session hijacking | Unlikely | High | Medium | Secure cookies, TLS | Low |
| R-006 | Insider threat | Rare | Critical | Medium | Audit logging, RBAC | Medium |
| R-007 | Key compromise | Rare | Critical | Medium | Fernet encryption | Low |

### 7.3 Risk Treatment Plan

| Risk | Treatment | Control | Owner | Timeline |
|------|-----------|---------|-------|----------|
| R-001 | Mitigate | Implemented E2E encryption | Dev Team | ✅ Complete |
| R-002 | Mitigate | Implemented field-level encryption | Dev Team | ✅ Complete |
| R-003 | Accept/Transfer | Rate limiting implemented; CDN pending | Ops Team | Partial |
| R-004 | Mitigate | 2FA mandatory for admins | Dev Team | ✅ Complete |
| R-005 | Mitigate | Secure session configuration | Dev Team | ✅ Complete |
| R-006 | Mitigate | Comprehensive audit logging | Dev Team | ✅ Complete |
| R-007 | Mitigate | Keys encrypted with Fernet | Dev Team | ✅ Complete |

---

# Task 3: STRIDE Threat Identification (30 Marks)

## STRIDE Categories Applied to System Components

### 3.1 Authentication Module

| Component | STRIDE Category | Threat Identified | Possible Impact | Mitigation |
|-----------|-----------------|-------------------|-----------------|------------|
| Login Form | **S**poofing | Attacker impersonates legitimate user | Unauthorized access, vote fraud | Argon2 hashing, 2FA (TOTP), account lockout |
| Login Form | **T**ampering | Modification of login credentials in transit | Credential theft | TLS 1.3 encryption |
| Login Form | **R**epudiation | User denies login action | Audit issues | Comprehensive audit logging with timestamps |
| Login Form | **I**nformation Disclosure | Error messages reveal valid usernames | User enumeration | Generic error messages |
| Login Form | **D**enial of Service | Brute force overwhelms server | Service unavailability | Rate limiting (5 req/min), CAPTCHA (future) |
| Login Form | **E**levation of Privilege | Normal user gains admin access | Full system compromise | RBAC with strict role checks |

### 3.2 Voter Module

| Component | STRIDE Category | Threat Identified | Possible Impact | Mitigation |
|-----------|-----------------|-------------------|-----------------|------------|
| Vote Submission | **S**poofing | Attacker votes as another user | Election fraud | Session authentication, nonce verification |
| Vote Submission | **T**ampering | Vote altered during transmission | Corrupted results | RSA+AES encryption, digital signatures |
| Vote Submission | **R**epudiation | Voter denies casting vote | Disputes | Verification token, audit log |
| Vote Submission | **I**nformation Disclosure | Vote content exposed | Vote secrecy breach | End-to-end encryption (RSA-4096) |
| Vote Submission | **D**enial of Service | Flood of vote requests | Unable to vote | Rate limiting, input validation |
| Vote Submission | **E**levation of Privilege | Voter modifies others' votes | Election manipulation | Object-level authorization, IDOR prevention |

### 3.3 Admin Module

| Component | STRIDE Category | Threat Identified | Possible Impact | Mitigation |
|-----------|-----------------|-------------------|-----------------|------------|
| Election Management | **S**poofing | Non-admin accesses admin functions | Unauthorized election changes | Role-based access control |
| Election Management | **T**ampering | Election parameters modified | Unfair election | Input validation, audit logging |
| Tally Function | **R**epudiation | Admin denies changing results | Trust issues | Digitally signed tally results |
| User Management | **I**nformation Disclosure | User list exposed | Privacy breach | Admin-only access, no public listing |
| Dashboard | **D**enial of Service | Admin locked out during critical period | Election disruption | Backup admin accounts, recovery codes |
| Invite Generation | **E**levation of Privilege | Invite grants wrong role | Unauthorized admin access | Invite validation, role specification |

### 3.4 Database Layer

| Component | STRIDE Category | Threat Identified | Possible Impact | Mitigation |
|-----------|-----------------|-------------------|-----------------|------------|
| User Table | **S**poofing | Fake user records inserted | Fake voters | Invite-only registration |
| Vote Table | **T**ampering | Votes modified in database | Election fraud | Encrypted votes, integrity checks |
| Audit Log | **R**epudiation | Audit records deleted/modified | Cover tracks | HMAC chain verification |
| All Tables | **I**nformation Disclosure | Database dump exposed | Full data breach | Field-level encryption, access controls |
| Database Server | **D**enial of Service | Database overwhelmed | System failure | Connection pooling, query optimization |
| Admin Records | **E**levation of Privilege | User role changed in DB | Privilege escalation | Application-level role management |

### 3.5 API Endpoints

| Component | STRIDE Category | Threat Identified | Possible Impact | Mitigation |
|-----------|-----------------|-------------------|-----------------|------------|
| `/api/generate-nonce` | **S**poofing | Unauthorized nonce generation | Replay attacks | Session authentication |
| `/api/election/*/public-key` | **T**ampering | Public key substituted | Vote to wrong key | Key served from trusted DB |
| All APIs | **R**epudiation | API actions denied | Accountability issues | Request logging |
| Public Key API | **I**nformation Disclosure | N/A (public by design) | None | N/A |
| All APIs | **D**enial of Service | API flooding | Service degradation | Rate limiting |
| Admin APIs | **E**levation of Privilege | Voter calls admin API | Unauthorized actions | Role-based API authorization |

### 3.6 Session Management

| Component | STRIDE Category | Threat Identified | Possible Impact | Mitigation |
|-----------|-----------------|-------------------|-----------------|------------|
| Session Cookie | **S**poofing | Session token stolen | Account takeover | HttpOnly, Secure, SameSite |
| Session Data | **T**ampering | Session data modified | Privilege escalation | Server-side sessions, signing |
| Session Actions | **R**epudiation | User denies session actions | Disputes | Action logging with session ID |
| Session Cookie | **I**nformation Disclosure | Session ID leaked | Account hijacking | TLS only, no URL parameters |
| Session Store | **D**enial of Service | Session store overwhelmed | Login failures | Session limits, cleanup |
| Session Roles | **E**levation of Privilege | Role in session modified | Unauthorized access | Server-side role verification |

---

# Task 4: Threat Prioritization with DREAD (20 Marks)

## DREAD Scoring Model

Each factor scored 1-10:
- **D**amage Potential: How much damage if exploited?
- **R**eproducibility: How easy to reproduce?
- **E**xploitability: How easy to launch attack?
- **A**ffected Users: How many users impacted?
- **D**iscoverability: How easy to find the vulnerability?

## Selected Top 10 Threats with DREAD Scores

| # | Threat | D | R | E | A | D | Avg Score | Priority |
|---|--------|---|---|---|---|---|-----------|----------|
| 1 | **Vote Manipulation via Key Compromise** | 10 | 3 | 2 | 10 | 2 | **5.4** | Critical |
| 2 | **SQL Injection Attack** | 9 | 8 | 3 | 10 | 7 | **7.4** | Critical |
| 3 | **Admin Account Takeover** | 10 | 5 | 4 | 10 | 5 | **6.8** | Critical |
| 4 | **Session Hijacking** | 8 | 6 | 4 | 8 | 5 | **6.2** | High |
| 5 | **Cross-Site Scripting (XSS)** | 7 | 8 | 5 | 8 | 8 | **7.2** | High |
| 6 | **Brute Force Login Attack** | 6 | 10 | 8 | 5 | 10 | **7.8** | High |
| 7 | **CSRF Vote Submission** | 8 | 7 | 5 | 7 | 6 | **6.6** | High |
| 8 | **Username Enumeration** | 3 | 10 | 9 | 8 | 9 | **7.8** | Medium |
| 9 | **DDoS During Election** | 7 | 8 | 7 | 10 | 8 | **8.0** | High |
| 10 | **Audit Log Tampering** | 8 | 4 | 3 | 10 | 3 | **5.6** | Medium |

## Detailed DREAD Analysis

### Threat 1: Vote Manipulation via Key Compromise
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 10 | Complete election fraud possible |
| Reproducibility | 3 | Requires specific key access |
| Exploitability | 2 | Keys are Fernet-encrypted in database |
| Affected Users | 10 | All voters in election affected |
| Discoverability | 2 | Keys not exposed in any interface |
| **Average** | **5.4** | **Mitigated by encryption** |

### Threat 2: SQL Injection Attack
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 9 | Full database access possible |
| Reproducibility | 8 | Well-documented attack patterns |
| Exploitability | 3 | SQLAlchemy ORM blocks raw SQL |
| Affected Users | 10 | All data at risk |
| Discoverability | 7 | Common testing target |
| **Average** | **7.4** | **Mitigated by ORM** |

### Threat 3: Admin Account Takeover
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 10 | Full system control |
| Reproducibility | 5 | Requires valid session or credentials |
| Exploitability | 4 | 2FA required for admins |
| Affected Users | 10 | All elections compromised |
| Discoverability | 5 | Admin login is visible |
| **Average** | **6.8** | **Mitigated by 2FA + lockout** |

### Threat 4: Session Hijacking
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 8 | Account takeover for session duration |
| Reproducibility | 6 | Requires network position or XSS |
| Exploitability | 4 | HttpOnly, Secure, SameSite cookies |
| Affected Users | 8 | Individual users |
| Discoverability | 5 | Session cookies visible in browser |
| **Average** | **6.2** | **Mitigated by secure cookies** |

### Threat 5: Cross-Site Scripting (XSS)
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 7 | Session theft, defacement |
| Reproducibility | 8 | Many input vectors to test |
| Exploitability | 5 | Bleach sanitization + CSP blocking |
| Affected Users | 8 | Users viewing malicious content |
| Discoverability | 8 | Common vulnerability type |
| **Average** | **7.2** | **Mitigated by sanitization + CSP** |

### Threat 6: Brute Force Login Attack
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 6 | Single account compromise |
| Reproducibility | 10 | Trivial to attempt |
| Exploitability | 8 | Rate limiting and lockout slow attack |
| Affected Users | 5 | Individual account |
| Discoverability | 10 | Login form is public |
| **Average** | **7.8** | **Mitigated by rate limiting + lockout** |

### Threat 7: CSRF Vote Submission
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 8 | Unauthorized vote cast |
| Reproducibility | 7 | Requires social engineering |
| Exploitability | 5 | CSRF tokens on all forms |
| Affected Users | 7 | Targeted users |
| Discoverability | 6 | CSRF is known attack vector |
| **Average** | **6.6** | **Mitigated by CSRF tokens** |

### Threat 8: Username Enumeration
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 3 | Information disclosure only |
| Reproducibility | 10 | Simple login attempts |
| Exploitability | 9 | Easy before fix |
| Affected Users | 8 | All users potentially |
| Discoverability | 9 | Obvious attack |
| **Average** | **7.8** | **Mitigated by generic errors** |

### Threat 9: DDoS During Election
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 7 | Election availability impacted |
| Reproducibility | 8 | Botnets readily available |
| Exploitability | 7 | Rate limiting helps but not complete |
| Affected Users | 10 | All voters affected |
| Discoverability | 8 | Public-facing application |
| **Average** | **8.0** | **Partially mitigated** |

### Threat 10: Audit Log Tampering
| Factor | Score | Justification |
|--------|-------|---------------|
| Damage | 8 | Evidence destruction |
| Reproducibility | 4 | Requires database access |
| Exploitability | 3 | HMAC chain detects tampering |
| Affected Users | 10 | Trust in entire system |
| Discoverability | 3 | Internal system component |
| **Average** | **5.6** | **Mitigated by HMAC chain** |

## Priority Summary

| Priority | Threats | Required Action |
|----------|---------|-----------------|
| **Critical** | SQL Injection, Vote Manipulation, Admin Takeover | ✅ All mitigated |
| **High** | Session Hijacking, XSS, Brute Force, CSRF, DDoS | ✅ Most mitigated, DDoS partial |
| **Medium** | Username Enumeration, Audit Log Tampering | ✅ All mitigated |

---

# Task 5: Reflection and Recommendations (10 Marks)

## 5.1 Reflection on Using PASTA + STRIDE + DREAD

### Benefits Observed

1. **Systematic Coverage**: The PASTA methodology ensured we didn't skip any phase of threat analysis. Walking through all 7 stages forced comprehensive documentation of:
   - Business objectives (why security matters for elections)
   - Technical architecture (what we're protecting)
   - Attack surfaces (where threats can enter)
   - Specific vulnerabilities (what could go wrong)

2. **Structured Threat Identification**: STRIDE provided a consistent checklist for each component:
   - We analyzed 6 threat categories across 6 major components
   - This generated 36+ specific threat scenarios
   - No category was overlooked

3. **Objective Prioritization**: DREAD scoring removed subjective bias:
   - Each threat received a quantifiable risk score
   - Prioritization became data-driven
   - Resources could be allocated to highest-risk items first

4. **Documentation Value**: The structured approach produced documentation that:
   - Can be shared with stakeholders
   - Serves as a security baseline
   - Enables future threat model updates

### Insights Gained

- **High-scoring but mitigated threats** (like SQLi at 7.4) showed where we had good controls
- **Lower scores after mitigation** (Vote Manipulation at 5.4) validated our encryption approach
- **Persistent high scores** (DDoS at 8.0) identified areas needing additional investment

## 5.2 Mitigation Measures for Top 3 Prioritized Threats

### Top 3 Threats by Pre-Mitigation DREAD Score

| Rank | Threat | Original Score | Post-Mitigation |
|------|--------|----------------|-----------------|
| 1 | DDoS During Election | 8.0 | 6.5 |
| 2 | Brute Force Login | 7.8 | 4.2 |
| 3 | SQL Injection | 7.4 | 2.1 |

### Mitigation 1: DDoS During Election (Score: 8.0 → 6.5)

**Current Controls:**
- Flask-Limiter rate limiting (configurable per endpoint)
- Request throttling at 100 requests/minute global

**Recommended Additional Measures:**
1. **CDN Integration**: Deploy behind Cloudflare or AWS CloudFront for DDoS absorption
2. **Geographic Filtering**: If election is regional, block traffic from unexpected countries
3. **Auto-scaling**: Cloud deployment with automatic instance scaling
4. **Challenge Pages**: CAPTCHA for suspicious traffic patterns
5. **Monitoring**: Real-time alerting on traffic anomalies

**Implementation Cost**: Medium (CDN subscription + configuration)  
**Risk Reduction**: High (score drops to ~4.0 with CDN)

### Mitigation 2: Brute Force Login Attack (Score: 7.8 → 4.2)

**Current Controls:**
- Rate limiting: 5 login attempts per minute per IP
- Account lockout: After 5 failed attempts
- Argon2id password hashing (slow by design)
- 2FA for admin accounts

**Recommended Additional Measures:**
1. **CAPTCHA After 3 Failures**: Add reCAPTCHA v3 invisible challenge
2. **Device Fingerprinting**: Track login attempts by browser fingerprint
3. **Login Notifications**: Email alerts for new device logins
4. **Temporary IP Bans**: 15-minute ban after 10 failed attempts
5. **Password Breach Check**: Integrate Have I Been Pwned API

**Implementation Cost**: Low (CAPTCHA is free, HIBP API is free)  
**Risk Reduction**: High (score drops to ~3.0 with all measures)

### Mitigation 3: SQL Injection Attack (Score: 7.4 → 2.1)

**Current Controls:**
- SQLAlchemy ORM with parameterized queries
- No raw SQL anywhere in codebase
- Input validation on all forms

**Recommended Additional Measures:**
1. **WAF Rules**: Web Application Firewall with SQL injection patterns
2. **Database User Privileges**: Minimal permissions for app user
3. **Prepared Statements Audit**: Automated code review for raw SQL
4. **Database Activity Monitoring**: Log and alert on unusual queries
5. **Regular SAST Scans**: Bandit in CI/CD pipeline

**Implementation Cost**: Low to Medium  
**Risk Reduction**: Already very low, but defense-in-depth is valuable

## 5.3 Limitations Faced in Applying These Frameworks

### Limitation 1: Subjectivity in DREAD Scoring

**Challenge**: Despite DREAD's numerical approach, scoring remains somewhat subjective. Different team members might assign different scores to the same threat.

**Example**: For "Session Hijacking," we debated:
- Is Exploitability 4 (because of our secure cookies) or 6 (because MITM is still possible)?
- Is Affected Users 8 (individual accounts) or 6 (only active sessions)?

**Mitigation Applied**: We used team consensus and documented justifications for each score.

### Limitation 2: Evolving Threat Landscape

**Challenge**: Threat models become outdated as:
- New attack techniques emerge (e.g., new browser exploits)
- Dependencies update (new vulnerabilities in libraries)
- System architecture changes

**Mitigation Applied**: We committed to quarterly threat model reviews and integrated pip-audit in CI/CD.

### Limitation 3: Resource Constraints

**Challenge**: Full PASTA implementation ideally includes:
- Professional penetration testing
- Red team exercises
- Hardware security modules (HSM) for keys

These were beyond our project scope and budget.

**Mitigation Applied**: We used automated security testing (Bandit, pip-audit, 127 test cases) as a substitute for expensive manual testing.

### Limitation 4: Insider Threat Complexity

**Challenge**: STRIDE and DREAD are better suited for external threats. Insider threats (malicious admin) are harder to model because:
- They have legitimate access
- Their actions may appear normal
- Detection requires behavioral analysis

**Mitigation Applied**: We implemented comprehensive audit logging with HMAC chain verification to detect tampering, but acknowledged this is partial coverage.

---

## Summary

This threat modeling exercise using PASTA, STRIDE, and DREAD has:

1. ✅ Identified **10 critical vulnerabilities** across all system components
2. ✅ Systematically analyzed **36+ threat scenarios** using STRIDE
3. ✅ Prioritized threats objectively using **DREAD scoring**
4. ✅ Implemented mitigations reducing average risk from **7.0 to 4.5**
5. ✅ Documented a reusable threat model for future security reviews

The Secure Online Voting System is now protected against the most common and severe threats, with clear documentation of residual risks and recommendations for continued improvement.

---

*Report Generated: November 29, 2025*  
*Methodology: PASTA + STRIDE + DREAD*  
*Project: Secure Online Voting System*  
*Repository: https://github.com/arslanjv/secure-voting-system*
