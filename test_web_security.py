#!/usr/bin/env python3
"""
Web Security Test Script
Tests security headers and endpoint responses
"""
import os
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_URL = "http://127.0.0.1:5000"


def test_security_headers():
    """Test that security headers are properly set"""
    print("=" * 60)
    print("Testing Security Headers (VULN-005, VULN-006, VULN-008)")
    print("=" * 60)
    
    response = requests.get(BASE_URL + "/")
    headers = response.headers
    
    print("\nResponse Headers:")
    print("-" * 40)
    
    # Check Content-Security-Policy
    csp = headers.get('Content-Security-Policy')
    if csp:
        print(f"✓ Content-Security-Policy: {csp[:80]}...")
        if 'nonce-' in csp or "'strict-dynamic'" in csp:
            print("  ✓ CSP uses nonces for script protection")
        if "default-src 'self'" in csp:
            print("  ✓ CSP has restrictive default-src")
    else:
        print("✗ Content-Security-Policy: MISSING!")
    
    # Check X-Content-Type-Options
    x_content_type = headers.get('X-Content-Type-Options')
    if x_content_type == 'nosniff':
        print(f"✓ X-Content-Type-Options: {x_content_type}")
    else:
        print(f"✗ X-Content-Type-Options: {x_content_type or 'MISSING!'}")
    
    # Check X-Frame-Options
    x_frame = headers.get('X-Frame-Options')
    if x_frame in ['DENY', 'SAMEORIGIN']:
        print(f"✓ X-Frame-Options: {x_frame}")
    else:
        print(f"✗ X-Frame-Options: {x_frame or 'MISSING!'}")
    
    # Check X-XSS-Protection
    xss = headers.get('X-XSS-Protection')
    if xss:
        print(f"✓ X-XSS-Protection: {xss}")
    else:
        print(f"✗ X-XSS-Protection: MISSING!")
    
    # Check Strict-Transport-Security (may not be present in dev mode)
    hsts = headers.get('Strict-Transport-Security')
    if hsts:
        print(f"✓ Strict-Transport-Security: {hsts}")
    else:
        print(f"⚠ Strict-Transport-Security: Not set (OK for HTTP dev mode)")
    
    # Check Referrer-Policy
    referrer = headers.get('Referrer-Policy')
    if referrer:
        print(f"✓ Referrer-Policy: {referrer}")
    else:
        print(f"⚠ Referrer-Policy: Not explicitly set")
    
    print()


def test_routes():
    """Test that all main routes return correct status codes"""
    print("=" * 60)
    print("Testing Route Responses")
    print("=" * 60)
    
    routes = [
        ('/', 'Home Page', 200),
        ('/auth/login', 'Login Page', 200),
        ('/auth/register', 'Register Page', 200),
    ]
    
    all_passed = True
    for route, name, expected_code in routes:
        try:
            response = requests.get(BASE_URL + route, timeout=5)
            status = "✓" if response.status_code == expected_code else "✗"
            print(f"{status} {name} ({route}): {response.status_code}")
            if response.status_code != expected_code:
                all_passed = False
        except Exception as e:
            print(f"✗ {name} ({route}): ERROR - {e}")
            all_passed = False
    
    print()
    return all_passed


def test_protected_routes():
    """Test that protected routes require authentication"""
    print("=" * 60)
    print("Testing Protected Routes (should redirect to login)")
    print("=" * 60)
    
    protected_routes = [
        '/admin/',
        '/voting/elections',
        '/voting/results',
    ]
    
    for route in protected_routes:
        try:
            response = requests.get(BASE_URL + route, timeout=5, allow_redirects=False)
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', 'unknown')
                print(f"✓ {route}: Redirects ({response.status_code}) -> {location}")
            elif response.status_code == 401:
                print(f"✓ {route}: Returns 401 Unauthorized")
            elif response.status_code == 403:
                print(f"✓ {route}: Returns 403 Forbidden")
            else:
                print(f"⚠ {route}: Returns {response.status_code}")
        except Exception as e:
            print(f"✗ {route}: ERROR - {e}")
    
    print()


def test_login_csrf():
    """Test that login form includes CSRF protection"""
    print("=" * 60)
    print("Testing CSRF Protection")
    print("=" * 60)
    
    response = requests.get(BASE_URL + "/auth/login")
    
    if 'csrf' in response.text.lower() or 'csrf_token' in response.text.lower():
        print("✓ Login form includes CSRF token")
    else:
        print("⚠ CSRF token not found in login form (may use different implementation)")
    
    # Check for session cookie security
    cookies = response.cookies
    for cookie in cookies:
        print(f"Cookie '{cookie.name}':")
        if hasattr(cookie, 'secure'):
            print(f"  Secure: {cookie.secure}")
        if hasattr(cookie, 'has_nonstandard_attr'):
            if cookie.has_nonstandard_attr('HttpOnly'):
                print(f"  HttpOnly: True")
            if cookie.has_nonstandard_attr('SameSite'):
                print(f"  SameSite: {cookie.get_nonstandard_attr('SameSite')}")
    
    print()


def test_error_pages():
    """Test that error pages don't leak information"""
    print("=" * 60)
    print("Testing Error Pages (VULN-004: No information leakage)")
    print("=" * 60)
    
    # Test 404
    response = requests.get(BASE_URL + "/nonexistent-page-12345")
    if response.status_code == 404:
        print(f"✓ 404 Page: Returns proper 404")
        if 'traceback' not in response.text.lower() and 'exception' not in response.text.lower():
            print(f"  ✓ No stack trace in 404 page")
        else:
            print(f"  ✗ Stack trace found in 404 page!")
    else:
        print(f"⚠ Non-existent page returns {response.status_code}")
    
    print()


def main():
    print("\n" + "=" * 60)
    print("WEB SECURITY TEST SUITE")
    print("=" * 60 + "\n")
    
    try:
        # Quick connectivity check
        requests.get(BASE_URL, timeout=2)
    except Exception as e:
        print(f"ERROR: Cannot connect to {BASE_URL}")
        print(f"Make sure the Flask server is running!")
        print(f"Error: {e}")
        sys.exit(1)
    
    test_security_headers()
    test_routes()
    test_protected_routes()
    test_login_csrf()
    test_error_pages()
    
    print("=" * 60)
    print("WEB SECURITY TESTS COMPLETED!")
    print("=" * 60)


if __name__ == "__main__":
    main()
