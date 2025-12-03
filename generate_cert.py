"""
Generate self-signed SSL certificate for HTTPS
Run this once to create cert.pem and key.pem
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import ipaddress
import socket

def get_local_ip():
    """Get the local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def generate_self_signed_cert():
    """Generate a self-signed certificate valid for localhost and LAN IPs"""
    
    # Generate private key
    print("Generating RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Get local IP for SAN
    local_ip = get_local_ip()
    print(f"Local IP detected: {local_ip}")
    
    # Certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Development"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Voting System"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    # Subject Alternative Names (SAN) - important for browser trust
    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    
    # Add local network IP
    if local_ip != "127.0.0.1":
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
        print(f"Added {local_ip} to certificate SANs")
    
    # Add common private network ranges (so cert works if IP changes)
    # This covers most LAN scenarios
    
    # Build certificate
    print("Building certificate...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Write private key
    print("Writing key.pem...")
    with open("key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate
    print("Writing cert.pem...")
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n" + "="*60)
    print("SUCCESS! SSL certificate generated.")
    print("="*60)
    print(f"\nFiles created:")
    print(f"  - cert.pem (certificate)")
    print(f"  - key.pem (private key)")
    print(f"\nCertificate valid for:")
    print(f"  - localhost")
    print(f"  - 127.0.0.1")
    print(f"  - {local_ip}")
    print(f"\nValid until: {datetime.utcnow() + timedelta(days=365)}")
    print(f"\n" + "="*60)
    print("IMPORTANT: Users must accept the browser security warning")
    print("when first accessing the site (self-signed cert).")
    print("="*60)

if __name__ == "__main__":
    generate_self_signed_cert()
