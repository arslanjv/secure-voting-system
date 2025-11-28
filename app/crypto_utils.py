"""
Centralized Encryption Utilities Module
Implements secure cryptographic operations for the voting system

Security Features:
- RSA-4096 key pair generation for election vote encryption
- Fernet symmetric encryption for TOTP secrets and private keys
- AES-GCM decryption for encrypted votes
- Secure random generation for salts and nonces

Following OWASP, NIST 800-57, and cryptographic best practices.
"""
import os
import base64
import json
import secrets
from datetime import datetime
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class CryptoUtils:
    """
    Centralized cryptographic utilities for the voting system.
    
    Provides:
    - RSA-4096 key pair generation for vote encryption
    - Fernet encryption for secrets at rest
    - AES-GCM decryption for encrypted votes
    - Secure random generation
    """
    
    # Key size constants
    RSA_KEY_SIZE = 4096
    AES_KEY_SIZE = 32  # 256 bits
    SALT_SIZE = 16  # 128 bits
    NONCE_SIZE = 12  # 96 bits for AES-GCM
    
    # ========================
    # RSA Key Pair Operations
    # ========================
    
    @staticmethod
    def generate_rsa_keypair() -> Tuple[str, str]:
        """
        Generate RSA-4096 key pair for election vote encryption.
        
        Returns:
            Tuple[str, str]: (private_key_pem, public_key_pem) as PEM-encoded strings
            
        Security Notes:
        - Uses 4096-bit key size for long-term security
        - Uses standard public exponent 65537
        - Private key returned unencrypted - caller must encrypt before storage
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CryptoUtils.RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize private key (unencrypted - will be encrypted before storage)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    
    @staticmethod
    def decrypt_with_rsa(encrypted_data: bytes, private_key_pem: str) -> bytes:
        """
        Decrypt data using RSA-OAEP with SHA-256.
        
        Args:
            encrypted_data: Encrypted bytes to decrypt
            private_key_pem: PEM-encoded private key string
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            ValueError: If decryption fails
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            plaintext = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext
        except Exception as e:
            raise ValueError(f"RSA decryption failed: {str(e)}")
    
    # ========================
    # Fernet Encryption (for secrets at rest)
    # ========================
    
    @staticmethod
    def generate_fernet_key() -> str:
        """
        Generate a new Fernet key for symmetric encryption.
        
        Returns:
            str: Base64-encoded 32-byte Fernet key
            
        Use for:
        - TOTP secret encryption
        - Private key encryption at rest
        """
        return Fernet.generate_key().decode('utf-8')
    
    @staticmethod
    def encrypt_with_fernet(plaintext: str, key: str) -> str:
        """
        Encrypt plaintext using Fernet symmetric encryption.
        
        Args:
            plaintext: String to encrypt
            key: Fernet key (base64-encoded)
            
        Returns:
            str: Encrypted data as base64 string
        """
        if not plaintext:
            return None
        
        f = Fernet(key.encode('utf-8') if isinstance(key, str) else key)
        encrypted = f.encrypt(plaintext.encode('utf-8'))
        return encrypted.decode('utf-8')
    
    @staticmethod
    def decrypt_with_fernet(encrypted_data: str, key: str) -> str:
        """
        Decrypt Fernet-encrypted data.
        
        Args:
            encrypted_data: Encrypted string (base64)
            key: Fernet key (base64-encoded)
            
        Returns:
            str: Decrypted plaintext
            
        Raises:
            InvalidToken: If decryption fails (wrong key or tampered data)
        """
        if not encrypted_data:
            return None
        
        try:
            f = Fernet(key.encode('utf-8') if isinstance(key, str) else key)
            decrypted = f.decrypt(encrypted_data.encode('utf-8'))
            return decrypted.decode('utf-8')
        except InvalidToken:
            raise ValueError("Decryption failed - invalid key or tampered data")
    
    # ========================
    # TOTP Secret Encryption
    # ========================
    
    @staticmethod
    def encrypt_totp_secret(secret: str, encryption_key: str) -> str:
        """
        Encrypt TOTP secret for secure storage.
        
        Args:
            secret: TOTP secret to encrypt
            encryption_key: Fernet key from environment
            
        Returns:
            str: Encrypted secret (base64)
        """
        return CryptoUtils.encrypt_with_fernet(secret, encryption_key)
    
    @staticmethod
    def decrypt_totp_secret(encrypted_secret: str, encryption_key: str) -> Optional[str]:
        """
        Decrypt TOTP secret from storage.
        
        Args:
            encrypted_secret: Encrypted secret (base64)
            encryption_key: Fernet key from environment
            
        Returns:
            str: Decrypted TOTP secret, or None if empty
        """
        if not encrypted_secret:
            return None
        return CryptoUtils.decrypt_with_fernet(encrypted_secret, encryption_key)
    
    # ========================
    # Private Key Encryption (for database storage)
    # ========================
    
    @staticmethod
    def encrypt_private_key(private_key_pem: str, master_key: str) -> str:
        """
        Encrypt RSA private key for secure database storage.
        
        Args:
            private_key_pem: PEM-encoded private key
            master_key: Master encryption key (Fernet format)
            
        Returns:
            str: Encrypted private key (base64)
        """
        return CryptoUtils.encrypt_with_fernet(private_key_pem, master_key)
    
    @staticmethod
    def decrypt_private_key(encrypted_key: str, master_key: str) -> str:
        """
        Decrypt RSA private key from database.
        
        Args:
            encrypted_key: Encrypted private key (base64)
            master_key: Master encryption key (Fernet format)
            
        Returns:
            str: PEM-encoded private key
        """
        return CryptoUtils.decrypt_with_fernet(encrypted_key, master_key)
    
    # ========================
    # AES-GCM Decryption (for votes)
    # ========================
    
    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte AES key
            nonce: 12-byte nonce/IV
            tag: 16-byte authentication tag
            
        Returns:
            bytes: Decrypted plaintext
            
        Raises:
            ValueError: If decryption or authentication fails
        """
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except Exception as e:
            raise ValueError(f"AES-GCM decryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_hybrid_vote(encrypted_vote_b64: str, encrypted_key_b64: str, 
                            iv_b64: str, private_key_pem: str) -> str:
        """
        Decrypt a vote encrypted with hybrid RSA+AES encryption.
        
        The client encrypts the vote with a random AES key, then encrypts
        the AES key with the election's RSA public key.
        
        Args:
            encrypted_vote_b64: Base64-encoded AES-encrypted vote data
            encrypted_key_b64: Base64-encoded RSA-encrypted AES key
            iv_b64: Base64-encoded AES-GCM IV/nonce
            private_key_pem: PEM-encoded RSA private key
            
        Returns:
            str: Decrypted vote data as JSON string
        """
        # Decode base64 inputs
        encrypted_vote = base64.b64decode(encrypted_vote_b64)
        encrypted_aes_key = base64.b64decode(encrypted_key_b64)
        iv = base64.b64decode(iv_b64)
        
        # Step 1: Decrypt the AES key using RSA
        aes_key = CryptoUtils.decrypt_with_rsa(encrypted_aes_key, private_key_pem)
        
        # Step 2: Decrypt the vote using AES-GCM
        # Note: Web Crypto API concatenates ciphertext and tag
        # Tag is last 16 bytes
        tag = encrypted_vote[-16:]
        ciphertext = encrypted_vote[:-16]
        
        plaintext = CryptoUtils.decrypt_aes_gcm(ciphertext, aes_key, iv, tag)
        
        return plaintext.decode('utf-8')
    
    # ========================
    # Random Generation
    # ========================
    
    @staticmethod
    def generate_random_salt() -> str:
        """
        Generate cryptographically secure random salt.
        
        Returns:
            str: Base64-encoded 16-byte salt
        """
        salt = get_random_bytes(CryptoUtils.SALT_SIZE)
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def generate_random_nonce() -> str:
        """
        Generate cryptographically secure random nonce.
        
        Returns:
            str: Hex-encoded 32-byte nonce
        """
        return secrets.token_hex(32)
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> list:
        """
        Generate secure backup codes for 2FA recovery.
        
        Args:
            count: Number of codes to generate (default 10)
            
        Returns:
            list: List of 8-character alphanumeric codes
        """
        codes = []
        for _ in range(count):
            # Generate 8-character codes (uppercase alphanumeric)
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
            codes.append(code)
        return codes
    
    @staticmethod
    def hash_backup_code(code: str) -> str:
        """
        Hash a backup code for secure storage.
        
        Args:
            code: Backup code to hash
            
        Returns:
            str: Hex-encoded SHA-256 hash
        """
        import hashlib
        return hashlib.sha256(code.upper().encode('utf-8')).hexdigest()


class SigningKeyManager:
    """
    Manages signing keys for tally signatures.
    Handles migration from file-based to database storage.
    """
    
    @staticmethod
    def load_from_file(private_key_path: str) -> Optional[str]:
        """
        Load signing private key from file (for migration).
        
        Args:
            private_key_path: Path to PEM file
            
        Returns:
            str: PEM-encoded private key, or None if not found
        """
        try:
            if os.path.exists(private_key_path):
                with open(private_key_path, 'rb') as f:
                    return f.read().decode('utf-8')
        except Exception:
            pass
        return None
    
    @staticmethod
    def store_encrypted(private_key_pem: str, master_key: str) -> str:
        """
        Encrypt signing key for database storage.
        
        Args:
            private_key_pem: PEM-encoded private key
            master_key: Master encryption key
            
        Returns:
            str: Encrypted private key
        """
        return CryptoUtils.encrypt_private_key(private_key_pem, master_key)
    
    @staticmethod
    def retrieve_decrypted(encrypted_key: str, master_key: str) -> str:
        """
        Decrypt signing key from database.
        
        Args:
            encrypted_key: Encrypted private key
            master_key: Master encryption key
            
        Returns:
            str: PEM-encoded private key
        """
        return CryptoUtils.decrypt_private_key(encrypted_key, master_key)
