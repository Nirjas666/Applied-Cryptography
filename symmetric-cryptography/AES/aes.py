#!/usr/bin/env python3
"""
AES Encryption Implementation
Demonstrates AES-CBC and AES-GCM modes with security analysis.

This module provides:
- AES-CBC (Cipher Block Chaining) encryption/decryption
- AES-GCM (Galois/Counter Mode) encryption/decryption with authentication
- Mode comparison and analysis
- Key and IV/nonce generation

Usage:
    python3 aes/implementation.py --mode cbc --plaintext "Hello" --keysize 256
    python3 aes/implementation.py --mode gcm --plaintext "Hello" --keysize 256
"""

import os
import sys
import argparse
import base64
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class AESEncryption:
    """AES encryption/decryption with multiple modes."""
    
    def __init__(self, key_size=256):
        """
        Initialize AES cipher.
        
        Args:
            key_size: Key size in bits (128, 192, or 256)
        """
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")
        
        self.key_size = key_size
        self.key_bytes = key_size // 8
        self.backend = default_backend()
        
    def generate_key(self):
        """Generate cryptographically secure random key."""
        return os.urandom(self.key_bytes)
    
    @staticmethod
    def generate_iv():
        """Generate random 128-bit IV for CBC mode."""
        return os.urandom(16)
    
    @staticmethod
    def generate_nonce():
        """Generate random 96-bit nonce for GCM mode."""
        return os.urandom(12)
    
    def encrypt_cbc(self, plaintext, key, iv=None):
        """
        Encrypt plaintext using AES-CBC.
        
        Args:
            plaintext: Data to encrypt (bytes or string)
            key: Encryption key (bytes)
            iv: Initialization vector (bytes). If None, generates random.
        
        Returns:
            Tuple of (iv, ciphertext) both as bytes
            
        Important Notes:
            - A new random IV MUST be generated for each encryption
            - Reusing IV with same key compromises security
            - IV doesn't need to be secret, but must be random/unique
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        if iv is None:
            iv = self.generate_iv()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return iv, ciphertext
    
    def decrypt_cbc(self, ciphertext, key, iv):
        """
        Decrypt ciphertext using AES-CBC.
        
        Args:
            ciphertext: Data to decrypt (bytes)
            key: Decryption key (bytes)
            iv: Initialization vector (bytes)
        
        Returns:
            Plaintext (bytes)
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def encrypt_gcm(self, plaintext, key, nonce=None, aad=None):
        """
        Encrypt plaintext using AES-GCM (authenticated encryption).
        
        Args:
            plaintext: Data to encrypt (bytes or string)
            key: Encryption key (bytes)
            nonce: 96-bit nonce (bytes). If None, generates random.
            aad: Additional Authenticated Data (optional, bytes)
        
        Returns:
            Tuple of (nonce, ciphertext, tag) all as bytes
            
        Important Notes:
            - A new random nonce MUST be generated for each encryption
            - NEVER reuse nonce with same key (catastrophic failure)
            - GCM provides both confidentiality AND authentication
            - Tag is 16 bytes (128 bits)
            - AAD (if present) is authenticated but not encrypted
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        if nonce is None:
            nonce = self.generate_nonce()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        if aad:
            encryptor.authenticate_additional_data(aad)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        return nonce, ciphertext, tag
    
    def decrypt_gcm(self, ciphertext, key, nonce, tag, aad=None):
        """
        Decrypt ciphertext using AES-GCM.
        
        Args:
            ciphertext: Data to decrypt (bytes)
            key: Decryption key (bytes)
            nonce: 96-bit nonce (bytes)
            tag: Authentication tag (16 bytes)
            aad: Additional Authenticated Data (optional, bytes)
        
        Returns:
            Plaintext (bytes)
            
        Raises:
            cryptography.exceptions.InvalidTag if authentication fails
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        if aad:
            decryptor.authenticate_additional_data(aad)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext


def demo_cbc_mode():
    """Demonstrate AES-CBC encryption."""
    print("\n" + "="*60)
    print("AES-CBC Mode Demonstration")
    print("="*60)
    
    aes = AESEncryption(key_size=256)
    
    # Generate key
    key = aes.generate_key()
    print(f"\n[*] Generated 256-bit key: {base64.b64encode(key[:8])...}...")
    
    # Encrypt
    plaintext = "This is sensitive data that needs encryption."
    print(f"\n[*] Plaintext:  {plaintext}")
    
    iv, ciphertext = aes.encrypt_cbc(plaintext, key)
    print(f"[+] Ciphertext: {base64.b64encode(ciphertext).decode()}")
    print(f"[*] IV:         {base64.b64encode(iv).decode()}")
    
    # Decrypt
    decrypted = aes.decrypt_cbc(ciphertext, key, iv)
    print(f"\n[+] Decrypted:  {decrypted.decode('utf-8')}")
    
    # Verify
    if decrypted.decode('utf-8') == plaintext:
        print("[✓] Encryption/Decryption successful")
    else:
        print("[✗] Decryption failed")
    
    # Security Notes
    print("\n[!] Security Notes:")
    print("    - IV was randomly generated")
    print("    - Each encryption MUST use a new IV")
    print("    - IV can be transmitted with ciphertext (doesn't need to be secret)")
    print("    - No authentication tag (use GCM for integrity verification)")


def demo_gcm_mode():
    """Demonstrate AES-GCM encryption with authentication."""
    print("\n" + "="*60)
    print("AES-GCM Mode Demonstration (with Authentication)")
    print("="*60)
    
    aes = AESEncryption(key_size=256)
    
    # Generate key
    key = aes.generate_key()
    print(f"\n[*] Generated 256-bit key: {base64.b64encode(key[:8])...}...")
    
    # Encrypt
    plaintext = "This is sensitive data that needs encryption AND authentication."
    print(f"\n[*] Plaintext: {plaintext}")
    
    nonce, ciphertext, tag = aes.encrypt_gcm(plaintext, key)
    print(f"[+] Ciphertext: {base64.b64encode(ciphertext).decode()}")
    print(f"[*] Nonce:      {base64.b64encode(nonce).decode()}")
    print(f"[+] Auth Tag:   {base64.b64encode(tag).decode()}")
    
    # Decrypt
    try:
        decrypted = aes.decrypt_gcm(ciphertext, key, nonce, tag)
        print(f"\n[+] Decrypted: {decrypted.decode('utf-8')}")
        print("[✓] Authentication verification successful")
    except Exception as e:
        print(f"[✗] Authentication failed: {e}")
        return
    
    # Security Notes
    print("\n[!] Security Notes:")
    print("    - GCM provides BOTH confidentiality and authentication")
    print("    - Nonce is randomly generated (never reuse with same key!)")
    print("    - Authentication tag verifies ciphertext integrity")
    print("    - Tampering with ciphertext will be detected")
    
    # Demonstrate tampering detection
    print("\n[*] Testing tampering detection...")
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # Flip a bit
    
    try:
        aes.decrypt_gcm(bytes(tampered_ciphertext), key, nonce, tag)
        print("[✗] Tampered data was accepted (shouldn't happen!)")
    except Exception as e:
        print(f"[✓] Tampered data detected and rejected: {type(e).__name__}")


def demo_mode_comparison():
    """Compare AES-CBC and AES-GCM."""
    print("\n" + "="*60)
    print("AES-CBC vs AES-GCM Comparison")
    print("="*60)
    
    aes = AESEncryption(key_size=256)
    key = aes.generate_key()
    
    plaintext = "x" * 1000  # 1KB of data
    
    # CBC Encryption
    print("\n[*] CBC Mode:")
    start = time.time()
    iv, cbc_ciphertext = aes.encrypt_cbc(plaintext, key)
    cbc_time = time.time() - start
    print(f"    Ciphertext size: {len(cbc_ciphertext)} bytes")
    print(f"    Encryption time: {cbc_time*1000:.2f} ms")
    print(f"    Authentication: None (add HMAC separately)")
    
    # GCM Encryption
    print("\n[*] GCM Mode:")
    start = time.time()
    nonce, gcm_ciphertext, tag = aes.encrypt_gcm(plaintext, key)
    gcm_time = time.time() - start
    print(f"    Ciphertext size: {len(gcm_ciphertext)} bytes")
    print(f"    Auth tag size:   {len(tag)} bytes")
    print(f"    Encryption time: {gcm_time*1000:.2f} ms")
    print(f"    Authentication: Built-in (16-byte tag)")
    
    # Overhead
    print("\n[*] Overhead Comparison:")
    print(f"    CBC: IV ({len(iv)}) + Ciphertext ({len(cbc_ciphertext)}) = {len(iv) + len(cbc_ciphertext)} bytes")
    print(f"    GCM: Nonce ({len(nonce)}) + Ciphertext ({len(gcm_ciphertext)}) + Tag ({len(tag)}) = {len(nonce) + len(gcm_ciphertext) + len(tag)} bytes")
    
    print("\n[!] When to use each mode:")
    print("    CBC: Encryption of structured data at rest")
    print("    GCM: When authentication/integrity is needed")
    print("    GCM: Modern protocols (TLS 1.2+, modern APIs)")


def main():
    """Main function with CLI interface."""
    parser = argparse.ArgumentParser(
        description="AES Encryption Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aes/implementation.py --demo all
  python3 aes/implementation.py --mode cbc --plaintext "Hello" --keysize 256
  python3 aes/implementation.py --mode gcm --plaintext "Hello" --keysize 256
        """
    )
    
    parser.add_argument('--mode', choices=['cbc', 'gcm'],
                       help='Encryption mode')
    parser.add_argument('--plaintext', type=str,
                       help='Text to encrypt')
    parser.add_argument('--keysize', type=int, choices=[128, 192, 256],
                       default=256, help='Key size in bits (default: 256)')
    parser.add_argument('--demo', choices=['cbc', 'gcm', 'compare', 'all'],
                       help='Run demonstration')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Show header
    print("\n" + "="*60)
    print("AES Encryption Implementation")
    print("="*60)
    
    if args.demo:
        # Run demonstrations
        if args.demo in ['cbc', 'all']:
            demo_cbc_mode()
        if args.demo in ['gcm', 'all']:
            demo_gcm_mode()
        if args.demo in ['compare', 'all']:
            demo_mode_comparison()
    
    elif args.mode and args.plaintext:
        # Single encryption
        aes = AESEncryption(key_size=args.keysize)
        key = aes.generate_key()
        
        print(f"\n[*] Key size: {args.keysize} bits")
        print(f"[*] Plaintext: {args.plaintext}")
        
        if args.mode == 'cbc':
            iv, ciphertext = aes.encrypt_cbc(args.plaintext, key)
            print(f"[+] Ciphertext: {base64.b64encode(ciphertext).decode()}")
            print(f"[*] IV: {base64.b64encode(iv).decode()}")
            
            decrypted = aes.decrypt_cbc(ciphertext, key, iv)
            print(f"[✓] Decrypted: {decrypted.decode()}")
        
        elif args.mode == 'gcm':
            nonce, ciphertext, tag = aes.encrypt_gcm(args.plaintext, key)
            print(f"[+] Ciphertext: {base64.b64encode(ciphertext).decode()}")
            print(f"[*] Nonce: {base64.b64encode(nonce).decode()}")
            print(f"[+] Auth Tag: {base64.b64encode(tag).decode()}")
            
            try:
                decrypted = aes.decrypt_gcm(ciphertext, key, nonce, tag)
                print(f"[✓] Decrypted: {decrypted.decode()}")
            except Exception as e:
                print(f"[✗] Authentication failed: {e}")
    
    else:
        # Show help
        print("\nNo arguments provided. Use --demo or --mode + --plaintext")
        print("\nQuick demo:")
        demo_cbc_mode()
        demo_gcm_mode()
        demo_mode_comparison()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        sys.exit(1)