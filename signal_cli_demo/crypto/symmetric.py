#!/usr/bin/env python3
"""
Symmetric encryption functions for the Signal Protocol educational demo.

This module provides authenticated symmetric encryption using Fernet,
which is based on AES-128 in CBC mode with HMAC-SHA256 for authentication.
"""

from cryptography.fernet import Fernet
import base64


def create_cipher(key: bytes) -> Fernet:
    """
    Create a Fernet cipher object from a key.

    Fernet requires a 32-byte key (256 bits). If our key is longer,
    we truncate it. If shorter, this would fail, but our KDF produces 32 bytes.

    Args:
        key: 32-byte encryption key

    Returns:
        Fernet cipher object
    """
    # Fernet expects the key to be base64-encoded
    # Convert our raw bytes to base64
    key_b64 = base64.urlsafe_b64encode(key)
    return Fernet(key_b64)


def encrypt_message(message_key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a plaintext message using the given message key.

    Args:
        message_key: 32-byte key for encryption
        plaintext: The message to encrypt

    Returns:
        Encrypted ciphertext (includes authentication tag)
    """
    cipher = create_cipher(message_key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = cipher.encrypt(plaintext_bytes)
    return ciphertext


def decrypt_message(message_key: bytes, ciphertext: bytes) -> str:
    """
    Decrypt a ciphertext message using the given message key.

    Args:
        message_key: 32-byte key for decryption
        ciphertext: The encrypted message

    Returns:
        Decrypted plaintext string

    Raises:
        Exception: If decryption fails (wrong key or tampered message)
    """
    try:
        cipher = create_cipher(message_key)
        plaintext_bytes = cipher.decrypt(ciphertext)
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        # In a real implementation, we'd handle this more gracefully
        raise ValueError("Decryption failed - invalid key or corrupted message") from e
