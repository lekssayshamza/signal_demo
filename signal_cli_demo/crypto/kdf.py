#!/usr/bin/env python3
"""
Key Derivation Functions for the Signal Protocol educational demo.

This module implements simplified key derivation functions similar to HKDF
used in the Signal protocol. We use SHA-256 for simplicity and educational purposes.
"""

import hashlib
import hmac


def hkdf_like(input_key_material: bytes, info: bytes = b"", length: int = 32) -> bytes:
    """
    Simplified HKDF-like key derivation function.

    In the real Signal protocol, HKDF is used with specific parameters.
    Here we use a simplified version for educational purposes.

    Args:
        input_key_material: The input key material (e.g., shared secrets)
        info: Context-specific information (like "root" or "chain")
        length: Desired output length in bytes

    Returns:
        Derived key of specified length
    """
    # In real HKDF, we use HMAC with a salt. Here we simplify for education
    # Step 1: Extract (simplified - no salt)
    prk = hmac.new(b"", input_key_material, hashlib.sha256).digest()

    # Step 2: Expand
    # In real HKDF, we do multiple rounds. Here we do one round for simplicity
    expanded = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    # Return the requested length
    return expanded[:length]


def derive_root_key(master_secret: bytes) -> bytes:
    """
    Derive the root key from the master secret.

    The root key is the foundation of the double ratchet algorithm.
    It is never used directly for encryption - only for deriving chain keys.

    Args:
        master_secret: The shared secret from X3DH

    Returns:
        32-byte root key
    """
    return hkdf_like(master_secret, b"root", 32)


def derive_chain_keys(root_key: bytes) -> tuple[bytes, bytes]:
    """
    Derive sending and receiving chain keys from the root key.

    Args:
        root_key: The root key from X3DH

    Returns:
        Tuple of (sending_chain_key, receiving_chain_key)
    """
    sending_ck = hkdf_like(root_key, b"sending_chain", 32)
    receiving_ck = hkdf_like(root_key, b"receiving_chain", 32)
    return sending_ck, receiving_ck


def derive_message_key(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    Derive a message key from the current chain key and advance the chain.

    This implements the "ratcheting" behavior where each message key
    is derived from the current chain key, and the chain key is advanced.

    Args:
        chain_key: Current chain key

    Returns:
        Tuple of (message_key, new_chain_key)
    """
    # Derive message key from current chain key
    message_key = hkdf_like(chain_key, b"message", 32)

    # Advance the chain key (ratchet forward)
    new_chain_key = hkdf_like(chain_key, b"next_chain", 32)

    return message_key, new_chain_key
