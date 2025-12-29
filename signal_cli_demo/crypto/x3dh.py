#!/usr/bin/env python3
"""
X3DH (Extended Triple Diffie-Hellman) implementation for Signal Protocol demo.

X3DH allows two parties to establish a shared secret key over an insecure channel
using a combination of identity keys, pre-keys, and ephemeral keys.

This is a simplified educational version.
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from .kdf import hkdf_like


def generate_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generate a new X25519 keypair for Diffie-Hellman exchange.

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def compute_dh(private_key: x25519.X25519PrivateKey,
               public_key: x25519.X25519PublicKey) -> bytes:
    """
    Compute Diffie-Hellman shared secret between private and public keys.

    Args:
        private_key: Alice's private key
        public_key: Bob's public key

    Returns:
        32-byte shared secret
    """
    # X25519 produces a 32-byte shared secret
    shared_secret = private_key.exchange(public_key)
    return shared_secret


def x3dh_compute_master_secret(alice_identity_private: x25519.X25519PrivateKey,
                               alice_ephemeral_private: x25519.X25519PrivateKey,
                               bob_identity_public: x25519.X25519PublicKey,
                               bob_signed_prekey_public: x25519.X25519PublicKey,
                               bob_onetime_prekey_public: x25519.X25519PublicKey) -> bytes:
    """
    Perform X3DH key agreement to compute the master secret.

    X3DH computes three Diffie-Hellman exchanges:
    DH1 = DH(IK_A_private, SPK_B_public)  # Alice's identity with Bob's signed prekey
    DH2 = DH(EK_A_private, IK_B_public)   # Alice's ephemeral with Bob's identity
    DH3 = DH(EK_A_private, OPK_B_public)  # Alice's ephemeral with Bob's one-time prekey

    The master secret is derived from the concatenation: KDF(DH1 || DH2 || DH3)

    Args:
        alice_identity_private: Alice's identity private key
        alice_ephemeral_private: Alice's ephemeral private key
        bob_identity_public: Bob's identity public key
        bob_signed_prekey_public: Bob's signed prekey public key
        bob_onetime_prekey_public: Bob's one-time prekey public key

    Returns:
        32-byte master secret
    """
    # DH1: Alice's identity key with Bob's signed prekey
    dh1 = compute_dh(alice_identity_private, bob_signed_prekey_public)

    # DH2: Alice's ephemeral key with Bob's identity key
    dh2 = compute_dh(alice_ephemeral_private, bob_identity_public)

    # DH3: Alice's ephemeral key with Bob's one-time prekey
    dh3 = compute_dh(alice_ephemeral_private, bob_onetime_prekey_public)

    # Concatenate all DH outputs
    dh_concat = dh1 + dh2 + dh3

    # Derive master secret
    master_secret = hkdf_like(dh_concat, b"x3dh_master", 32)

    return master_secret, dh1, dh2, dh3
