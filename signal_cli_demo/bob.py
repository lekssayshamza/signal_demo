#!/usr/bin/env python3
"""
Bob's cryptographic state for the Signal Protocol educational demo.

Bob represents the receiver in our demonstration. He has:
- Identity keypair (long-term)
- Signed pre-keypair (medium-term, signed by identity key)
- One-time pre-keypair (single use)
"""

from crypto.x3dh import generate_keypair
from cryptography.hazmat.primitives.asymmetric import x25519


class Bob:
    """
    Bob's cryptographic identity and pre-keys.
    """

    def __init__(self):
        """
        Initialize Bob with his cryptographic keys.
        """
        # Generate Bob's identity keypair (long-term)
        self.identity_private, self.identity_public = generate_keypair()

        # Generate Bob's signed pre-keypair (medium-term)
        # In real Signal, this would be signed by the identity key
        self.signed_prekey_private, self.signed_prekey_public = generate_keypair()

        # Generate Bob's one-time pre-keypair (single use)
        self.onetime_prekey_private, self.onetime_prekey_public = generate_keypair()

    def get_identity_public_key(self) -> x25519.X25519PublicKey:
        """
        Get Bob's identity public key.

        Returns:
            Bob's identity public key
        """
        return self.identity_public

    def get_signed_prekey_public_key(self) -> x25519.X25519PublicKey:
        """
        Get Bob's signed pre-key public key.

        Returns:
            Bob's signed pre-key public key
        """
        return self.signed_prekey_public

    def get_onetime_prekey_public_key(self) -> x25519.X25519PublicKey:
        """
        Get Bob's one-time pre-key public key.

        Returns:
            Bob's one-time pre-key public key
        """
        return self.onetime_prekey_public

    def get_identity_private_key(self) -> x25519.X25519PrivateKey:
        """
        Get Bob's identity private key.

        Returns:
            Bob's identity private key
        """
        return self.identity_private

    def get_signed_prekey_private_key(self) -> x25519.X25519PrivateKey:
        """
        Get Bob's signed pre-key private key.

        Returns:
            Bob's signed pre-key private key
        """
        return self.signed_prekey_private

    def get_onetime_prekey_private_key(self) -> x25519.X25519PrivateKey:
        """
        Get Bob's one-time pre-key private key.

        Returns:
            Bob's one-time pre-key private key
        """
        return self.onetime_prekey_private
