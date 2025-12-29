#!/usr/bin/env python3
"""
Alice's cryptographic state for the Signal Protocol educational demo.

Alice represents the sender in our demonstration. She has:
- Identity keypair (long-term)
- Ephemeral keypair (one-time use for X3DH)
"""

from crypto.x3dh import generate_keypair
from cryptography.hazmat.primitives.asymmetric import x25519


class Alice:
    """
    Alice's cryptographic identity and state.
    """

    def __init__(self):
        """
        Initialize Alice with her cryptographic keys.
        """
        # Generate Alice's identity keypair (long-term)
        self.identity_private, self.identity_public = generate_keypair()

        # Generate Alice's ephemeral keypair (one-time use for this conversation)
        self.ephemeral_private, self.ephemeral_public = generate_keypair()

    def get_identity_public_key(self) -> x25519.X25519PublicKey:
        """
        Get Alice's identity public key.

        Returns:
            Alice's identity public key
        """
        return self.identity_public

    def get_ephemeral_public_key(self) -> x25519.X25519PublicKey:
        """
        Get Alice's ephemeral public key.

        Returns:
            Alice's ephemeral public key
        """
        return self.ephemeral_public

    def get_identity_private_key(self) -> x25519.X25519PrivateKey:
        """
        Get Alice's identity private key.

        Returns:
            Alice's identity private key
        """
        return self.identity_private

    def get_ephemeral_private_key(self) -> x25519.X25519PrivateKey:
        """
        Get Alice's ephemeral private key.

        Returns:
            Alice's ephemeral private key
        """
        return self.ephemeral_private
