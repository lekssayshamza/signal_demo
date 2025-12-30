#!/usr/bin/env python3
"""
Signal Protocol Key Distribution Server - Educational Simulation

This module simulates the behavior of the Signal Protocol's key distribution server.
The server acts as a non-confidential relay that stores and distributes public keys only.

SECURITY MODEL:
- Server stores ONLY public keys (never private keys)
- Server never encrypts/decrypts messages
- Server never sees message content
- Server acts as a trusted third party for key distribution

This is a SIMULATION for educational purposes only.
In the real Signal Protocol, this functionality is provided by the Signal servers.
"""

from cryptography.hazmat.primitives import serialization


class KeyServer:
    """
    Signal Protocol Key Distribution Server Simulation.

    The server maintains a public directory of user keys:
    - Identity Keys (long-term public keys)
    - Signed Pre-Keys (medium-term public keys)
    - One-Time Pre-Keys (single-use public keys)

    Security Properties:
    - Server is non-confidential (stores only public information)
    - Server cannot decrypt messages or compromise conversations
    - Server acts as a trusted third party for key distribution
    """

    def __init__(self):
        """
        Initialize the key server with an empty user registry.

        The server starts with no users registered and maintains
        all key material in memory only.
        """
        # users[user_id] = {
        #     'identity_key': bytes,
        #     'signed_prekey': bytes,
        #     'one_time_prekey': bytes  # Optional, consumed after use
        # }
        self.users = {}

        print("Signal Key Server initialized (educational simulation)")
        print("Server state: No users registered")
        print("-" * 50)

    def register_user(self, user_id: str, public_keys: dict) -> bool:
        """
        Register a user's public keys on the server.

        This simulates the process where Bob publishes his public keys
        to the Signal servers before Alice can initiate contact.

        Args:
            user_id: Unique identifier for the user (e.g., "bob")
            public_keys: Dictionary containing:
                - 'identity_key': Public identity key
                - 'signed_prekey': Public signed pre-key
                - 'one_time_prekey': Public one-time pre-key (optional)

        Returns:
            True if registration successful, False otherwise

        Security Note:
            The server stores only public keys and cannot access
            the corresponding private keys held by the user.
        """
        try:
            # Validate required keys
            if 'identity_key' not in public_keys:
                print(f"ERROR: Identity key required for user {user_id}")
                return False

            if 'signed_prekey' not in public_keys:
                print(f"ERROR: Signed pre-key required for user {user_id}")
                return False

            # Store public keys (convert to raw bytes for consistency)
            user_data = {
                'identity_key': public_keys['identity_key'].public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ),
                'signed_prekey': public_keys['signed_prekey'].public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            }

            # One-time pre-key is optional
            if 'one_time_prekey' in public_keys and public_keys['one_time_prekey'] is not None:
                user_data['one_time_prekey'] = public_keys['one_time_prekey'].public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )

            # Register the user
            self.users[user_id] = user_data

            print(f"SUCCESS: {user_id} has published public keys to the server")
            print(f"  - Identity Key registered")
            print(f"  - Signed Pre-Key registered")
            if 'one_time_prekey' in user_data:
                print(f"  - One-Time Pre-Key registered")
            else:
                print(f"  - No One-Time Pre-Key provided")

            return True

        except Exception as e:
            print(f"ERROR: Failed to register user {user_id}: {e}")
            return False

    def get_prekeys(self, user_id: str) -> dict:
        """
        Retrieve a user's public pre-keys for X3DH initialization.

        This simulates Alice fetching Bob's public keys from the server
        before performing X3DH key agreement.

        Args:
            user_id: The user whose keys to retrieve

        Returns:
            Dictionary with 'identity_key', 'signed_prekey', and optionally
            'one_time_prekey', or None if user not found

        Security Note:
            This is public information that can be safely shared.
            The server acts as a trusted directory service.
        """
        if user_id not in self.users:
            print(f"ERROR: User {user_id} not found on server")
            return None

        user_data = self.users[user_id]

        # Return a copy of the public keys
        prekeys = {
            'identity_key': user_data['identity_key'],
            'signed_prekey': user_data['signed_prekey']
        }

        # Include one-time pre-key if available
        if 'one_time_prekey' in user_data:
            prekeys['one_time_prekey'] = user_data['one_time_prekey']
        else:
            prekeys['one_time_prekey'] = None
            print(f"NOTICE: No one-time pre-key available for {user_id}")

        print(f"SUCCESS: Server provided {user_id}'s pre-keys to requesting client")
        print(f"  - Identity Key delivered")
        print(f"  - Signed Pre-Key delivered")
        if prekeys['one_time_prekey'] is not None:
            print(f"  - One-Time Pre-Key delivered")
        else:
            print(f"  - No One-Time Pre-Key available")

        return prekeys

    def consume_one_time_prekey(self, user_id: str) -> bool:
        """
        Consume (delete) a user's one-time pre-key after X3DH usage.

        In the real Signal protocol, one-time pre-keys are deleted from
        the server immediately after being used in X3DH. This prevents
        replay attacks and ensures each pre-key is used at most once.

        Args:
            user_id: The user whose one-time pre-key to consume

        Returns:
            True if consumed successfully, False otherwise

        Security Note:
            This is a critical security property: one-time pre-keys
            are consumed to prevent reuse in different conversations.
        """
        if user_id not in self.users:
            print(f"ERROR: User {user_id} not found on server")
            return False

        user_data = self.users[user_id]

        if 'one_time_prekey' not in user_data:
            print(f"NOTICE: No one-time pre-key to consume for {user_id}")
            return True  # Not an error if none exists

        # Consume (delete) the one-time pre-key
        del user_data['one_time_prekey']

        print(f"SUCCESS: One-time pre-key consumed and deleted from server for {user_id}")
        print("Security: This pre-key cannot be reused in future conversations")

        return True

    def show_server_state(self):
        """
        Display the current state of the key server.

        This educational function shows what public information
        is stored on the server, demonstrating that the server
        holds no confidential information.

        Security Note:
            Everything displayed here is public information.
            The server cannot compromise any conversations.
        """
        print("\n" + "="*60)
        print("SIGNAL KEY SERVER STATE (Educational View)")
        print("="*60)

        if not self.users:
            print("No users registered on the server")
            print("Server is empty")
        else:
            print(f"Registered users: {len(self.users)}")

            for user_id, user_data in self.users.items():
                print(f"\nUser: {user_id}")
                print(f"  Identity Key: {user_data['identity_key'].hex()[:32]}...")
                print(f"  Signed Pre-Key: {user_data['signed_prekey'].hex()[:32]}...")

                if 'one_time_prekey' in user_data:
                    print(f"  One-Time Pre-Key: {user_data['one_time_prekey'].hex()[:32]}...")
                    print("  Status: One-Time Pre-Key available for X3DH")
                else:
                    print("  One-Time Pre-Key: CONSUMED/DELETED")
                    print("  Status: No one-time pre-key available")

        print("\nSECURITY ANALYSIS:")
        print("- Server stores ONLY public keys (no private keys)")
        print("- Server cannot decrypt messages or compromise conversations")
        print("- Server acts as trusted directory for key distribution")
        print("- All stored data is safe to share publicly")
        print("="*60 + "\n")

    def is_user_registered(self, user_id: str) -> bool:
        """
        Check if a user is registered on the server.

        Args:
            user_id: User ID to check

        Returns:
            True if user is registered, False otherwise
        """
        return user_id in self.users

    def has_one_time_prekey(self, user_id: str) -> bool:
        """
        Check if a user has an available one-time pre-key.

        Args:
            user_id: User ID to check

        Returns:
            True if user has one-time pre-key available, False otherwise
        """
        if user_id not in self.users:
            return False
        return 'one_time_prekey' in self.users[user_id]
