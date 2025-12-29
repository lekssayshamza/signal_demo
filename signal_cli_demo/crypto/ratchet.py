#!/usr/bin/env python3
"""
Double Ratchet implementation for the Signal Protocol educational demo.

The Double Ratchet provides forward secrecy and post-compromise security
by continuously evolving encryption keys for each message.
"""

from .kdf import derive_root_key, derive_chain_keys, derive_message_key


class DoubleRatchet:
    """
    Simplified Double Ratchet implementation.

    In the real Signal protocol, there are sending and receiving ratchets
    that can advance independently. Here we simplify for educational purposes.
    """

    def __init__(self, master_secret: bytes):
        """
        Initialize the double ratchet with the master secret from X3DH.

        Args:
            master_secret: Shared secret from X3DH key agreement
        """
        # Derive the root key from master secret
        self.root_key = derive_root_key(master_secret)

        # Derive initial sending and receiving chain keys
        self.sending_chain_key, self.receiving_chain_key = derive_chain_keys(self.root_key)

        # Track message numbers for educational purposes
        self.message_count = 0

    def get_next_message_key(self) -> bytes:
        """
        Get the next message key for sending and advance the sending chain.

        Returns:
            32-byte message key for encryption
        """
        message_key, new_chain_key = derive_message_key(self.sending_chain_key)
        self.sending_chain_key = new_chain_key
        self.message_count += 1
        return message_key

    def get_message_key_for_receiving(self, message_number: int) -> bytes:
        """
        Get the message key for receiving a specific message number.

        In a real implementation, this would be more complex with proper
        ratchet advancement. Here we simulate by deriving keys sequentially.

        Args:
            message_number: Which message number to get the key for

        Returns:
            32-byte message key for decryption
        """
        # For educational purposes, we derive the key by advancing
        # from the initial receiving chain key
        current_key = self.receiving_chain_key

        # Advance the chain to the requested message number
        for i in range(message_number):
            _, current_key = derive_message_key(current_key)

        # Get the message key for this message
        message_key, _ = derive_message_key(current_key)

        return message_key

    def get_root_key(self) -> bytes:
        """
        Get the current root key (for educational display).

        Returns:
            32-byte root key
        """
        return self.root_key

    def get_sending_chain_key(self) -> bytes:
        """
        Get the current sending chain key (for educational display).

        Returns:
            32-byte sending chain key
        """
        return self.sending_chain_key

    def get_receiving_chain_key(self) -> bytes:
        """
        Get the current receiving chain key (for educational display).

        Returns:
            32-byte receiving chain key
        """
        return self.receiving_chain_key
