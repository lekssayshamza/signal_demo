#!/usr/bin/env python3
"""
Attack simulation module for the Signal Protocol educational demo.

This module demonstrates what happens when an attacker compromises
specific keys or message keys.
"""

from crypto.symmetric import decrypt_message


class Attacker:
    """
    Represents an attacker who can compromise various cryptographic materials.
    """

    def __init__(self):
        """
        Initialize the attacker with no compromised keys.
        """
        self.compromised_message_keys = {}

    def compromise_message_key(self, message_number: int, message_key: bytes):
        """
        Simulate the attacker obtaining a specific message key.

        Args:
            message_number: Which message number's key was compromised
            message_key: The compromised message key
        """
        self.compromised_message_keys[message_number] = message_key

    def try_decrypt_message(self, message_number: int, ciphertext: bytes) -> tuple[bool, str]:
        """
        Attempt to decrypt a message using only compromised keys.

        Args:
            message_number: The message number to attempt decryption on
            ciphertext: The encrypted message

        Returns:
            Tuple of (success: bool, result: str)
        """
        if message_number in self.compromised_message_keys:
            try:
                key = self.compromised_message_keys[message_number]
                plaintext = decrypt_message(key, ciphertext)
                return True, plaintext
            except ValueError:
                return False, "Échec du déchiffrement – clé incorrecte ou message corrompu"
        else:
            return False, "Aucune clé compromise disponible pour ce message"

    def demonstrate_attack(self, messages: list, ciphertexts: list, actual_keys: list = None):
        """
        Demonstrate the attacker's capabilities and limitations.

        Args:
            messages: List of original plaintext messages
            ciphertexts: List of corresponding encrypted messages
            actual_keys: List of actual message keys used for encryption (for verification)
        """
        print("DÉMONSTRATION D’ATTAQUE")
        print("L’attaquant a compromis UNIQUEMENT la clé de message pour le message 2")
        print()

        for i, (plaintext, ciphertext) in enumerate(zip(messages, ciphertexts), 1):
            success, result = self.try_decrypt_message(i, ciphertext)

            print(f"Tentative de déchiffrement du message {i}...")

            if success:
                print(f"  SUCCÈS: '{result}'")
                print("  Ce message a été compromis!")
            else:
                print(f"  ÉCHEC: {result}")
                if actual_keys and i <= len(actual_keys):
                    # Show that the key was actually different
                    actual_key = actual_keys[i-1]
                    print(f"  (La clé réellement utilisée était différente: {actual_key.hex()[:16]}...)")
                print("  Ce message reste sécurisé!")

            print()
