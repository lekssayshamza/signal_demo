#!/usr/bin/env python3
"""
Signal Protocol Educational Demo - Main CLI Application

This program demonstrates the core concepts of the Signal protocol:
- X3DH (Extended Triple Diffie-Hellman) for initial key agreement
- Double Ratchet for ongoing message encryption
- Forward secrecy and post-compromise security

⚠️  NOT FOR PRODUCTION USE - Educational purposes only!
"""

from alice import Alice
from bob import Bob
from crypto.x3dh import x3dh_compute_master_secret
from crypto.ratchet import DoubleRatchet
from crypto.symmetric import encrypt_message, decrypt_message
from attacks import Attacker
from utils import (
    print_separator, print_hex, print_step_header,
    print_explanation, print_message_info, print_attack_info, print_result
)
from cryptography.hazmat.primitives import serialization


def main():
    """
    Main demonstration function that walks through the Signal protocol step by step.
    """
    print("Signal Protocol Educational Demo")
    print("===================================")
    print()
    print("This demo shows how the Signal messaging protocol provides:")
    print("- Forward secrecy (past messages stay secure)")
    print("- Post-compromise security (future messages stay secure)")
    print("- Perfect forward secrecy through key evolution")
    print()
    print("WARNING: This is simplified cryptography for education only!")
    print()

    # ============================================================================
    # STEP 1: Show Public Keys
    # ============================================================================
    print_step_header(1, "Show Public Keys")

    print_explanation("""
    Before communication begins, both parties publish their public keys.
    These are safe to share openly - only the private keys are secret.

    Bob publishes his long-term keys on a server:
    - Identity Key (IK_B) - Bob's long-term identity
    - Signed Pre-Key (SPK_B) - Medium-term key, cryptographically signed
    - One-Time Pre-Key (OPK_B) - Single-use key, deleted after use

    Alice generates ephemeral keys for this conversation:
    - Identity Key (IK_A) - Alice's long-term identity
    - Ephemeral Key (EK_A) - One-time key for this conversation
    """)

    # Initialize Alice and Bob
    alice = Alice()
    bob = Bob()

    print("Bob's Public Keys:")
    print_hex(bob.get_identity_public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), "Identity Key (IK_B)", 2)
    print_hex(bob.get_signed_prekey_public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), "Signed Pre-Key (SPK_B)", 2)
    print_hex(bob.get_onetime_prekey_public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), "One-Time Pre-Key (OPK_B)", 2)
    print()

    print("Alice's Public Keys:")
    print_hex(alice.get_identity_public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), "Identity Key (IK_A)", 2)
    print_hex(alice.get_ephemeral_public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), "Ephemeral Key (EK_A)", 2)
    print()

    # ============================================================================
    # STEP 2: X3DH Computation
    # ============================================================================
    print_step_header(2, "X3DH Computation")

    print_explanation("""
    X3DH (Extended Triple Diffie-Hellman) establishes a shared secret.

    Alice computes three Diffie-Hellman exchanges using Bob's public keys
    and her private keys:

    DH1 = DH(IK_A_private, SPK_B_public)  [Alice's identity + Bob's signed prekey]
    DH2 = DH(EK_A_private, IK_B_public)   [Alice's ephemeral + Bob's identity]
    DH3 = DH(EK_A_private, OPK_B_public)  [Alice's ephemeral + Bob's one-time prekey]

    The master secret is derived from all three: MASTER_SECRET = KDF(DH1 || DH2 || DH3)

    This provides forward secrecy because compromising Alice's identity key
    doesn't reveal past conversations (thanks to the ephemeral key).
    """)

    # Alice performs X3DH computation
    master_secret, dh1, dh2, dh3 = x3dh_compute_master_secret(
        alice_identity_private=alice.get_identity_private_key(),
        alice_ephemeral_private=alice.get_ephemeral_private_key(),
        bob_identity_public=bob.get_identity_public_key(),
        bob_signed_prekey_public=bob.get_signed_prekey_public_key(),
        bob_onetime_prekey_public=bob.get_onetime_prekey_public_key()
    )

    print("Diffie-Hellman Results:")
    print_hex(dh1, "DH1 = DH(IK_A_private, SPK_B_public)", 2)
    print_hex(dh2, "DH2 = DH(EK_A_private, IK_B_public)", 2)
    print_hex(dh3, "DH3 = DH(EK_A_private, OPK_B_public)", 2)
    print()

    print("Final Master Secret:")
    print_hex(master_secret, "MASTER_SECRET = KDF(DH1 || DH2 || DH3)", 2)
    print()

    # ============================================================================
    # STEP 3: Root Key Derivation
    # ============================================================================
    print_step_header(3, "Root Key Derivation")

    print_explanation("""
    The root key is derived from the master secret and serves as the foundation
    for the double ratchet algorithm.

    Root Key = KDF(MASTER_SECRET)

    The root key is NEVER used directly for encryption. Instead, it derives
    "chain keys" that evolve with each message. This ensures that compromising
    the root key doesn't immediately compromise all messages.
    """)

    # Initialize the double ratchet
    ratchet = DoubleRatchet(master_secret)

    print("Root Key:")
    print_hex(ratchet.get_root_key(), "Root Key (never used directly)", 2)
    print()

    # ============================================================================
    # STEP 4: Initialize Double Ratchet
    # ============================================================================
    print_step_header(4, "Initialize Double Ratchet")

    print_explanation("""
    The double ratchet derives separate chain keys for sending and receiving:

    Sending Chain Key (CKs) = KDF(Root Key, "sending_chain")
    Receiving Chain Key (CKr) = KDF(Root Key, "receiving_chain")

    Each message will derive a unique message key from the current chain key,
    then advance the chain key. This creates a "ratchet" effect where keys
    evolve and old keys become useless.
    """)

    print("Initial Chain Keys:")
    print_hex(ratchet.get_sending_chain_key(), "Sending Chain Key (CKs)", 2)
    print_hex(ratchet.get_receiving_chain_key(), "Receiving Chain Key (CKr)", 2)
    print()

    # ============================================================================
    # STEP 5: Secure Messaging (Alice → Bob)
    # ============================================================================
    print_step_header(5, "Secure Messaging (Alice to Bob)")

    print_explanation("""
    Alice sends three messages to Bob. For each message:

    1. Derive a unique Message Key (MK) from the current Sending Chain Key
    2. Advance the Sending Chain Key (ratchet forward)
    3. Encrypt the message with the Message Key

    Each message gets a unique key, and the chain evolves so that
    compromising one message key doesn't help with others.
    """)

    # Messages to send
    messages = [
        "Hello Bob!",
        "How are you doing?",
        "Let's meet for coffee."
    ]

    # Store encrypted messages and their keys for later attack simulation
    encrypted_messages = []
    message_keys = []

    for i, message in enumerate(messages, 1):
        print(f"Sending Message {i}")

        # Get next message key (this advances the chain)
        message_key = ratchet.get_next_message_key()
        message_keys.append(message_key)

        # Encrypt the message
        ciphertext = encrypt_message(message_key, message)
        encrypted_messages.append(ciphertext)

        print_message_info(i, message,
                          f"Derived from Sending Chain Key, then chain advanced")
        print_hex(message_key, "Message Key (MK)", 2)
        print_hex(ciphertext, "Encrypted Message", 2)
        print()

    # ============================================================================
    # STEP 6: Attack Simulation
    # ============================================================================
    print_step_header(6, "Attack Simulation")

    print_explanation("""
    Now we simulate a powerful attacker who compromises ONE message key.

    In a real attack, this could happen through:
    - Memory corruption in the messaging app
    - Side-channel attacks
    - Malware on the device

    The attacker obtains the Message Key for Message 2 (MK2).
    Can they decrypt other messages?
    """)

    # Create attacker and compromise MK2
    attacker = Attacker()

    # Compromise the actual key used for message 2 (index 1)
    mk2 = message_keys[1]  # Message 2's key
    attacker.compromise_message_key(2, mk2)

    print_attack_info("Attacker obtained Message Key 2 (MK2)")
    print_hex(mk2, "Compromised Key (MK2)", 2)
    print()

    # ============================================================================
    # STEP 7: Decryption Attempts
    # ============================================================================
    print_step_header(7, "Decryption Attempts")

    print_explanation("""
    The attacker tries to decrypt all three messages using only MK2.

    This demonstrates Signal's security properties:

    - Forward Secrecy: Past messages (Message 1) remain secure
    - Post-Compromise Security: Future messages (Message 3) remain secure
    - Perfect Forward Secrecy: Each message uses a unique key
    """)

    attacker.demonstrate_attack(messages, encrypted_messages, message_keys)

    # ============================================================================
    # CONCLUSION
    # ============================================================================
    print_separator("CONCLUSION")

    print_explanation("""
    Signal Protocol Security Properties Demonstrated:

    FORWARD SECRECY: Compromising MK2 doesn't reveal past messages
    POST-COMPROMISE SECURITY: Compromising MK2 doesn't reveal future messages
    PERFECT FORWARD SECRECY: Each message uses a unique, evolving key

    Key Insights:

    - X3DH establishes the initial shared secret securely
    - Double Ratchet evolves keys so each message is unique
    - Compromising one message key affects only that message
    - The protocol provides strong security guarantees even against powerful attackers

    Real Signal Protocol includes additional features:
    - Symmetric ratchet for bidirectional communication
    - Out-of-order message handling
    - Cryptographic signatures on pre-keys
    - Session management and key updates
    """)

    print("Demo completed!")


if __name__ == "__main__":
    main()
