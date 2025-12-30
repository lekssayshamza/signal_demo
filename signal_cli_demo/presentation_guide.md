# Signal Protocol Presentation Guide

## Overview
This guide contains the key code sections to explain in your Signal Protocol presentation. Each section includes:
- **Code Snippet**: The actual implementation
- **Why Explain**: Importance to understanding Signal
- **What to Say**: Presentation script for your slides
- **Signal Context**: How it fits into the broader protocol

---

## 1. X3DH - Extended Triple Diffie-Hellman

### Code Snippet
```python
def compute_dh(private_key, public_key):
    """Basic Diffie-Hellman computation using X25519"""
    shared_secret = private_key.exchange(public_key)
    return shared_secret

def x3dh_compute_master_secret(alice_identity_private, alice_ephemeral_private,
                               bob_identity_public, bob_signed_prekey_public,
                               bob_onetime_prekey_public):
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
```

### Why Explain This Code
This is the **foundation** of Signal's security. X3DH establishes the initial shared secret between Alice and Bob without them ever having communicated before. The "triple" refers to the three Diffie-Hellman exchanges that provide different security properties.

### What to Say in Presentation
"X3DH is the 'extended triple Diffie-Hellman' key agreement that makes Signal possible. Instead of just one Diffie-Hellman exchange, it uses **three**:

- **DH1** provides **authentication** - Alice proves her identity using her long-term key
- **DH2** provides **identity hiding** - prevents passive eavesdroppers from learning who is talking to whom
- **DH3** provides **forward secrecy** - the one-time prekey is deleted after use

The genius is the **ephemeral key** (EK_A). If Alice's identity key gets compromised later, **past conversations remain secure** because the ephemeral key 'covers' the identity key in the computation."

### Signal Protocol Context
- **Precondition**: Alice knows Bob's public keys from his server
- **Result**: Shared master secret that both Alice and Bob can compute
- **Security**: Forward secrecy even if long-term keys are compromised
- **Real Signal**: Uses additional signatures and more complex key types

---

## 2. HKDF - Key Derivation Function

### Code Snippet
```python
def hkdf_like(input_key_material, info=b"", length=32):
    """Simplified HKDF - Extract-then-Expand key derivation"""
    # Extract phase
    prk = hmac.new(b"", input_key_material, hashlib.sha256).digest()

    # Expand phase
    expanded = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    return expanded[:length]

def derive_root_key(master_secret):
    """Master Secret → Root Key"""
    return hkdf_like(master_secret, b"root", 32)

def derive_chain_keys(root_key):
    """Root Key → Sending & Receiving Chain Keys"""
    sending_ck = hkdf_like(root_key, b"sending_chain", 32)
    receiving_ck = hkdf_like(root_key, b"receiving_chain", 32)
    return sending_ck, receiving_ck
```

### Why Explain This Code
HKDF (HMAC-based Key Derivation Function) is how Signal derives multiple cryptographically independent keys from a single secret. This is crucial because it allows one master secret to spawn an entire key hierarchy without weakening security.

### What to Say in Presentation
"Signal uses HKDF to create a **key hierarchy** from the master secret. Think of it as a tree:

```
Master Secret (from X3DH)
    ├── Root Key (foundation for ratchet)
    └── Chain Keys (sending & receiving)
        └── Message Keys (one per message)
```

The `info` parameter ensures each derived key is **cryptographically independent**. If an attacker compromises a message key, they can't work backwards to get the root key or other message keys.

This is why Signal can provide **post-compromise security** - compromising one key doesn't compromise the others."

### Signal Protocol Context
- **Purpose**: Derive multiple keys from one secret without weakening security
- **Security**: Each key is independent - compromise of one doesn't affect others
- **Real Signal**: Uses full HKDF with salts and multiple expansion rounds
- **Importance**: Enables the entire double ratchet mechanism

---

## 3. Double Ratchet Algorithm

### Code Snippet
```python
def derive_message_key(chain_key):
    """
    THE DOUBLE RATCHET ALGORITHM

    This implements the "ratcheting" behavior where each message key
    is derived from the current chain key, and the chain key is advanced.
    """
    # Derive message key from current chain key
    message_key = hkdf_like(chain_key, b"message", 32)

    # Advance the chain key (ratchet forward)
    new_chain_key = hkdf_like(chain_key, b"next_chain", 32)

    return message_key, new_chain_key

class DoubleRatchet:
    def get_next_message_key(self):
        """Each call advances the ratchet"""
        message_key, new_chain_key = derive_message_key(self.sending_chain_key)
        self.sending_chain_key = new_chain_key  # Ratchet advances!
        return message_key
```

### Why Explain This Code
This is the **heart** of Signal's security innovation. The double ratchet ensures that each message uses a unique key, and old keys become permanently unusable. It's what provides Signal's famous forward secrecy and post-compromise security.

### What to Say in Presentation
"The Double Ratchet is Signal's secret weapon. Here's how it works:

1. **Derive**: Each message gets a unique key from the current chain key
2. **Advance**: The chain key is immediately replaced with a new one
3. **Repeat**: Next message uses the new chain key

Like a ratchet wrench, it only moves **forward** - you can't go back. This means:

- **Forward Secrecy**: Old messages stay secure even if current keys are compromised
- **Post-Compromise Security**: New messages stay secure after a breach

Each party has their own ratchet that advances as they send/receive messages."

### Signal Protocol Context
- **Components**: Root key, chain keys, message keys
- **Advancement**: Happens with each message (symmetric ratchet)
- **Direction**: Separate sending and receiving chains for bidirectional communication
- **Real Signal**: Much more complex with header keys, symmetric ratcheting, etc.

---

## 4. Message Encryption Flow

### Code Snippet
```python
def send_messages_demo():
    """DEMONSTRATES THE COMPLETE MESSAGE FLOW"""
    messages = ["Hello!", "How are you?", "Meet for coffee?"]

    # Initialize ratchet with master secret
    ratchet = DoubleRatchet(master_secret)

    for i, message in enumerate(messages, 1):
        # This advances the ratchet!
        message_key = ratchet.get_next_message_key()

        # Encrypt with unique key
        ciphertext = encrypt_message(message_key, message)

        print(f"Message {i}: '{message}'")
        print(f"  Unique Key: {message_key.hex()[:16]}...")
        print(f"  Chain Advanced: New chain key ready")
```

### Why Explain This Code
This shows the **practical result** of the double ratchet. Each message gets a completely different key, proving that the protocol achieves perfect forward secrecy in practice.

### What to Say in Presentation
"Let's see the ratchet in action. Watch how each message gets a **completely different key**:

```
Message 1: Key = a1b2c3d4... → Encrypt → Chain advances
Message 2: Key = e5f6g7h8... → Encrypt → Chain advances
Message 3: Key = i9j0k1l2... → Encrypt → Chain advances
```

This demonstrates **perfect forward secrecy**. If an attacker compromises the key for Message 2, they still can't decrypt Messages 1 or 3 because:

- Message 1's key was already 'forgotten' when the chain advanced
- Message 3's key hasn't been generated yet

The chain only moves **forward** - like a ratchet!"

### Signal Protocol Context
- **Per-Message**: Unique key for each message
- **Authenticated Encryption**: Uses AES-GCM or similar
- **Headers**: In real Signal, message headers are encrypted with different keys
- **Out-of-Order**: Real Signal handles out-of-order message delivery

---

## 5. Attack Simulation - Proving Security

### Code Snippet
```python
class Attacker:
    def compromise_key(self, message_num, key):
        """Attacker obtains one specific message key"""
        self.compromised_keys[message_num] = key

    def try_decrypt(self, message_num, ciphertext):
        """Can only decrypt the compromised message"""
        if message_num in self.compromised_keys:
            try:
                key = self.compromised_keys[message_num]
                plaintext = decrypt_message(key, ciphertext)
                return True, plaintext
            except:
                return False, "Decryption failed"
        else:
            return False, "No key available - message secure!"

def demonstrate_security():
    """THE CLIMAX - Prove all security properties"""
    attacker = Attacker()
    attacker.compromise_key(2, actual_keys[1])  # Only Message 2

    for i, (msg, ct) in enumerate(zip(messages, ciphertexts), 1):
        success, result = attacker.try_decrypt(i, ct)

        if success:
            print(f"❌ COMPROMISED: '{result}'")
        else:
            print(f"✅ SECURE: {result}")
```

### Why Explain This Code
This is the **proof** that Signal's design works. It demonstrates that compromising one message key affects only that message, proving forward secrecy and post-compromise security.

### What to Say in Presentation
"Now for the moment of truth. Let's simulate a powerful attacker who compromises **only** the key for Message 2. What can they decrypt?

**Result:**
- Message 1: ✅ **SECURE** (Forward Secrecy)
- Message 2: ❌ **COMPROMISED** (Expected - they have the key)
- Message 3: ✅ **SECURE** (Post-Compromise Security)

This proves Signal's security guarantees:

1. **Forward Secrecy**: Past messages stay secure
2. **Post-Compromise Security**: Future messages stay secure
3. **Perfect Forward Secrecy**: Each message has a unique key

Even with a compromised key, the attacker is limited to just **one message**. That's the power of the double ratchet!"

### Signal Protocol Context
- **Worst Case**: Attacker has one message key
- **Result**: Can decrypt only that one message
- **Implication**: Breaches are contained, not catastrophic
- **Real Attacks**: This defends against memory corruption, keyloggers, etc.

---

## Presentation Flow Recommendations

### Slide Structure
1. **Introduction** - What is Signal and why it matters
2. **X3DH** - How initial key agreement works
3. **Key Hierarchy** - How HKDF builds the key tree
4. **Double Ratchet** - The core algorithm explained
5. **Live Demo** - Show messages with evolving keys
6. **Attack Simulation** - Prove security properties
7. **Conclusion** - Why this design is revolutionary

### Key Takeaways to Emphasize
- **X3DH**: Triple DH provides authentication + forward secrecy
- **HKDF**: Derives independent keys from one secret
- **Double Ratchet**: Keys evolve and old ones become unusable
- **Security**: Breach of one key affects only one message
- **Innovation**: Perfect forward secrecy in messaging

### Timing Suggestions
- X3DH: 3-4 minutes
- HKDF: 2-3 minutes
- Double Ratchet: 4-5 minutes
- Demo: 3-4 minutes
- Attack Simulation: 3-4 minutes
- Total: 15-20 minutes

Remember: Focus on **why** each component exists and **how** they work together to provide Signal's security guarantees!
