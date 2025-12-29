# Signal Protocol Educational Demo

A Python command-line application that demonstrates the core concepts of the Signal messaging protocol, including X3DH key agreement and the Double Ratchet algorithm.

## ⚠️ Important Warning

**This is NOT production cryptography. It is for educational purposes only!**

All keys are printed in hexadecimal for clarity, and the implementation uses simplified cryptographic operations. Do not use this code for real security applications.

## Features Demonstrated

- **X3DH (Extended Triple Diffie-Hellman)**: Secure key agreement over insecure channels
- **Double Ratchet**: Forward secrecy and post-compromise security through key evolution
- **Attack Simulation**: Shows that compromising one message key doesn't compromise others

## Security Properties Proven

✅ **Forward Secrecy**: Past messages remain secure even if current keys are compromised
✅ **Post-Compromise Security**: Future messages remain secure after a breach
✅ **Perfect Forward Secrecy**: Each message uses a unique, evolving key

## Project Structure

```
signal_cli_demo/
├── main.py                # CLI menu and demo flow
├── alice.py               # Alice's cryptographic state and keys
├── bob.py                 # Bob's cryptographic state and keys
├── crypto/
│   ├── x3dh.py            # Simplified X3DH implementation
│   ├── ratchet.py         # Simplified Double Ratchet
│   ├── kdf.py             # Key derivation (HKDF-like)
│   └── symmetric.py       # Symmetric encryption (Fernet/AES-GCM)
├── attacks.py             # Key compromise simulation
├── utils.py               # Printing helpers (hex, separators)
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Installation & Usage

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the demo:
   ```bash
   python main.py
   ```

The program automatically executes the complete educational scenario step-by-step.

## Educational Flow

1. **Show Public Keys**: Display all public keys used in the protocol
2. **X3DH Computation**: Demonstrate the triple Diffie-Hellman key agreement
3. **Root Key Derivation**: Show how the master secret becomes the root key
4. **Initialize Double Ratchet**: Set up the sending and receiving chain keys
5. **Secure Messaging**: Alice sends three messages with evolving keys
6. **Attack Simulation**: Demonstrate that compromising one message key affects only that message
7. **Conclusion**: Summarize the security properties achieved

## Cryptographic Simplifications

- Uses X25519 for Diffie-Hellman (via cryptography library)
- HKDF-like key derivation with SHA-256
- Fernet (AES-128 CBC + HMAC-SHA256) for authenticated encryption
- Simplified ratchet logic for educational clarity

## Real Signal Protocol Differences

The real Signal protocol includes additional complexity:
- Symmetric ratcheting for bidirectional communication
- Out-of-order message handling
- Cryptographic signatures on pre-keys
- Session management and key updates
- Protection against various attack vectors

This demo focuses on the core concepts of forward secrecy and post-compromise security.
