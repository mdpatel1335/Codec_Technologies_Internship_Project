# Cryptography Toolkit

**Author:** Mihir Patel

A Python-based toolkit for learning and experimenting with cryptography, featuring **AES**, **RSA**, and **SHA** algorithms. Designed for educational purposes, it provides an easy-to-use interface for encryption, decryption, hashing, and digital signatures.

> ⚠️ This toolkit is intended for learning and experimentation. For production use, rely on vetted cryptographic libraries and best practices.

---

## Key Features

### 🔐 AES (Advanced Encryption Standard)

* Supports key sizes: 128, 192, 256 bits
* CBC mode with PKCS7 padding
* Encrypt/decrypt text and files
* Secure key generation
* Optimized for speed with chunked file processing
* Interactive user input support

### 🔑 RSA (Rivest–Shamir–Adleman)

* Supports key sizes: 1024, 2048, 3072, 4096 bits
* Generate public/private key pairs
* Encrypt/decrypt messages
* Sign and verify messages
* Hybrid RSA+AES encryption for large data
* Save/load keys in PEM format

### #️⃣ SHA (Secure Hash Algorithm)

* Algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
* Hash text and files
* HMAC and PBKDF2 password hashing
* Salt-based password hashing for added security
* Output in Hexadecimal or Base64

---

## Project Structure

```
crypto_toolkit/
├── aes_cipher.py       # AES encryption/decryption with interactive user input
├── rsa_cipher.py       # RSA key generation, encryption/decryption, signing, verification
├── sha_hasher.py       # SHA hashing, HMAC, PBKDF2, and advanced hash utilities
├── crypto_toolkit.py   # Unified interface combining AES, RSA, and SHA modules
├── demo.py             # Interactive demo combining all modules
├── requirements.txt    # Python dependencies (pycryptodome, cryptography, etc.)
├── README.md           # Project documentation
└── LICENSE             # Open-source license file (MIT License)
```

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/crypto_toolkit.git
cd crypto_toolkit

# Create a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### Usage

```python
from crypto_toolkit import CryptoToolkit

# Initialize the toolkit
toolkit = CryptoToolkit()

# AES Example
aes_result = toolkit.encrypt_message("Hello World!", key_size=256)
print("Ciphertext:", aes_result['ciphertext'].hex())
print("Decrypted:", toolkit.decrypt_message(aes_result['ciphertext'], aes_result['key']))

# RSA Example
keys = toolkit.generate_rsa_keypair(2048)
message = b"Secure Message"
# Encrypt/decrypt using RSA
from rsa_cipher import RSACipher
rsa = RSACipher(2048)
ciphertext = rsa.encrypt(message, keys['public_key'])
plaintext = rsa.decrypt(ciphertext, keys['private_key'])
print("RSA decrypted matches original:", plaintext == message)

# SHA Example
hash_result = toolkit.hash_data("Hello World!", algorithm='sha256')
print("SHA-256 Hash:", hash_result)
```

### Run Interactive Demo

```bash
python demo.py
```

---

## Dependencies

* `cryptography>=41.0.4` – RSA, hashing, key management
* `pycryptodome>=3.19.0` – AES and additional cryptography algorithms
* `colorama>=0.4.6` – Colored terminal output

Install all dependencies with:

```bash
pip install -r requirements.txt
```

---

## Security Guidelines

* Never hardcode keys in your code.
* Use AES-256 and RSA-2048+ for strong encryption.
* Always generate cryptographically secure random numbers.
* Prefer SHA-256 or higher for hashing operations.
* For password storage, use PBKDF2 with sufficient iterations.

> This toolkit is educational. Always rely on vetted libraries for production.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Feel free to fork the repository and submit pull requests to improve the toolkit.
