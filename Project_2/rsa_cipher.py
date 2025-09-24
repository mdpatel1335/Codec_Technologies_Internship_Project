"""
RSA Implementation with interactive user input
Supports key generation, encryption, decryption, signing, and verifying.
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

class RSACipher:
    def __init__(self, key_size: int = 2048):
        """Generate new RSA keypair"""
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()

    def export_keys(self):
        return {
            'private_key': self.key.export_key().decode(),
            'public_key': self.public_key.export_key().decode()
        }

    def encrypt(self, plaintext: str) -> str:
        cipher = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        cipher = PKCS1_OAEP.new(self.key)
        plain = cipher.decrypt(base64.b64decode(ciphertext))
        return plain.decode('utf-8')

    def sign(self, message: str) -> str:
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(h)
        return base64.b64encode(signature).decode('utf-8')

    def verify(self, message: str, signature: str) -> bool:
        h = SHA256.new(message.encode('utf-8'))
        try:
            pkcs1_15.new(self.public_key).verify(h, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False


if __name__ == "__main__":
    print("RSA Interactive Demo")
    key_size = int(input("Enter RSA key size (e.g. 2048): "))
    rsa_cipher = RSACipher(key_size)
    action = input("Choose action - Encrypt (e), Decrypt (d), Sign (s), Verify (v): ").lower()

    if action == 'e':
        plaintext = input("Enter plaintext to encrypt: ")
        ciphertext = rsa_cipher.encrypt(plaintext)
        print("Encrypted (Base64):")
        print(ciphertext)

    elif action == 'd':
        ciphertext = input("Enter Base64 ciphertext to decrypt: ")
        plaintext = rsa_cipher.decrypt(ciphertext)
        print("Decrypted plaintext:")
        print(plaintext)

    elif action == 's':
        message = input("Enter message to sign: ")
        signature = rsa_cipher.sign(message)
        print("Signature (Base64):")
        print(signature)

    elif action == 'v':
        message = input("Enter message to verify: ")
        signature = input("Enter signature (Base64): ")
        valid = rsa_cipher.verify(message, signature)
        print("Signature valid:", valid)
    else:
        print("Invalid option, exiting.")
