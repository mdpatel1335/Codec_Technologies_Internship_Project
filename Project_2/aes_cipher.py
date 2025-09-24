"""
AES (Advanced Encryption Standard) Implementation with user input
Supports AES-128, AES-192, AES-256 in CBC, OFB, CTR, GCM, and EAX modes.
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class AESCipher:
    def __init__(self, key: bytes):
        """Initialize AES cipher with a key (16, 24, or 32 bytes)."""
        self.key = key

    def encrypt(self, plaintext: str, mode: str = 'CBC') -> dict:
        """
        Encrypt plaintext using AES.
        Returns dict with mode, iv/nonce, ciphertext (base64), original.
        """
        data = plaintext.encode('utf-8')
        mode = mode.upper()
        if mode == 'CBC':
            cipher = AES.new(self.key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            result = {
                'mode': 'CBC',
                'iv': base64.b64encode(cipher.iv).decode('utf-8'),
                'ciphertext': base64.b64encode(ct_bytes).decode('utf-8'),
                'input': plaintext
            }
        elif mode == 'OFB':
            cipher = AES.new(self.key, AES.MODE_OFB)
            ct_bytes = cipher.encrypt(data)
            result = {
                'mode': 'OFB',
                'iv': base64.b64encode(cipher.iv).decode('utf-8'),
                'ciphertext': base64.b64encode(ct_bytes).decode('utf-8'),
                'input': plaintext
            }
        elif mode == 'CTR':
            cipher = AES.new(self.key, AES.MODE_CTR)
            ct_bytes = cipher.encrypt(data)
            result = {
                'mode': 'CTR',
                'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ct_bytes).decode('utf-8'),
                'input': plaintext
            }
        elif mode == 'GCM':
            cipher = AES.new(self.key, AES.MODE_GCM)
            ct_bytes, tag = cipher.encrypt_and_digest(data)
            result = {
                'mode': 'GCM',
                'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'ciphertext': base64.b64encode(ct_bytes).decode('utf-8'),
                'input': plaintext
            }
        elif mode == 'EAX':
            cipher = AES.new(self.key, AES.MODE_EAX)
            ct_bytes, tag = cipher.encrypt_and_digest(data)
            result = {
                'mode': 'EAX',
                'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'ciphertext': base64.b64encode(ct_bytes).decode('utf-8'),
                'input': plaintext
            }
        else:
            raise ValueError("Unsupported AES mode.")
        return result

    def decrypt(self, enc_dict: dict) -> str:
        """
        Decrypt ciphertext dict (from encrypt()). Returns plaintext str.
        """
        mode = enc_dict['mode'].upper()
        ct = base64.b64decode(enc_dict['ciphertext'])
        if mode == 'CBC':
            iv = base64.b64decode(enc_dict['iv'])
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
        elif mode == 'OFB':
            iv = base64.b64decode(enc_dict['iv'])
            cipher = AES.new(self.key, AES.MODE_OFB, iv)
            pt = cipher.decrypt(ct)
        elif mode == 'CTR':
            nonce = base64.b64decode(enc_dict['nonce'])
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            pt = cipher.decrypt(ct)
        elif mode in {'GCM', 'EAX'}:
            nonce = base64.b64decode(enc_dict['nonce'])
            tag = base64.b64decode(enc_dict['tag'])
            cipher = AES.new(self.key, AES.MODE_GCM if mode == 'GCM' else AES.MODE_EAX, nonce=nonce)
            pt = cipher.decrypt_and_verify(ct, tag)
        else:
            raise ValueError("Unsupported AES mode.")
        return pt.decode('utf-8')


if __name__ == "__main__":
    print("AES Interactive Demo")
    key_len = int(input("Enter AES key length (16, 24, 32): "))
    key = get_random_bytes(key_len)
    aes_cipher = AESCipher(key)
    mode = input("Enter AES mode (CBC, OFB, CTR, GCM, EAX): ").upper()
    action = input("Encrypt (e) or Decrypt (d)? ").lower()

    if action == 'e':
        plaintext = input("Enter plaintext to encrypt: ")
        encrypted = aes_cipher.encrypt(plaintext, mode)
        print("Encrypted data:")
        print(encrypted)
    elif action == 'd':
        enc = {}
        enc['mode'] = mode
        enc['ciphertext'] = input("Enter Base64 ciphertext: ")
        if mode in ['CBC', 'OFB']:
            enc['iv'] = input("Enter Base64 IV: ")
        if mode in ['CTR', 'GCM', 'EAX']:
            enc['nonce'] = input("Enter Base64 nonce: ")
        if mode in ['GCM', 'EAX']:
            enc['tag'] = input("Enter Base64 tag: ")
        plaintext = aes_cipher.decrypt(enc)
        print("Decrypted plaintext:")
        print(plaintext)
    else:
        print("Invalid input, exiting.")
