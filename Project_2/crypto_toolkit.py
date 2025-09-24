from aes_cipher import AESCipher
from rsa_cipher import RSACipher
from sha_hasher import SHAHasher
from Crypto.Random import get_random_bytes

class CryptoToolkit:
    def __init__(self):
        self.sha = SHAHasher()
        self.rsa = RSACipher()
        self.key = get_random_bytes(32)  # 256-bit AES key
        self.aes = AESCipher(self.key)

if __name__ == "__main__":
    print("Unified Crypto Toolkit Demo")
    toolkit = CryptoToolkit()
    print("Options:\n1) AES\n2) RSA\n3) SHA/HMAC/PBKDF2")
    opt = input("Choose option: ")

    if opt == '1':
        pt = input("AES plaintext: ")
        mode = input("AES mode (CBC, OFB, CTR, GCM, EAX): ")
        enc = toolkit.aes.encrypt(pt, mode)
        print("Encrypted:", enc)
        if input("Decrypt now? (y/n): ").lower() == 'y':
            print("Decrypted:", toolkit.aes.decrypt(enc))

    elif opt == '2':
        pt = input("RSA plaintext: ")
        enc = toolkit.rsa.encrypt(pt)
        print("Encrypted:", enc)
        if input("Decrypt now? (y/n): ").lower() == 'y':
            print("Decrypted:", toolkit.rsa.decrypt(enc))
        if input("Sign message? (y/n): ").lower() == 'y':
            sig = toolkit.rsa.sign(pt)
            print("Signature:", sig)
            print("Signature valid:", toolkit.rsa.verify(pt, sig))

    elif opt == '3':
        txt = input("Text for SHA: ")
        algo = input("SHA algorithm (sha1, sha224, sha256, sha384, sha512): ")
        print(toolkit.sha.hash_text(txt, algo))

    else:
        print("Invalid option.")

