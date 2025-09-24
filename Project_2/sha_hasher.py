"""
Advanced SHAHasher Module with:
- Hash identification from hash string
- Hash decoding (hex/base64 to bytes)
- Salt utilities
- Comprehensive SHA, HMAC, PBKDF2 password hashing
"""
import hashlib
import hmac
import base64
import os
import re

class SHAHasher:
    def __init__(self):
        self.algorithms = {
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
        # Hash lengths in bytes keyed by algorithm
        self.hash_lengths = {
            'sha1': 20,
            'sha224': 28,
            'sha256': 32,
            'sha384': 48,
            'sha512': 64
        }

    def hash_text(self, text: str, algorithm: str = "sha256") -> dict:
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported SHA algorithm '{algorithm}'")
        data = text.encode()
        hash_obj = self.algorithms[algorithm]()
        hash_obj.update(data)
        digest_bytes = hash_obj.digest()
        return {
            "algorithm": algorithm.upper(),
            "input": text,
            "hex": hash_obj.hexdigest(),
            "base64": base64.b64encode(digest_bytes).decode(),
            "length": len(digest_bytes) * 8,
        }

    def hash_file(self, filepath: str, algorithm: str = "sha256") -> dict:
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported SHA algorithm '{algorithm}'")
        hash_obj = self.algorithms[algorithm]()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        digest_bytes = hash_obj.digest()
        return {
            "algorithm": algorithm.upper(),
            "file_path": filepath,
            "file_size": os.path.getsize(filepath),
            "hex": hash_obj.hexdigest(),
            "base64": base64.b64encode(digest_bytes).decode(),
        }

    def hmac_hash(self, message: str, key: str, algorithm: str = "sha256") -> dict:
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported SHA algorithm '{algorithm}'")
        key_bytes = key.encode()
        msg_bytes = message.encode()
        hmac_obj = hmac.new(key_bytes, msg_bytes, self.algorithms[algorithm])
        digest_bytes = hmac_obj.digest()
        return {
            "algorithm": f"HMAC-{algorithm.upper()}",
            "message": message,
            "hex": hmac_obj.hexdigest(),
            "base64": base64.b64encode(digest_bytes).decode(),
        }

    def verify_hmac(self, message: str, key: str, expected_hmac: str, algorithm: str = "sha256") -> bool:
        computed = self.hmac_hash(message, key, algorithm)
        return hmac.compare_digest(computed["hex"], expected_hmac)

    def hash_password(self, password: str, salt: str = None, algorithm: str = "sha256", iterations: int = 100000) -> dict:
        if salt is None:
            salt_bytes = os.urandom(32)
            salt_b64 = base64.b64encode(salt_bytes).decode()
        else:
            # Accept base64 or raw bytes passed as str or bytes
            if isinstance(salt, str):
                # Detect if salt is base64
                if self._is_base64(salt):
                    salt_bytes = base64.b64decode(salt)
                    salt_b64 = salt
                else:
                    salt_bytes = salt.encode()
                    salt_b64 = base64.b64encode(salt_bytes).decode()
            elif isinstance(salt, bytes):
                salt_bytes = salt
                salt_b64 = base64.b64encode(salt_bytes).decode()
            else:
                raise ValueError("Salt must be None, str, or bytes")

        dk = hashlib.pbkdf2_hmac(algorithm, password.encode(), salt_bytes, iterations)
        return {
            "algorithm": f"PBKDF2-{algorithm.upper()}",
            "iterations": iterations,
            "salt": salt_b64,
            "hash": base64.b64encode(dk).decode(),
        }

    def verify_password(self, password: str, stored_hash: dict) -> bool:
        alg = stored_hash.get("algorithm", "").replace("PBKDF2-", "").lower()
        salt = stored_hash.get("salt")
        iterations = stored_hash.get("iterations", 100000)
        hash_b64 = stored_hash.get("hash")

        if not alg or not salt or not hash_b64:
            raise ValueError("Invalid stored hash dictionary")

        computed = self.hash_password(password, salt, alg, iterations)
        return hmac.compare_digest(computed["hash"], hash_b64)

    def identify_hash(self, hash_str: str) -> str:
        """
        Identify likely hash algorithm based on length and format of hex or base64 string.
        Returns algorithm name or 'unknown'.
        """
        hash_bytes = None
        hash_format = None

        # Normalize
        h = hash_str.strip().lower()
        if self._is_hex(h):
            hash_bytes = bytes.fromhex(h)
            hash_format = "hex"
        elif self._is_base64(h):
            try:
                hash_bytes = base64.b64decode(h)
                hash_format = "base64"
            except Exception:
                pass
        if hash_bytes is None:
            return "unknown"

        length = len(hash_bytes)

        for alg, size in self.hash_lengths.items():
            if size == length:
                return alg.upper()

        return "unknown"

    def decode_hash(self, hash_str: str) -> bytes:
        """
        Decode hash string (hex or base64) to bytes, raises if invalid.
        """
        h = hash_str.strip()
        if self._is_hex(h):
            return bytes.fromhex(h)
        elif self._is_base64(h):
            return base64.b64decode(h)
        else:
            raise ValueError("Input is not valid hex or base64")

    def _is_hex(self, s: str) -> bool:
        return bool(re.fullmatch(r'[0-9a-fA-F]+', s)) and (len(s) % 2 == 0)

    def _is_base64(self, s: str) -> bool:
        try:
            return base64.b64encode(base64.b64decode(s)) == s.encode()
        except Exception:
            return False


# Interactive demo with advanced options
if __name__ == "__main__":
    sh = SHAHasher()
    print("SHA Advanced Hasher")
    print("Options:")
    print("1) Hash text")
    print("2) Hash file")
    print("3) HMAC")
    print("4) Password hash")
    print("5) Verify password")
    print("6) Identify hash algorithm")
    print("7) Decode hash string (hex/base64)")

    choice = input("Choose an option (1-7): ").strip()
    if choice == "1":
        txt = input("Input text: ")
        alg = input("Algorithm (sha1, sha224, sha256, sha384, sha512): ").strip().lower()
        print(sh.hash_text(txt, alg))
    elif choice == "2":
        path = input("Path to file: ")
        alg = input("Algorithm: ").strip().lower()
        print(sh.hash_file(path, alg))
    elif choice == "3":
        msg = input("Message: ")
        key = input("Key: ")
        alg = input("Algorithm: ").strip().lower()
        print(sh.hmac_hash(msg, key, alg))
    elif choice == "4":
        pwd = input("Password: ")
        salt_in = input("Salt (leave blank to generate random): ").strip() or None
        iterations = input("Iterations (default 100000): ").strip()
        iterations = int(iterations) if iterations.isnumeric() else 100000
        alg = input("Algorithm: ").strip().lower()
        print(sh.hash_password(pwd, salt_in, alg, iterations))
    elif choice == "5":
        pwd = input("Password to verify: ")
        alg = input("Stored hash algorithm (PBKDF2-SHAxxx): ").strip()
        salt = input("Stored salt: ").strip()
        iterations = int(input("Stored iterations: ").strip())
        hsh = input("Stored hash (base64): ").strip()
        stored = {"algorithm": alg, "salt": salt, "iterations": iterations, "hash": hsh}
        print("Password match:", sh.verify_password(pwd, stored))
    elif choice == "6":
        hsh = input("Enter hash string (hex/base64): ").strip()
        print("Identified algorithm:", sh.identify_hash(hsh))
    elif choice == "7":
        hsh = input("Enter hash string (hex/base64): ").strip()
        try:
            decoded = sh.decode_hash(hsh)
            print("Decoded bytes:", decoded)
        except ValueError as e:
            print("Error decoding:", e)
    else:
        print("Invalid choice, exiting.")
