from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class SymmetricCrypto:
    KEY_SIZE = 32  # 256 bits for AES
    ITERATION_COUNT = 10000

    def generate_key(self, password: str):
        # Derive key from password
        salt = b''  # Empty salt as in the Java example
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATION_COUNT,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return AES(key)

    def encrypt(self, data: bytes, key: AES):
        # Encrypt data
        cipher = Cipher(key, ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, data: bytes, key: AES):
        # Decrypt data
        cipher = Cipher(key, ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_data = decryptor.update(data) + decryptor.finalize()
        return unpadder.update(padded_data) + unpadder.finalize()
