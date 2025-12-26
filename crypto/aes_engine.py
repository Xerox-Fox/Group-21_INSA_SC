import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESEngine:
    def __init__(self, key: bytes):
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, encrypted: bytes) -> bytes:
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)
