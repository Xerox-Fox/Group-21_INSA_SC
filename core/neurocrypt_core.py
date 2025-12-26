from config.secrets import ensure_master_secret
from crypto.key_derivation import KeyDerivation
from crypto.aes_engine import AESEngine
from crypto.hmac_engine import HMACEngine

class NeuroCrypt:
    def __init__(self, context_id: str):
        self.master = ensure_master_secret()
        self.key = KeyDerivation.derive_key(self.master, context_id)
        self.aes = AESEngine(self.key)

    def encrypt_and_sign(self, data: bytes):
        encrypted = self.aes.encrypt(data)
        tag = HMACEngine.sign(self.key, encrypted)
        return encrypted, tag

    def verify_and_decrypt(self, encrypted: bytes, tag: bytes):
        if not HMACEngine.verify(self.key, encrypted, tag):
            raise ValueError("Integrity check failed")
        return self.aes.decrypt(encrypted)
