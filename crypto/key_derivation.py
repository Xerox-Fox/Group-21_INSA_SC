from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class KeyDerivation:
    @staticmethod
    def derive_key(master_secret: bytes, context: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context.encode()
        )
        return hkdf.derive(master_secret)
