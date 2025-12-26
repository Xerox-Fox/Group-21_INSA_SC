import hmac, hashlib

class HMACEngine:
    @staticmethod
    def sign(key: bytes, data: bytes) -> bytes:
        return hmac.digest(key, data, hashlib.sha256)

    @staticmethod
    def verify(key: bytes, data: bytes, tag: bytes) -> bool:
        expected = hmac.digest(key, data, hashlib.sha256)
        return hmac.compare_digest(expected, tag)
