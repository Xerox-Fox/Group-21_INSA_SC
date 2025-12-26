import os
from crypto.hmac_engine import HMACEngine

class ChallengeAuth:
    @staticmethod
    def generate_challenge() -> bytes:
        return os.urandom(32)

    @staticmethod
    def verify_response(key: bytes, challenge: bytes, response: bytes) -> bool:
        return HMACEngine.verify(key, challenge, response)
