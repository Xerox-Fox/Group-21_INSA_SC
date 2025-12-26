import os

class SecureStorage:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def save(self, client_id: str, filename: str, data: bytes):
        path = os.path.join(self.base_dir, f"{client_id}_{filename}")
        with open(path, "wb") as f:
            f.write(data)

    def load(self, client_id: str, filename: str) -> bytes:
        path = os.path.join(self.base_dir, f"{client_id}_{filename}")
        with open(path, "rb") as f:
            return f.read()
