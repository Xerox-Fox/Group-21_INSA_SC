import os
import threading
import socket
import time
import hmac
import hashlib
from flask import Flask, jsonify
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import platform
# --- Configuration ---
MAX_CLIENTS = 4
TCP_HOST = "127.0.0.1"
TCP_PORT = 1020
FLASK_PORT = 2210

def ensure_master_secret():
    """Generate MASTER_SECRET if not set and store it safely."""
    master_secret = os.environ.get("MASTER_SECRET")
    if master_secret is None:
        # Generate a strong random 32-byte secret
        master_secret = secrets.token_hex(32)
        os.environ["MASTER_SECRET"] = master_secret
        print(f"[INFO] Generated new MASTER_SECRET for this session: {master_secret}")

        # Save to file
        system = platform.system()
        if system == "Windows":
            path = os.path.join(os.environ["APPDATA"], "master_secret.txt")
        else:
            path = os.path.join(os.path.expanduser("~"), ".master_secret")
        with open(path, "w") as f:
            f.write(master_secret)
        print(f"[INFO] MASTER_SECRET saved to {path} (keep it secret!)")

    # Always return bytes
    if isinstance(master_secret, str):
        return master_secret.encode()
    return master_secret  # already bytes

# --- Master secret (read from env) ---
MASTER_SECRET = ensure_master_secret()  # already bytes
if MASTER_SECRET is None:
    raise RuntimeError("Set MASTER_SECRET environment variable!")
MASTER_SECRET = MASTER_SECRET.encode()

# --- Flask app ---
app = Flask(__name__)

# --- Client tracking ---
approved_clients = {}      # client_id -> True if connected
pending_recycle = {}       # client_id -> timer thread
lock = threading.Lock()

# --- Key derivation ---
def derive_key(client_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=client_id.encode()
    )
    return hkdf.derive(MASTER_SECRET)

# --- Flask endpoint: approve client ---
@app.route("/request_key/<client_id>")
def request_key(client_id):
    with lock:
        if client_id in approved_clients:
            return jsonify({"status": "ok"})
        if len(approved_clients) >= MAX_CLIENTS:
            return jsonify({"status": "full", "message": "Max clients reached"})
        approved_clients[client_id] = True
        return jsonify({"status": "ok"})

# --- Helper: recycle client after 60s if disconnected ---
def recycle_client(client_id):
    time.sleep(60)
    with lock:
        if client_id in pending_recycle:
            print(f"Recycling client slot: {client_id}")
            del pending_recycle[client_id]
            if client_id in approved_clients:
                del approved_clients[client_id]

# --- Helper to receive exact bytes ---
def recv_exact(conn, n):
    b = b""
    while len(b) < n:
        chunk = conn.recv(n - len(b))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        b += chunk
    return b

# --- TCP handler ---
def handle_client(conn, addr):
    try:
        client_id = conn.recv(1024).decode()
        key = derive_key(client_id)
        aesgcm = AESGCM(key)

        # --- Challenge-response ---
        challenge = os.urandom(32)
        conn.sendall(challenge)
        resp = recv_exact(conn, 32)
        expected = hmac.digest(key, challenge, hashlib.sha256)
        if not hmac.compare_digest(resp, expected):
            print(f"[{client_id}] Failed auth attempt")
            conn.close()
            return

        print(f"[{client_id}] Connected from {addr}")

        # Cancel any pending recycle
        with lock:
            if client_id in pending_recycle:
                del pending_recycle[client_id]

        # --- Message loop ---
        while True:
            # Read nonce (12 bytes) + length prefix (4 bytes)
            nonce = recv_exact(conn, 12)
            length_bytes = recv_exact(conn, 4)
            msg_len = int.from_bytes(length_bytes, "big")
            enc_msg = recv_exact(conn, msg_len)

            # Decrypt
            plaintext = aesgcm.decrypt(nonce, enc_msg, None)
            print(f"[{client_id}] Message: {plaintext.decode()}")

            # Reply (new nonce)
            reply_nonce = os.urandom(12)
            reply = aesgcm.encrypt(reply_nonce, b"Server received your message", None)
            conn.sendall(reply_nonce + len(reply).to_bytes(4, "big") + reply)

    except Exception as e:
        print(f"[{client_id}] Error: {e}")
    finally:
        conn.close()
        print(f"[{client_id}] Connection closed.")
        with lock:
            if client_id not in pending_recycle:
                t = threading.Thread(target=recycle_client, args=(client_id,), daemon=True)
                pending_recycle[client_id] = t
                t.start()

# --- TCP server ---
def tcp_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((TCP_HOST, TCP_PORT))
    server_sock.listen(MAX_CLIENTS)
    print(f"TCP server listening on {TCP_HOST}:{TCP_PORT}")

    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# --- Start TCP server in background ---
threading.Thread(target=tcp_server, daemon=True).start()

# --- Start Flask server ---
if __name__ == "__main__":
    print(f"Flask server running on port {FLASK_PORT}")
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=True, use_reloader=False)
