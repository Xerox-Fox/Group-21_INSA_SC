import os
import threading
import socket
import time
import hmac
import hashlib
from flask import Flask, jsonify, request, Response
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import platform
from werkzeug.utils import secure_filename
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime

# --- Configuration ---
MAX_CLIENTS = 4
TCP_HOST = "127.0.0.1"
TCP_PORT = 1020
FLASK_PORT = 2210
STORAGE_DIR = "./encrypted_storage"
os.makedirs(STORAGE_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'jpg', 'png', 'mp4', 'docx'}

def ensure_master_secret():
    master_secret = os.environ.get("MASTER_SECRET")
    if master_secret is None:
        system = platform.system()
        if system == "Windows":
            path = os.path.join(os.environ["APPDATA"], "master_secret.txt")
        else:
            path = os.path.join(os.path.expanduser("~"), ".master_secret")
        try:
            with open(path, "r") as f:
                master_secret = f.read().strip()
                print(f"[INFO] Loaded MASTER_SECRET from {path}")
        except FileNotFoundError:
            master_secret = secrets.token_hex(32)
            os.environ["MASTER_SECRET"] = master_secret
            with open(path, "w") as f:
                f.write(master_secret)
            print(f"[INFO] Generated and saved MASTER_SECRET to {path}")
    if isinstance(master_secret, str):
        return master_secret.encode()
    return master_secret

MASTER_SECRET = ensure_master_secret()
if MASTER_SECRET is None:
    raise RuntimeError("Failed to set MASTER_SECRET")

app = Flask(__name__)
approved_clients = {}
pending_recycle = {}
lock = threading.Lock()

# GUI Setup
class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted File Storage Server")
        self.root.geometry("600x400")

        tk.Label(root, text="Connected Clients:").pack(pady=5)
        self.client_listbox = tk.Listbox(root, height=5)
        self.client_listbox.pack(fill=tk.X, padx=10)

        tk.Label(root, text="Server Logs:").pack(pady=5)
        self.log_area = scrolledtext.ScrolledText(root, height=15, state='disabled')
        self.log_area.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Assign app.gui before starting servers
        app.gui = self
        self.log("Server GUI initialized")
        self.update_clients()
        threading.Thread(target=self.start_servers, daemon=True).start()

    def log(self, message):
        self.log_area.configure(state='normal')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.configure(state='disabled')
        self.log_area.yview(tk.END)

    def update_clients(self):
        self.client_listbox.delete(0, tk.END)
        with lock:
            for client_id in approved_clients:
                status = "Connected" if client_id in approved_clients else "Pending Recycle"
                self.client_listbox.insert(tk.END, f"{client_id}: {status}")
        self.root.after(1000, self.update_clients)

    def start_servers(self):
        try:
            self.log("Starting TCP server...")
            threading.Thread(target=tcp_server, daemon=True).start()
            self.log("Starting Flask server...")
            app.run(host="0.0.0.0", port=FLASK_PORT, debug=True, use_reloader=False)
        except Exception as e:
            self.log(f"Server startup failed: {e}")
            raise

def derive_key(client_id: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=client_id.encode())
    return hkdf.derive(MASTER_SECRET)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/request_key/<client_id>")
def request_key(client_id):
    with lock:
        if client_id in approved_clients:
            app.gui.log(f"Client {client_id} re-approved")
            return jsonify({"status": "ok"})
        if len(approved_clients) >= MAX_CLIENTS:
            app.gui.log(f"Client {client_id} rejected: Max clients reached")
            return jsonify({"status": "full", "message": "Max clients reached"})
        approved_clients[client_id] = True
        app.gui.log(f"Client {client_id} approved")
        return jsonify({"status": "ok"})

@app.route("/upload", methods=["POST"])
def upload_file():
    client_id = request.headers.get("X-Client-ID")
    if not client_id or client_id not in approved_clients:
        app.gui.log(f"Unauthorized upload attempt by {client_id}")
        return jsonify({"error": "Unauthorized"}), 401
    if "file" not in request.files:
        app.gui.log("Upload failed: No file provided")
        return jsonify({"error": "No file"}), 400
    file = request.files["file"]
    if file.filename == "":
        app.gui.log("Upload failed: No file selected")
        return jsonify({"error": "No file selected"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(STORAGE_DIR, f"{client_id}_{filename}")
        try:
            file.save(filepath)
            app.gui.log(f"Uploaded {client_id}_{filename} to local storage")
            return jsonify({"status": "ok", "filename": filename})
        except Exception as e:
            app.gui.log(f"Upload error for {client_id}_{filename}: {e}")
            return jsonify({"error": "Upload failed"}), 500
    app.gui.log(f"Invalid file type: {file.filename}")
    return jsonify({"error": "Invalid file"}), 400

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    client_id = request.headers.get("X-Client-ID")
    if not client_id or client_id not in approved_clients:
        app.gui.log(f"Unauthorized download attempt by {client_id}")
        return jsonify({"error": "Unauthorized"}), 401
    filepath = os.path.join(STORAGE_DIR, f"{client_id}_{filename}")
    if os.path.exists(filepath):
        app.gui.log(f"Downloaded {client_id}_{filename} for {client_id}")
        return Response(
            open(filepath, 'rb'),
            mimetype='application/octet-stream',
            headers={"Content-Disposition": f"attachment;filename={filename}"}
        )
    app.gui.log(f"File {client_id}_{filename} not found")
    return jsonify({"error": "File not found"}), 404

def recycle_client(client_id):
    time.sleep(60)
    with lock:
        if client_id in pending_recycle:
            print(f"Recycling client slot: {client_id}")
            app.gui.log(f"Recycled client slot: {client_id}")
            del pending_recycle[client_id]
            if client_id in approved_clients:
                del approved_clients[client_id]

def recv_exact(conn, n):
    b = b""
    while len(b) < n:
        chunk = conn.recv(n - len(b))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        b += chunk
    return b

def handle_client(conn, addr):
    try:
        client_id = conn.recv(1024).decode()
        key = derive_key(client_id)
        aesgcm = AESGCM(key)
        challenge = os.urandom(32)
        conn.sendall(challenge)
        resp = recv_exact(conn, 32)
        expected = hmac.digest(key, challenge, hashlib.sha256)
        if not hmac.compare_digest(resp, expected):
            print(f"[{client_id}] Failed auth attempt")
            app.gui.log(f"[{client_id}] Failed auth attempt")
            conn.close()
            return
        print(f"[{client_id}] Connected from {addr}")
        app.gui.log(f"[{client_id}] Connected from {addr}")
        with lock:
            if client_id in pending_recycle:
                del pending_recycle[client_id]
        while True:
            nonce = recv_exact(conn, 12)
            length_bytes = recv_exact(conn, 4)
            msg_len = int.from_bytes(length_bytes, "big")
            enc_msg = recv_exact(conn, msg_len)
            plaintext = aesgcm.decrypt(nonce, enc_msg, None)
            print(f"[{client_id}] Message: {plaintext.decode()}")
            app.gui.log(f"[{client_id}] Message: {plaintext.decode()}")
            reply_nonce = os.urandom(12)
            reply = aesgcm.encrypt(reply_nonce, b"Server received your message", None)
            conn.sendall(reply_nonce + len(reply).to_bytes(4, "big") + reply)
    except Exception as e:
        print(f"[{client_id}] Error: {e}")
        app.gui.log(f"[{client_id}] Error: {e}")
    finally:
        conn.close()
        print(f"[{client_id}] Connection closed.")
        app.gui.log(f"[{client_id}] Connection closed.")
        with lock:
            if client_id not in pending_recycle:
                t = threading.Thread(target=recycle_client, args=(client_id,), daemon=True)
                pending_recycle[client_id] = t
                t.start()

def tcp_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((TCP_HOST, TCP_PORT))
        server_sock.listen(MAX_CLIENTS)
        print(f"TCP server listening on {TCP_HOST}:{TCP_PORT}")
        app.gui.log(f"TCP server listening on {TCP_HOST}:{TCP_PORT}")
    except Exception as e:
        print(f"TCP server bind failed: {e}")
        app.gui.log(f"TCP server bind failed: {e}")
        raise
    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app.gui = ServerGUI(root)  # Ensure app.gui is set before any threads start
    root.mainloop()