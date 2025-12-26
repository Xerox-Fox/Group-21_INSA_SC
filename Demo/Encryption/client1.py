import os
import requests
import tempfile
import subprocess
import sys
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Changed to HKDF
import secrets
import platform
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import threading

# --- Config ---
CLIENT_ID = "client1"
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 2210
TCP_HOST = "127.0.0.1"
TCP_PORT = 1020
BASE_URL = f"http://{FLASK_HOST}:{FLASK_PORT}"

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

# Derive AES key with HKDF (aligned with server)
def derive_key(master_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=CLIENT_ID.encode())
    return hkdf.derive(master_secret)

key = derive_key(MASTER_SECRET)
aesgcm = AESGCM(key)

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted File Storage Client")
        self.root.geometry("500x400")
        self.connected = False
        self.chat_socket = None

        # Status Label
        self.status_var = tk.StringVar(value="Not connected")
        tk.Label(root, textvariable=self.status_var, fg="red").pack(pady=5)

        # Connect Button
        tk.Button(root, text="Connect to Server", command=self.connect).pack(pady=5)

        # File Upload Section
        tk.Label(root, text="Upload File:").pack()
        tk.Button(root, text="Select File", command=self.upload_file).pack()

        # File Download Section
        tk.Label(root, text="Download File:").pack()
        self.filename_entry = tk.Entry(root)
        self.filename_entry.pack()
        tk.Label(root, text="Editor Command (e.g., 'gedit'):").pack()
        self.editor_entry = tk.Entry(root)
        self.editor_entry.pack()
        tk.Button(root, text="Download and Edit", command=self.download_file).pack(pady=5)

        # Chat Section
        tk.Label(root, text="Chat with Server:").pack()
        self.chat_entry = tk.Entry(root)
        self.chat_entry.pack()
        tk.Button(root, text="Send Message", command=self.send_chat).pack()
        self.chat_log = tk.Text(root, height=5, state='disabled')
        self.chat_log.pack(fill=tk.X, padx=10, pady=5)

    def log(self, message):
        self.chat_log.configure(state='normal')
        self.chat_log.insert(tk.END, f"{message}\n")
        self.chat_log.configure(state='disabled')
        self.chat_log.yview(tk.END)

    def connect(self):
        try:
            self.log("Attempting HTTP request to /request_key...")
            r = requests.get(f"{BASE_URL}/request_key/{CLIENT_ID}", timeout=5)
            self.log(f"HTTP response: {r.status_code}, {r.text}")
            data = r.json()
            if data["status"] == "ok":
                self.connected = True
                self.status_var.set("Connected to server")
                self.root.children['!label'].config(fg="green")
                self.log("Connected to server")
                self.chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    self.log(f"Connecting to TCP {TCP_HOST}:{TCP_PORT}...")
                    self.chat_socket.connect((TCP_HOST, TCP_PORT))
                    self.log("Sending client ID...")
                    self.chat_socket.sendall(CLIENT_ID.encode())
                    self.log("Receiving challenge...")
                    challenge = self.chat_socket.recv(32)
                    self.log(f"Challenge received: {len(challenge)} bytes")
                    resp = hmac.digest(key, challenge, hashlib.sha256)
                    self.log("Sending HMAC response...")
                    self.chat_socket.sendall(resp)
                    self.log("Starting chat receiver...")
                    threading.Thread(target=self.receive_chat, daemon=True).start()
                except Exception as e:
                    self.log(f"TCP connection failed: {e}")
                    raise
            else:
                self.status_var.set(f"Connection failed: {data.get('message', 'Unknown error')}")
                messagebox.showerror("Error", f"Connection failed: {data.get('message')}")
        except Exception as e:
            self.status_var.set(f"Connection error: {e}")
            self.log(f"Connection error: {e}")
            messagebox.showerror("Error", f"Connection error: {e}")

    def encrypt_file(self, file_path: str, nonce: bytes = None) -> tuple[bytes, bytes]:
        with open(file_path, "rb") as f:
            plaintext = f.read()
        nonce = nonce or os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        hmac_tag = hmac.digest(key, nonce + ciphertext, hashlib.sha256)
        return nonce + ciphertext, hmac_tag

    def decrypt_file(self, encrypted_data: bytes, hmac_tag: bytes, temp_path: str):
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        expected_hmac = hmac.digest(key, nonce + ciphertext, hashlib.sha256)
        if not hmac.compare_digest(hmac_tag, expected_hmac):
            raise ValueError("Integrity check failed")
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        with open(temp_path, "wb") as f:
            f.write(plaintext)

    def upload_file(self):
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            encrypted_data, hmac_tag = self.encrypt_file(file_path)
            filename = os.path.basename(file_path)
            files = {"file": (filename, encrypted_data, "application/octet-stream")}
            headers = {"X-Client-ID": CLIENT_ID, "X-HMAC": hmac_tag.hex()}
            self.status_var.set(f"Uploading {filename}...")
            r = requests.post(f"{BASE_URL}/upload", files=files, headers=headers)
            if r.json()["status"] == "ok":
                self.status_var.set(f"Uploaded {filename}")
                self.log(f"Uploaded {filename}")
            else:
                self.status_var.set(f"Upload failed: {r.json()}")
                messagebox.showerror("Error", f"Upload failed: {r.json()}")
        except Exception as e:
            self.status_var.set(f"Upload error: {e}")
            messagebox.showerror("Error", f"Upload error: {e}")

    def download_file(self):
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
        filename = self.filename_entry.get().strip()
        editor_cmd = self.editor_entry.get().strip()
        if not filename:
            messagebox.showerror("Error", "Enter a filename")
            return
        try:
            headers = {"X-Client-ID": CLIENT_ID}
            self.status_var.set(f"Downloading {filename}...")
            r = requests.get(f"{BASE_URL}/download/{filename}", headers=headers)
            if r.status_code != 200:
                self.status_var.set(f"Download failed: {r.text}")
                messagebox.showerror("Error", f"Download failed: {r.text}")
                return
            encrypted_data = r.content
            hmac_tag = bytes.fromhex(r.headers.get("X-HMAC", ""))
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as temp:
                temp_path = temp.name
                self.decrypt_file(encrypted_data, hmac_tag, temp_path)
                self.status_var.set(f"Decrypted to temp: {temp_path}")
                self.log(f"Decrypted to temp: {temp_path}")
            if editor_cmd:
                subprocess.run([editor_cmd, temp_path])
                self.log("Edit complete. Re-encrypting...")
            else:
                self.log("File ready for manual edit. Delete when done.")
            self.upload_file_after_edit(temp_path, filename)
            os.unlink(temp_path)
            self.status_var.set("Download and re-upload complete")
        except Exception as e:
            self.status_var.set(f"Download error: {e}")
            messagebox.showerror("Error", f"Download error: {e}")

    def upload_file_after_edit(self, temp_path, filename):
        encrypted_data, hmac_tag = self.encrypt_file(temp_path)
        files = {"file": (filename, encrypted_data, "application/octet-stream")}
        headers = {"X-Client-ID": CLIENT_ID, "X-HMAC": hmac_tag.hex()}
        r = requests.post(f"{BASE_URL}/upload", files=files, headers=headers)
        if r.json()["status"] == "ok":
            self.log(f"Re-uploaded {filename}")
        else:
            self.log(f"Re-upload failed: {r.json()}")
            messagebox.showerror("Error", f"Re-upload failed: {r.json()}")

    def send_chat(self):
        if not self.connected or not self.chat_socket:
            messagebox.showerror("Error", "Not connected to chat server")
            return
        message = self.chat_entry.get().strip()
        if not message:
            return
        try:
            message = message.encode()
            nonce = os.urandom(12)
            enc_msg = aesgcm.encrypt(nonce, message, None)
            self.chat_socket.sendall(nonce + len(enc_msg).to_bytes(4, "big") + enc_msg)
            self.log(f"Sent: {message.decode()}")
            self.chat_entry.delete(0, tk.END)
        except Exception as e:
            self.log(f"Chat error: {e}")
            messagebox.showerror("Error", f"Chat error: {e}")

    def receive_chat(self):
        while self.connected and self.chat_socket:
            try:
                reply_nonce = self.chat_socket.recv(12)
                if not reply_nonce:
                    break
                reply_len = int.from_bytes(self.chat_socket.recv(4), "big")
                enc_reply = self.chat_socket.recv(reply_len)
                reply = aesgcm.decrypt(reply_nonce, enc_reply, None)
                self.log(f"Server: {reply.decode()}")
            except Exception as e:
                self.log(f"Chat receive error: {e}")
                self.connected = False
                self.status_var.set("Disconnected from server")
                self.root.children['!label'].config(fg="red")
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()