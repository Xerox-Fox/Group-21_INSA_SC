from flask import Flask, request, jsonify
from datetime import datetime
import os
import json

app = Flask(__name__)

# Path to log file (can be a filename or path)
HONEYPOT_LOG = "honeypot_logs.txt"

def ensure_log_path(path):
    directory = os.path.dirname(path)
    if directory:  # only create directory if a directory was specified
        os.makedirs(directory, exist_ok=True)

# ensure directory exists (if any)
ensure_log_path(HONEYPOT_LOG)

@app.route("/trap", methods=["POST"])
def trap():
    """
    Receives JSON (or plain text) and appends a timestamped record to the log file.
    """
    try:
        # Prefer JSON if provided, but accept raw body as fallback
        try:
            data = request.get_json(force=True)
        except Exception:
            data = request.get_data(as_text=True)

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Write a compact JSON line to the log file for easy parsing later
        with open(HONEYPOT_LOG, "a", encoding="utf-8") as f:
            record = {"timestamp": timestamp, "remote_addr": request.remote_addr, "data": data}
            f.write(json.dumps(record, default=str) + "\n")

        print(f"[{timestamp}] Trapped data from {request.remote_addr}")
        return jsonify({"status": "received"}), 200

    except Exception as e:
        # don't crash the server on malformed input
        print(f"[!] Honeypot error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

if __name__ == "__main__":
    print(f"Starting honeypot server; logging to: {os.path.abspath(HONEYPOT_LOG)}")
    # bind to localhost by default; change host/port if you want network accessibility
    app.run(host="127.0.0.1", port=8081, debug=False)