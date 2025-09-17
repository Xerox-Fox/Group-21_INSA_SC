import threading
import time
import logging
from datetime import datetime
from flask import Flask, request
import random

app = Flask(__name__)

# Custom formatter for ZooKeeper log format
class ZooKeeperFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        # Format timestamp as YYYY-MM-DD HH:MM:SS,mmm
        dt = datetime.fromtimestamp(record.created)
        return dt.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

    def format(self, record):
        # Format: YYYY-MM-DD HH:MM:SS,mmm - LEVEL [context] message
        context = "ServerThread" if record.threadName.startswith("Thread") else record.threadName
        return f"{self.formatTime(record)} - {record.levelname} [{context}] {record.getMessage()}"

# Configure logger directly
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Clear any existing handlers to avoid duplicates
logger.handlers.clear()

# Add FileHandler for server.log
file_handler = logging.FileHandler('server.log', mode='a')
file_handler.setFormatter(ZooKeeperFormatter())
logger.addHandler(file_handler)

# Add StreamHandler for console output
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(ZooKeeperFormatter())
logger.addHandler(stream_handler)

# Background thread to log periodic activity
def log_periodic_activity():
    ip_pool = ["10.10.34.11", "10.10.34.12", "10.10.34.13"]  # Simulate IPs
    while True:
        # Randomly choose log type to control error_rate
        severity = random.choices(
            ["normal", "low", "medium"],
            weights=[0.6, 0.2, 0.2],  # 60% normal, 20% low, 20% medium
            k=1
        )[0]
        
        ip = random.choice(ip_pool)
        if severity == "normal":
            # Normal INFO log (error_rate contribution: 0)
            logger.info(f"Processing request from /{ip}:8080")
        elif severity == "low":
            # Low severity WARN (error_rate ≤ 0.3)
            logger.warning(f"Received connection request from /{ip}:8080")
        else:
            # Medium severity WARN (error_rate ≤ 0.7)
            logger.warning(f"Connection broken for id {random.randint(1000, 9999)}, my id = 1, error = Timeout at /{ip}:3888")
        
        time.sleep(0.5)  # Log every 0.5 seconds for frequent activity

# Start the periodic logging thread
periodic_thread = threading.Thread(target=log_periodic_activity, daemon=True)
periodic_thread.start()

@app.route('/status', methods=['GET'])
def status():
    client_ip = random.choice(["10.10.34.11", "10.10.34.12", "10.10.34.13"])
    logger.info(f"HTTP GET /status from /{client_ip}:8080 - Status: OK")
    return {'status': 'OK', 'timestamp': datetime.now().isoformat()}

@app.route('/', methods=['GET'])
def home():
    client_ip = random.choice(["10.10.34.11", "10.10.34.12", "10.10.34.13"])
    logger.warning(f"Access to root from /{client_ip}:8080 - Possible probe?")
    return {'message': 'Server running'}

if __name__ == '__main__':
    print("Server starting on http://localhost:5000. Logs in server.log. Press Ctrl+C to stop.")
    app.run(host='0.0.0.0', port=5000, debug=False)