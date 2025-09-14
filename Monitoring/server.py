import threading
import time
import logging
from datetime import datetime
from flask import Flask, request

app = Flask(__name__)

# Configure logging to file (append mode)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('server.log', mode='a'),  # Append to server.log
        logging.StreamHandler()  # Also print to console
    ]
)
logger = logging.getLogger(__name__)

# Background thread to log every second (simulate ongoing activity)
def log_periodic_activity():
    while True:
        time.sleep(1)  # Every second
        fake_event = f"Simulated activity: {datetime.now().strftime('%H:%M:%S')} - User {threading.current_thread().name} processed resource X"
        logger.info(fake_event)

# Start the periodic logging thread
periodic_thread = threading.Thread(target=log_periodic_activity, daemon=True)
periodic_thread.start()

@app.route('/status', methods=['GET'])
def status():
    client_ip = request.remote_addr
    logger.info(f"HTTP GET /status from IP: {client_ip} - Status: OK")
    return {'status': 'OK', 'timestamp': datetime.now().isoformat()}

@app.route('/', methods=['GET'])
def home():
    logger.warning(f"Access to root from {request.remote_addr} - Possible probe?")
    return {'message': 'Server running'}

if __name__ == '__main__':
    print("Server starting on http://localhost:5000. Logs in server.log. Press Ctrl+C to stop.")
    app.run(host='0.0.0.0', port=5000, debug=False)