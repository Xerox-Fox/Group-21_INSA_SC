import time
import re
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from datetime import datetime

# ANSI color codes for terminal output
RED = "\033[91m"
RESET = "\033[0m"

# Load trained model and scaler
try:
    model = joblib.load('model.pkl')
    scaler = joblib.load('scaler.pkl')
    print("Model and scaler loaded successfully!")
except FileNotFoundError:
    print("Error: model.pkl or scaler.pkl not found. Train on Colab first.")
    exit(1)

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.buffer = deque(maxlen=60)  # Rolling buffer for 60 lines (~1 min)
        self.last_position = 0
        self.line_counter = 0  # Track lines for event_count_per_min

    def parse_log_line(self, line):
        # Regex for server log format
        ts_match = re.search(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})', line)
        level_match = re.search(r' - (INFO|WARN|ERROR) ', line)
        ip_matches = re.findall(r'/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):', line)
        is_break = 1 if 'Connection broken' in line else 0
        is_received = 1 if 'Received connection request' in line else 0
        level_num = 0 if level_match and level_match.group(1) == 'INFO' else 1
        
        ts = pd.to_datetime(ts_match.group(1)) if ts_match else pd.NaT
        unique_ips = len(set(ip_matches)) if ip_matches else 0
        ip_diversity_proxy = unique_ips / max(1, len(ip_matches)) if ip_matches else 0.0
        
        return pd.Series({
            'timestamp': ts,
            'level_numeric': level_num,
            'is_connection_break': is_break,
            'is_received_connection': is_received,
            'num_ips_in_line': len(ip_matches),
            'ip_diversity': ip_diversity_proxy,
            'log_line': line  # Store original line
        })

    def on_modified(self, event):
        if event.src_path.endswith('server.log'):  # Watch server.log
            try:
                with open(event.src_path, 'r') as f:
                    f.seek(self.last_position)
                    new_lines = f.readlines()
                    self.last_position = f.tell()
                    
                    for line in new_lines:
                        line = line.strip()
                        if line:  # Skip empty
                            self.buffer.append(line)
                            self.line_counter += 1
                            self.process_line(line)
            except (IOError, FileNotFoundError) as e:
                print(f"Error reading server.log: {e}")
                time.sleep(1)  # Wait briefly before retrying

    def process_line(self, line):
        # Parse single line
        parsed = self.parse_log_line(line)
        if pd.isna(parsed['timestamp']):
            print(f"Skipping invalid line: {line}")
            return

        # Create DataFrame with buffer for rolling features
        df = pd.DataFrame([self.parse_log_line(l) for l in self.buffer])
        df = df.dropna(subset=['timestamp']).sort_values('timestamp')

        # Feature engineering (matches training)
        df['event_count_per_min'] = df.index.to_series().rolling(window=60, min_periods=1).apply(lambda x: len(x)).values
        df['error_rate'] = df['level_numeric'].rolling(window=60, min_periods=1).mean()
        df['ip_diversity'] = df['num_ips_in_line'].rolling(window=60, min_periods=1).std().fillna(0)

        # Use features for the latest line
        features = df[['event_count_per_min', 'error_rate', 'ip_diversity']].iloc[[-1]]
        if features.isnull().any().any():
            print(f"Analyzing: {line}")
            print("Skipping due to NaN features")
            return

        # Scale and predict
        try:
            features_scaled = scaler.transform(features)
            pred = model.predict(features_scaled)[0]
        except ValueError as e:
            print(f"Error processing line: {line}")
            print(f"Scaler error: {e}")
            return

        # Print every line, highlight anomalies in red
        if pred == -1:
            print(f"{RED}Anomaly detected: {line}{RESET}")
            print(f"Features: event_count={features['event_count_per_min'].iloc[0]:.2f}, "
                  f"error_rate={features['error_rate'].iloc[0]:.2f}, "
                  f"ip_diversity={features['ip_diversity'].iloc[0]:.2f}")
        else:
            print(f"Analyzing: {line}")

# Start monitoring
event_handler = LogHandler()
observer = Observer()
observer.schedule(event_handler, path='.', recursive=False)  # Watch current dir for server.log
observer.start()
print("Live monitor started. Watching server.log. Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
