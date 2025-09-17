import time
import sqlite3
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import os
import re
from collections import deque

# ANSI color codes for terminal output
RED = "\033[91m"
RESET = "\033[0m"

# SQLite database setup
DB_FILE = "anomalies.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log_line TEXT,
            event_count REAL,
            error_rate REAL,
            ip_diversity REAL
        )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"SQLite init error: {e}")
    finally:
        conn.close()

def save_anomaly(timestamp, log_line, event_count, error_rate, ip_diversity):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO anomalies (timestamp, log_line, event_count, error_rate, ip_diversity)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, log_line, event_count, error_rate, ip_diversity))
        conn.commit()
    except sqlite3.Error as e:
        print(f"SQLite insert error: {e}")
    finally:
        conn.close()

# Load trained model and scaler
try:
    model = joblib.load('model.pkl')
    scaler = joblib.load('scaler.pkl')
    print("Model and scaler loaded successfully!")
except FileNotFoundError:
    print("Error: model.pkl or scaler.pkl not found. Train on Colab first.")
    exit(1)

# Parse ZooKeeper log line
def parse_log_line(line):
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
        'log_line': line
    })

def monitor_log(file_path):
    print(f"Monitoring {file_path} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")
    buffer = deque(maxlen=60)  # Rolling buffer for 60 lines (~1 min)
    line_counter = 0

    # Wait for file to exist
    if not os.path.exists(file_path):
        print(f"Waiting for {file_path} to be created...")
        while not os.path.exists(file_path):
            time.sleep(1)

    while True:
        try:
            with open(file_path, 'r') as f:
                f.seek(0, os.SEEK_END)  # Start at end
                pos = f.tell()
                while True:
                    f.seek(pos)
                    line = f.readline()
                    if not line:
                        time.sleep(0.05)  # Fast polling for live server
                        pos = f.tell()
                        continue

                    line = line.strip()
                    if not line:
                        pos = f.tell()
                        continue

                    buffer.append(line)
                    line_counter += 1

                    # Parse and process line
                    parsed = parse_log_line(line)
                    if pd.isna(parsed['timestamp']):
                        print(f"Skipping invalid line: {line}")
                        pos = f.tell()
                        continue

                    # Create DataFrame for rolling features
                    df = pd.DataFrame([parse_log_line(l) for l in buffer])
                    df = df.dropna(subset=['timestamp']).sort_values('timestamp')

                    # Feature engineering
                    df['event_count_per_min'] = df.index.to_series().rolling(window=60, min_periods=1).apply(lambda x: len(x)).values
                    df['error_rate'] = df['level_numeric'].rolling(window=60, min_periods=1).mean()
                    df['ip_diversity'] = df['num_ips_in_line'].rolling(window=60, min_periods=1).std().fillna(0)

                    features = df[['event_count_per_min', 'error_rate', 'ip_diversity']].iloc[[-1]]
                    if features.isnull().any().any():
                        print(f"Analyzing: {line}")
                        print("Skipping due to NaN features")
                        pos = f.tell()
                        continue

                    try:
                        features_scaled = scaler.transform(features)
                        pred = model.predict(features_scaled)[0]
                    except ValueError as e:
                        print(f"Error processing line: {line}")
                        print(f"Scaler error: {e}")
                        pos = f.tell()
                        continue

                    if pred == -1:
                        print(f"{RED}Anomaly detected: {line}{RESET}")
                        print(f"Features: event_count={features['event_count_per_min'].iloc[0]:.2f}, "
                              f"error_rate={features['error_rate'].iloc[0]:.2f}, "
                              f"ip_diversity={features['ip_diversity'].iloc[0]:.2f}")
                        save_anomaly(
                            parsed['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
                            line,
                            features['event_count_per_min'].iloc[0],
                            features['error_rate'].iloc[0],
                            features['ip_diversity'].iloc[0]
                        )
                    else:
                        print(f"Analyzing: {line}")

                    pos = f.tell()

        except (IOError, FileNotFoundError) as e:
            print(f"Error reading {file_path}: {e}")
            print(f"Retrying in 1 second...")
            time.sleep(1)
            continue

# Initialize database
init_db()

# Start monitoring
monitor_log('server.log')