# Save as monitor_with_honeypot.py
import time
import sqlite3
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import os, re, yara, requests, yaml
from collections import deque

# === CONFIG ===
HONEYPOT_URL = "http://127.0.0.1:8081/trap"
YARA_RULES_DIR = "./rules/yara"
SIGMA_RULES_DIR = "./rules/sigma"
DB_FILE = "anomalies.db"

RED = "\033[91m"
RESET = "\033[0m"

# === Helper: verbose print ===
def vprint(tag, msg, data=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{tag}] {msg}"
    print(line)
    if data is not None:
        print("    >>> DATA:", repr(data)[:1000])

# === SQLite setup ===
def init_db():
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
    conn.close()

def save_anomaly(ts, line, event_count, error_rate, ip_div):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""INSERT INTO anomalies (timestamp, log_line, event_count, error_rate, ip_diversity)
                   VALUES (?, ?, ?, ?, ?)""", (ts, line, event_count, error_rate, ip_div))
    conn.commit()
    conn.close()
    vprint("DB", "Anomaly saved", {"timestamp": ts, "line": line[:100]})

# === Load ML Model ===
try:
    model = joblib.load('model.pkl')
    scaler = joblib.load('scaler.pkl')
    vprint("ML", "Model and scaler loaded successfully!")
except FileNotFoundError:
    vprint("ML_ERR", "model.pkl or scaler.pkl not found. Exiting.")
    exit(1)

# === Load YARA Rules ===
def load_yara_rules():
    rules = {}
    if not os.path.exists(YARA_RULES_DIR):
        vprint("YARA", "No YARA rules directory found.")
        return None
    for file in os.listdir(YARA_RULES_DIR):
        if file.endswith(".yar"):
            path = os.path.join(YARA_RULES_DIR, file)
            try:
                rules[file] = yara.compile(filepath=path)
                vprint("YARA", f"Loaded YARA rule {file}")
            except Exception as e:
                vprint("YARA_ERR", f"Error loading {file}: {e}")
    return rules

# === Load Sigma Rules via PyYAML (keywords) ===
def load_sigma_rules():
    rules = []
    if not os.path.exists(SIGMA_RULES_DIR):
        vprint("SIGMA", "No Sigma rules directory found.")
        return rules
    for file in os.listdir(SIGMA_RULES_DIR):
        if file.endswith(".yml") or file.endswith(".yaml"):
            path = os.path.join(SIGMA_RULES_DIR, file)
            try:
                with open(path, 'r') as f:
                    doc = yaml.safe_load(f)
                    if "detection" in doc:
                        for key, value in doc["detection"].items():
                            if isinstance(value, dict):
                                for subval in value.values():
                                    if isinstance(subval, str):
                                        rules.append(subval)
                                    elif isinstance(subval, list):
                                        rules.extend([str(v) for v in subval])
                            elif isinstance(value, list):
                                rules.extend([str(v) for v in value])
                            elif isinstance(value, str):
                                rules.append(value)
                vprint("SIGMA", f"Loaded Sigma rule {file}")
            except Exception as e:
                vprint("SIGMA_ERR", f"Error loading {file}: {e}")
    return rules

yara_rules = load_yara_rules()
sigma_rules = load_sigma_rules()

# === Honeypot & blocklist helpers ===
BLOCKLIST_FILE = "blocklist.txt"
AUTO_BLOCK = False   # set True to append attacker IPs to blocklist.txt (no active network actions)

def extract_attacker_ips(line):
    ips = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    def valid_octet(o):
        try:
            n = int(o)
            return 0 <= n <= 255
        except:
            return False
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if all(valid_octet(p) for p in parts):
            valid_ips.append(ip)
    return list(dict.fromkeys(valid_ips))

def append_to_blocklist(ips):
    if not ips:
        return
    try:
        with open(BLOCKLIST_FILE, "a") as f:
            for ip in ips:
                f.write(ip + "\n")
        vprint("BLOCKLIST", f"Appended {len(ips)} IP(s) to {BLOCKLIST_FILE}", ips)
    except Exception as e:
        vprint("BLOCKLIST_ERR", f"Could not write blocklist: {e}")

def send_to_honeypot_enhanced(source, line, parsed, matched=None, rule_name=None, features=None, pred=None):
    attacker_ips = extract_attacker_ips(line)
    payload = {
        "detected_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_type": source,
        "matched": str(matched) if matched is not None else None,
        "rule_name": rule_name,
        "log_line": line,
        "attacker_ips": attacker_ips,
        "features": features or {},
        "prediction": int(pred) if pred is not None else None,
        "raw_parsed": {
            "timestamp": str(parsed.get("timestamp")) if parsed is not None else None,
            "level_numeric": int(parsed.get("level_numeric")) if parsed is not None else None,
            "is_connection_break": int(parsed.get("is_connection_break")) if parsed is not None else None,
            "is_received_connection": int(parsed.get("is_received_connection")) if parsed is not None else None,
            "num_ips_in_line": int(parsed.get("num_ips_in_line")) if parsed is not None else None,
        }
    }
    try:
        res = requests.post(HONEYPOT_URL, json=payload, timeout=4)
        if res.status_code == 200:
            vprint("HONEYPOT", "Successfully posted to honeypot", {"rule": rule_name, "ips": attacker_ips})
        else:
            vprint("HONEYPOT_ERR", f"Honeypot responded {res.status_code}", res.text[:500])
    except Exception as e:
        vprint("HONEYPOT_ERR", f"Failed to send to honeypot: {e}", payload)

    if AUTO_BLOCK and attacker_ips:
        append_to_blocklist(attacker_ips)

# === Parse Logs ===
def parse_log_line(line):
    ts_match = re.search(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})', line)
    level_match = re.search(r' - (INFO|WARN|ERROR) ', line)
    ip_matches = re.findall(r'/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):', line)
    ts = pd.to_datetime(ts_match.group(1)) if ts_match else pd.NaT
    level_num = 0 if level_match and level_match.group(1) == 'INFO' else 1
    is_break = 1 if 'Connection broken' in line else 0
    is_received = 1 if 'Received connection request' in line else 0
    unique_ips = len(set(ip_matches))
    ip_div = unique_ips / max(1, len(ip_matches)) if ip_matches else 0.0
    return pd.Series({
        'timestamp': ts,
        'level_numeric': level_num,
        'is_connection_break': is_break,
        'is_received_connection': is_received,
        'num_ips_in_line': len(ip_matches),
        'ip_diversity': ip_div,
        'log_line': line
    })

# === Main monitor ===
def monitor_log(file_path):
    vprint("MONITOR", f"Monitoring {file_path}")
    buffer = deque(maxlen=500)

    if not os.path.exists(file_path):
        vprint("MONITOR", f"Waiting for {file_path} to appear...")
        while not os.path.exists(file_path):
            time.sleep(1)

    pos = 0
    while True:
        try:
            with open(file_path, 'r') as f:
                f.seek(pos)
                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    pos = f.tell()
                    continue
                line = line.strip()
                if not line:
                    pos = f.tell()
                    continue

                buffer.append(line)
                parsed = parse_log_line(line)
                vprint("IN", f"Processing line", line)

                # --- YARA scan ---
                yara_match = False
                yara_rule_name = None
                for name, rule in (yara_rules or {}).items():
                    try:
                        matches = rule.match(data=line)
                        if matches:
                            yara_match = True
                            yara_rule_name = name
                            vprint("YARA", f"Match in {name}", matches)
                            break
                    except Exception as e:
                        vprint("YARA_ERR", f"{name} scan error: {e}")

                # --- Sigma check ---
                sigma_match = False
                matched_keyword = None
                for s in sigma_rules:
                    sk = str(s).lower().strip()
                    if sk and sk in line.lower():
                        sigma_match = True
                        matched_keyword = s
                        vprint("SIGMA", f"Matched keyword '{s}'")
                        break

                # --- Feature engineering ---
                df = pd.DataFrame([parse_log_line(l) for l in buffer])
                df = df.dropna(subset=['timestamp']).sort_values('timestamp')
                if df.empty:
                    pos = f.tell()
                    continue
                now_ts = df['timestamp'].iloc[-1]
                window_start = now_ts - pd.Timedelta(seconds=60)
                window_df = df[df['timestamp'] >= window_start]

                event_count_per_min = len(window_df)
                error_rate = window_df['level_numeric'].mean() if not window_df.empty else 0.0
                ip_diversity = window_df['num_ips_in_line'].std(ddof=0) if len(window_df) > 1 else 0.0

                features = {
                    'event_count_per_min': event_count_per_min,
                    'error_rate': error_rate,
                    'ip_diversity': ip_diversity
                }

                vprint("FEATURES", f"ecpm={event_count_per_min}, err={error_rate:.3f}, ipdiv={ip_diversity:.3f}", features)

                # --- ML prediction ---
                try:
                    feat_df = pd.DataFrame([features])
                    scaled = scaler.transform(feat_df)
                    pred = model.predict(scaled)[0]
                except Exception as e:
                    vprint("ML_ERR", f"Scaler/model error: {e}")
                    pos = f.tell()
                    continue

                # --- Decide and forward to honeypot with rich payload ---
                if pred == -1 or yara_match or sigma_match:
                    vprint("THREAT", f"Detected! pred={pred} yara={yara_match} sigma={sigma_match}", line)
                    save_anomaly(str(now_ts), line, event_count_per_min, error_rate, ip_diversity)
                    # send rich payload
                    send_to_honeypot_enhanced(
                        source="AI/YARA/SIGMA",
                        line=line,
                        parsed=parsed,
                        matched=(matched_keyword or None),
                        rule_name=(yara_rule_name if yara_match else None),
                        features=features,
                        pred=pred
                    )
                else:
                    vprint("OK", f"Analyzing line", line[:120])

                pos = f.tell()
        except Exception as e:
            vprint("MONITOR_ERR", f"Error: {e}")
            time.sleep(1)

# === Run ===
init_db()
monitor_log('server.log')
