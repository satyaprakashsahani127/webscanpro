# utils.py
import datetime, json, os

def log(step_num, msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{step_num}] {msg}")

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
