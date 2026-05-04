"""
Real-time Network Intrusion Detection System
============================================
Doc flows tu inputs/sample_flows.csv (da duoc prepare_input.py tao san),
tien xu ly, phan loai bang Random Forest, va in alert Suricata-style
khi phat hien attack.

Thu tu chay:
    python prepare_input.py   # chi can chay 1 lan de tao inputs/sample_flows.csv
    python realtime_alert.py

"""

import os
import sys

if sys.platform == "win32":
    os.system("chcp 65001 > NUL 2>&1")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import time
import random
import joblib
import pandas as pd
import numpy as np
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "inputs")
MODEL_DIR = os.path.join(BASE_DIR, "models")
LOG_DIR = os.path.join(BASE_DIR, "logs")
INPUT_PATH = os.path.join(INPUT_DIR, "sample_flows.csv")
SCALER_PATH = os.path.join(INPUT_DIR, "scaler.pkl")
MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")

SELECTED_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "URG Flag Count",
]


def load_model():
    print("[INFO] Loading Random Forest model and LabelEncoder...")
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(ENCODER_PATH)
    print(f"[OK] Model loaded  |  Features: {len(SELECTED_FEATURES)}")
    print(f"[OK] Labels: {len(label_encoder.classes_)} classes")
    return model, label_encoder


def load_flows():
    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError(
            f"File not found: {INPUT_PATH}\n"
            "Please run: python prepare_input.py"
        )
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            f"File not found: {SCALER_PATH}\n"
            "Please run: python prepare_input.py"
        )
    print("[INFO] Loading flows from inputs/sample_flows.csv...")
    df = pd.read_csv(INPUT_PATH)
    df.columns = df.columns.str.strip()
    print(f"[OK] Loaded {len(df)} flows | Labels: {df['Label'].nunique()}")

    print("[INFO] Loading scaler from inputs/scaler.pkl...")
    scaler = joblib.load(SCALER_PATH)
    print(f"[OK] Scaler loaded")
    return df, scaler


def preprocess(df, scaler):
    df = df.copy()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    num_cols = df.select_dtypes(include=[np.number]).columns
    for col in num_cols:
        df[col] = df[col].fillna(df[col].median())

    for col in SELECTED_FEATURES:
        if col not in df.columns:
            df[col] = 0.0

    X = df[SELECTED_FEATURES].copy()
    num_cols = X.select_dtypes(include=[np.number]).columns
    X[num_cols] = scaler.transform(X[num_cols])

    return X


def build_alert_entry(flow, pred_idx, label_encoder, flow_num):
    """Build alert text for both console and log file."""
    label = label_encoder.inverse_transform([pred_idx])[0]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    dst_port = flow.get("Destination Port", "N/A")
    flow_dur = flow.get("Flow Duration", 0)
    flow_bytes = flow.get("Flow Bytes/s", 0)
    flow_pkts = flow.get("Flow Packets/s", 0)
    syn_cnt = flow.get("SYN Flag Count", 0)
    ack_cnt = flow.get("ACK Flag Count", 0)

    entry = []
    entry.append("=" * 70)
    entry.append(f"  [ALERT] {ts}")
    entry.append("=" * 70)
    entry.append(f"  Classification  : {label}")
    entry.append(f"  Dest. Port      : {dst_port}")
    entry.append(f"  Flow Duration   : {flow_dur:,.0f} us")
    entry.append(f"  Flow Bytes/s    : {flow_bytes:,.2f}")
    entry.append(f"  Flow Packets/s  : {flow_pkts:,.2f}")
    entry.append(f"  SYN Flags       : {syn_cnt}")
    entry.append(f"  ACK Flags       : {ack_cnt}")
    entry.append("")
    entry.append("  Suricata EVE JSON:")
    entry.append("  {")
    entry.append(f'    "timestamp": "{ts}",')
    entry.append(f'    "event_type": "alert",')
    entry.append(f'    "dest_port": {dst_port},')
    entry.append(f'    "alert": {{')
    entry.append(f'      "signature_id": {2000000 + pred_idx},')
    entry.append(f'      "rev": 1,')
    entry.append(f'      "signature": "ML-IDS: {label} traffic detected"')
    entry.append(f"    }}")
    entry.append("  }")
    entry.append("=" * 70)

    return "\n".join(entry), ts, label


def simulate(model, label_encoder, flows_df, scaler, delay=(0.1, 0.5)):
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(
        LOG_DIR,
        f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    log_fh = open(log_file, "w", encoding="utf-8")

    log_fh.write(f"ALERT LOG - Started {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_fh.write(f"Total flows: {len(flows_df)}\n")
    log_fh.write("=" * 70 + "\n\n")

    X = preprocess(flows_df, scaler)

    total = len(flows_df)
    alert_count = 0

    print()
    print("=" * 70)
    print(f"  REAL-TIME INTRUSION DETECTION SIMULATION")
    print(f"  Total flows     : {total}")
    print(f"  Delay per flow : {delay[0]}s - {delay[1]}s")
    print(f"  Log file       : {log_file}")
    print("=" * 70)
    print()
    print(f"[INFO] Alert log: {log_file}")

    for idx in range(total):
        flow = flows_df.iloc[idx]
        X_row = X.iloc[idx : idx + 1]
        pred_idx = model.predict(X_row)[0]
        pred_label = label_encoder.inverse_transform([pred_idx])[0]
        flow_num = idx + 1

        if pred_label != "BENIGN":
            alert_count += 1
            alert_text, ts, label = build_alert_entry(flow, pred_idx, label_encoder, flow_num)
            print(alert_text)
            log_fh.write(f"[ALERT] Flow #{flow_num:04d} | {ts} | {label}\n")
            log_fh.write(alert_text + "\n\n")
            log_fh.flush()
        else:
            dst_port = flow.get("Destination Port", "N/A")
            msg = f"[BENIGN] #{flow_num:04d}/{total}  |  Dest Port: {dst_port}"
            print(msg)

        time.sleep(random.uniform(*delay))

    summary = (
        f"\n{'=' * 70}\n"
        f"  SIMULATION COMPLETE\n"
        f"  Flows processed : {total}\n"
        f"  Attacks detected : {alert_count}\n"
        f"  Alert rate       : {alert_count / total * 100:.1f}%\n"
        f"  Log saved to     : {log_file}\n"
        f"{'=' * 70}\n"
    )
    print(summary)
    log_fh.write(summary)
    log_fh.close()
    print(f"[OK] Alert log saved: {log_file}")


def main():
    print("=" * 70)
    print("  NETWORK INTRUSION DETECTION - REALTIME SIMULATION")
    print("=" * 70)

    model, label_encoder = load_model()
    flows_df, scaler = load_flows()

    print("\nLabel distribution in sample:")
    for label, count in flows_df["Label"].value_counts().items():
        print(f"  {label}: {count}")

    simulate(model, label_encoder, flows_df, scaler, delay=(0.1, 0.5))


if __name__ == "__main__":
    main()
