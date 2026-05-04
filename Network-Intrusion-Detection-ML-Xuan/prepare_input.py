"""
prepare_input.py
================
Lấy mẫu representative từ các file CSV gốc (CICIDS2017), mỗi attack type
vài dòng, rồi ghi ra inputs/sample_flows.csv để realtime_alert.py đọc trực tiếp.
Chạy một lần trước khi chạy realtime_alert.py.

Usage:
    python prepare_input.py
"""

import os
import sys

if sys.platform == "win32":
    os.system("chcp 65001 > NUL 2>&1")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "inputs")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sample_flows.csv")

SAMPLES_PER_ATTACK = 10  # so mau moi loai attack
SAMPLES_PER_BENIGN = 20  # so mau BENIGN moi file

def collect_samples(fname, target_label, df, collected, is_benign):
    n = SAMPLES_PER_BENIGN if is_benign else SAMPLES_PER_ATTACK
    subset = df[df["Label"] == target_label]
    n_actual = min(n, len(subset))
    if n_actual == 0:
        print(f"  [WARN] '{target_label}' not found in {fname}, skipping")
        return
    sample = subset.sample(n=n_actual, random_state=42)
    collected.append(sample)
    print(f"  [OK] {fname}: sampled {n_actual} rows of '{target_label}'")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    csv_files = sorted([f for f in os.listdir(DATA_DIR) if f.endswith(".csv")])
    print(f"Found {len(csv_files)} CSV files")

    # Doc tat ca, chi lay nhan label -> dem so luong moi label trong tung file
    # de biet file nao chua attack nao
    print("\nScanning labels per file...")
    label_counts = {}
    for fname in csv_files:
        fpath = os.path.join(DATA_DIR, fname)
        df = pd.read_csv(fpath, encoding="cp1252")
        df.columns = df.columns.str.strip()
        labels = df["Label"].value_counts()
        label_counts[fname] = labels
        print(f"  {fname}: {dict(labels)}")

    # Bang mapping: file -> label muon lay
    # Chi lay cac label khac BENIGN, va mot so BENIGN
    # Label names exactly as they appear in the dataset (after cp1252 decode)
    sample_plan = {
        "Monday-WorkingHours.pcap_ISCX.csv": ["BENIGN"],
        "Tuesday-WorkingHours.pcap_ISCX.csv": ["BENIGN", "FTP-Patator", "SSH-Patator"],
        "Wednesday-workingHours.pcap_ISCX.csv": [
            "BENIGN", "DoS Hulk", "DoS GoldenEye",
            "DoS slowloris", "DoS Slowhttptest"
        ],
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": [
            "BENIGN",
            # Web Attack labels have encoding artifacts, match by prefix
        ],
        # Infiltration removed (too rare)
        "Friday-WorkingHours-Morning.pcap_ISCX.csv": ["BENIGN", "Bot"],
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": ["BENIGN", "DDoS"],
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": ["BENIGN", "PortScan"],
    }

    # Handle Web Attack labels separately (encoding artifacts make exact match fragile)
    web_file = "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    web_fpath = os.path.join(DATA_DIR, web_file)
    if os.path.exists(web_fpath):
        df_web = pd.read_csv(web_fpath, encoding="cp1252")
        df_web.columns = df_web.columns.str.strip()
        web_labels = [l for l in df_web["Label"].unique() if "Web Attack" in l]
        sample_plan[web_file] = ["BENIGN"] + web_labels

    collected = []
    for fname, target_labels in sample_plan.items():
        fpath = os.path.join(DATA_DIR, fname)
        if fname not in label_counts:
            continue

        df = pd.read_csv(fpath, encoding="cp1252")
        df.columns = df.columns.str.strip()

        for label in target_labels:
            is_benign = label == "BENIGN"
            collect_samples(fname, label, df, collected, is_benign)

    if not collected:
        print("[ERROR] No data collected!")
        return

    result = pd.concat(collected, ignore_index=True)

    # Drop rows that are entirely NaN (can happen with some files)
    result = result.dropna(how="all")

    # Strip columns one more time
    result.columns = result.columns.str.strip()

    # Loai bo cac cot co toan gia tri null hoac chi co 1 gia tri (zero-variance)
    nunique = result.nunique()
    cols_to_drop = nunique[nunique <= 1].index.tolist()
    if cols_to_drop:
        print(f"\nDropping zero-variance columns: {cols_to_drop}")
        result.drop(columns=cols_to_drop, inplace=True)

    # Drop Label_encoded if it exists (from training pipeline)
    if "Label_encoded" in result.columns:
        result.drop(columns=["Label_encoded"], inplace=True)

    print(f"\n[OK] Total rows: {len(result)}")
    print(f"[OK] Label distribution:")
    print(result["Label"].value_counts().to_string())

    # 17 selected features used in model training (same as notebook)
    SELECTED_FEATURES = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Flow Bytes/s", "Flow Packets/s", "Packet Length Mean",
        "Packet Length Std", "SYN Flag Count", "ACK Flag Count",
        "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "URG Flag Count",
    ]

    # Fit scaler by reading each file in chunks (~50K rows at a time).
    # partial_fit accumulates statistics across all chunks = same as fitting
    # on the full dataset, without loading everything into RAM at once.
    print("\nFitting scaler on full dataset via chunked reading...")
    scaler = StandardScaler()
    chunk_size = 50000
    total_sampled = 0
    for fname in csv_files:
        fpath = os.path.join(DATA_DIR, fname)
        chunks_read = 0
        for chunk in pd.read_csv(fpath, encoding="cp1252", chunksize=chunk_size):
            chunk.columns = chunk.columns.str.strip()
            for col in SELECTED_FEATURES:
                if col not in chunk.columns:
                    chunk[col] = 0.0
                chunk[col] = pd.to_numeric(chunk[col], errors="coerce")
            chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
            for col in SELECTED_FEATURES:
                chunk[col] = chunk[col].fillna(chunk[col].median())
            scaler.partial_fit(chunk[SELECTED_FEATURES])
            chunks_read += len(chunk)
        total_sampled += chunks_read
        print(f"  [OK] {fname}: {chunks_read:,} rows for scaler")

    scaler_path = os.path.join(OUTPUT_DIR, "scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"[OK] Scaler fitted on {total_sampled:,} total rows -> saved to inputs/scaler.pkl")

    result.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[OK] Sample flows saved to inputs/sample_flows.csv")
    print(f"    Rows: {len(result)} | Columns: {len(result.columns)}")


if __name__ == "__main__":
    main()
