import os
import time
import joblib
import warnings
import numpy as np
from datetime import datetime

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(SCRIPT_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_model.pkl")
LOG_FILE = os.path.join(SCRIPT_DIR, "./logs/alerts.log")


# FEATURES: 17 numeric features (Protocol was NOT used in training)
FEATURE_NAMES = [
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

NUM_FEATURES = len(FEATURE_NAMES)  # 17


# Label mapping - EXACT from notebook output (LabelEncoder sorts alphabetically)
LABEL_MAPPING = {
    0: "BENIGN",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS slowloris",
    6: "FTP-Patator",
    7: "Heartbleed",
    8: "Infiltration",
    9: "PortScan",
    10: "SSH-Patator",
    11: "Web Attack - Brute Force",
    12: "Web Attack - Sql Injection",
    13: "Web Attack - XSS",
}


# LOAD MODEL & SCALER
try:
    model = joblib.load(MODEL_PATH)
    print(f"[INFO] Da load model tu: {MODEL_PATH}")
except FileNotFoundError as e:
    print(f"[ERROR] Khong tim thay file: {e}")
    print("[ERROR] Dam bao rang realtime_alert.py nam cung cap voi thu muc models/")
    raise SystemExit(1)
except Exception as e:
    print(f"[ERROR] Loi khi load model: {e}")
    raise SystemExit(1)



# 2. HAM XU LY REAL-TIME INPUT
def process_flow(flow_features: list) -> str:
    if len(flow_features) != NUM_FEATURES:
        raise ValueError(
            f"So luong feature khong dung! Mong muon {NUM_FEATURES}, "
            f"nhan duoc {len(flow_features)}. "
            f"Vui long kiem tra dau vao."
        )

    X = np.array(flow_features, dtype=np.float64).reshape(1, -1)

    # Du doan nhan (tra ve so nguyen 0-14)
    prediction = model.predict(X)
    predicted_class = int(prediction[0])

    # Chuyen so -> ten attack
    label_name = LABEL_MAPPING.get(predicted_class, f"Unknown({predicted_class})")
    return label_name



# 3. LOGIC ALERT
def trigger_alert(attack_type: str, expected_type: str) -> None:

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = (
        f"[ALERT] Suspicious traffic detected: {attack_type}. "
        f"Expected: {expected_type}"
    )

    # In ra console
    print(alert_msg)

    # Tao thu muc logs neu chua ton tai
    log_dir = os.path.dirname(os.path.abspath(LOG_FILE))
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # Append vao file log
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {alert_msg}\n")
    except Exception as e:
        print(f"[WARNING] Khong the ghi log: {e}")


# 4. SIMULATE REAL-TIME DATA
def simulate_stream() -> None:

    # MAU 1: Luong BENIGN (binh thuong)
    benign_samples = [
        # HTTP traffic binh thuong
        [1266342, 41, 44, 2664, 6954, 64.98, 158.0,
         7618.0, 0.067, 111.6, 115.2, 1, 1, 0, 0, 0, 0],
        # HTTPS traffic binh thuong
        [892134, 55, 52, 3200, 8100, 58.18, 155.77,
         12480.5, 0.12, 106.8, 108.4, 1, 1, 0, 0, 0, 0],
        # SSH traffic binh thuong
        [445667, 30, 28, 1900, 4100, 63.33, 146.43,
         13450.0, 0.13, 104.7, 98.3, 1, 1, 0, 0, 0, 0],
    ]

    # MAU 2: Port Scan attack
    portscan_samples = [
        # PortScan - nhieu port, it goi tra loi
        [3456, 1, 0, 0, 0, 0.0, 0.0,
         0.0, 289.0, 0.0, 0.0, 0, 0, 0, 0, 0, 0],
        # PortScan - nhieu goi Fwd, rat itBackward
        [1234, 50, 2, 200, 80, 4.0, 40.0,
         226.0, 42.1, 5.6, 12.3, 0, 1, 0, 0, 0, 0],
        # PortScan - thoi gian ngan, nhieu port
        [567, 30, 0, 120, 0, 4.0, 0.0,
         211.8, 52.9, 4.0, 0.0, 0, 0, 0, 0, 0, 0],
    ]

    # MAU 3: DDoS attack
    ddos_samples = [
        # DDoS - nhieu goi nho, tan suat cao
        [234, 200, 0, 2000, 0, 10.0, 0.0,
         8547.0, 854.7, 10.0, 0.0, 1, 0, 0, 0, 0, 0],
        # DDoS - luu luong lon, khong co goi tra loi
        [100, 500, 0, 5000, 0, 10.0, 0.0,
         50000.0, 5000.0, 10.0, 0.0, 1, 0, 0, 0, 0, 0],
        # DDoS - SYN flood
        [89, 300, 0, 3000, 0, 10.0, 0.0,
         33708.0, 3370.8, 10.0, 0.0, 1, 0, 0, 0, 0, 0],
    ]

    # MAU 4: Brute Force (SSH/HTTP)
    bruteforce_samples = [
        # SSH Brute Force - nhieu goi SYN nho
        [500, 80, 0, 800, 0, 10.0, 0.0,
         1600.0, 160.0, 10.0, 0.0, 1, 0, 0, 0, 0, 0],
        # HTTP Brute Force - nhieu request nho
        [300, 120, 0, 1200, 0, 10.0, 0.0,
         4000.0, 400.0, 10.0, 0.0, 0, 0, 0, 0, 0, 0],
        # Brute Force - tan suat cao, goi nho
        [150, 200, 0, 2000, 0, 10.0, 0.0,
         13333.0, 1333.3, 10.0, 0.0, 1, 0, 0, 0, 0, 0],
    ]

    # MAU 5: Infiltration / Botnet
    infiltration_samples = [
        # Infiltration - luong bat thuong, tan suat rat cao
        [50, 1000, 0, 10000, 0, 10.0, 0.0,
         200000.0, 20000.0, 10.0, 0.0, 1, 0, 0, 0, 0, 0],
        # Botnet - ket hop nhieu flag
        [200, 300, 100, 3000, 1000, 10.0, 10.0,
         20000.0, 2000.0, 10.0, 10.0, 1, 1, 0, 0, 1, 0],
    ]

    # Xay dung danh sach day du de simulate
    all_samples = [
        (benign_samples[0], "BENIGN"),
        (portscan_samples[0], "PortScan"),
        (benign_samples[1], "BENIGN"),
        (ddos_samples[0], "DDoS"),
        (benign_samples[2], "BENIGN"),
        (bruteforce_samples[0], "Brute Force"),
        (portscan_samples[1], "PortScan"),
        (ddos_samples[1], "DDoS"),
        (benign_samples[0], "BENIGN"),
        (infiltration_samples[0], "Infiltration"),
        (bruteforce_samples[1], "Brute Force"),
        (ddos_samples[2], "DDoS"),
        (portscan_samples[2], "PortScan"),
        (infiltration_samples[1], "Botnet"),
        (benign_samples[2], "BENIGN"),
        (bruteforce_samples[2], "Brute Force"),
        (benign_samples[1], "BENIGN"),
    ]

    print("=" * 60)
    print("  HE THONG PHAT HIEN TAN CONG MANG - REAL-TIME MODE")
    print("=" * 60)
    print(f"[INFO] Tong so flow: {len(all_samples)}")
    print(f"[INFO] Log file: {LOG_FILE}")
    print("-" * 60)

    for idx, (features, expected_label) in enumerate(all_samples, start=1):
        try:
            predicted_label = process_flow(features)

            # Neu khong phai BENIGN -> trigger alert
            if predicted_label != "BENIGN":
                trigger_alert(predicted_label, expected_label)
            else:
                print(f"[OK]   Flow {idx:02d}: {predicted_label} ({expected_label})")

        except ValueError as e:
            print(f"[ERROR] Flow {idx:02d}: {e}")
        except Exception as e:
            print(f"[ERROR] Flow {idx:02d}: Loi xu ly: {e}")

        # Dung 1 giay de gia lap real-time
        time.sleep(1)

    print("-" * 60)
    print("[INFO] Done!")


# 6. MAIN
if __name__ == "__main__":
    simulate_stream()
