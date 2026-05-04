# Hệ Thống Phát Hiện Xâm Nhập Mạng Dựa Trên Máy Học (Network Intrusion Detection System - ML-based)

## Mục lục

1. [Giới thiệu](#1-giới-thiệu)
2. [Cấu trúc dự án](#2-cấu-trúc-dự-án)
3. [Bộ dữ liệu](#3-bộ-dữ-liệu)
4. [Cài đặt và chuẩn bị](#4-cài-đặt-và-chuẩn-bị)
5. [Huấn luyện mô hình](#5-huấn-luyện-mô-hình)
6. [Mô phỏng phát hiện xâm nhập thời gian thực](#6-mô-phỏng-phát-hiện-xâm-nhập-thời-gian-thực)
7. [Chi tiết kỹ thuật](#7-chi-tiết-kỹ-thuật)
8. [Các mô hình được so sánh](#8-các-mô-hình-được-so-sánh)
9. [Định dạng cảnh báo](#9-định-dạng-cảnh-báo)
10. [Giải thích các trường dữ liệu](#10-giải-thích-các-trường-dữ-liệu)

---

## 1. Giới thiệu

Dự án xây dựng một **hệ thống phát hiện xâm nhập mạng (IDS)** sử dụng các thuật toán máy học (Machine Learning), được huấn luyện trên bộ dữ liệu **CICIDS2017** — bộ dữ liệu chuẩn quốc tế cho nghiên cứu phát hiện xâm nhập mạng.

Hệ thống hoạt động theo nguyên lý **phát hiện bất thường (anomaly-based detection)**: huấn luyện mô hình phân loại trên lưu lượng mạng bình thường và các kiểu tấn công, sau đó dùng mô hình đã huấn luyện để phân loại lưu lượng mới thành **bình thường (BENIGN)** hoặc **tấn công (attack)** cùng với loại tấn công cụ thể.

### Các loại tấn công được phát hiện

| Loại tấn công | Mô tả |
|---|---|
| **BENIGN** | Lưu lượng bình thường, không có xâm nhập |
| **Bot** | Mã độc bot tự động tấn công |
| **DDoS** | Tấn công từ chối dịch vụ phân tán |
| **DoS Hulk / GoldenEye / slowloris / Slowhttptest** | Các biến thể tấn công từ chối dịch vụ |
| **PortScan** | Quét cổng để tìm lỗ hổng |
| **FTP-Patator / SSH-Patator** | Tấn công brute-force vào dịch vụ FTP/SSH |
| **Web Attack (Brute Force, XSS, SQL Injection)** | Tấn công ứng dụng web |

---

## 2. Cấu trúc dự án

```
Network-Intrusion-Detection-ML-Xuan/
├── README.md                        # Tài liệu hướng dẫn (tệp này)
├── .gitignore                       # Loại trừ thư mục data/, logs/, inputs/, models/
├── src/
│   └── TrainingModel.ipynb          # Notebook huấn luyện mô hình ML
├── prepare_input.py                 # Script chuẩn bị dữ liệu đầu vào & fitting scaler
├── data/                            # Thư mục chứa bộ dữ liệu CICIDS2017
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   ├── Wednesday-workingHours.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
│   └── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
├── inputs/                          # Sinh ra bởi prepare_input.py
│   ├── sample_flows.csv            # Mẫu lưu lượng cho mô phỏng realtime
│   └── scaler.pkl                  # Scaler đã được fit
├── models/                         # Sinh ra bởi TrainingModel.ipynb
│   ├── random_forest_model.pkl     # Mô hình Random Forest đã huấn luyện
│   └── label_encoder.pkl           # Bộ mã hóa nhãn
└── logs/                           # Sinh ra bởi realtime_alert.py
    └── alerts_YYYYMMDD_HHMMSS.log  # Nhật ký cảnh báo
```

---

## 3. Bộ dữ liệu

Dự án sử dụng bộ dữ liệu **CICIDS2017** (Canadian Institute for Cybersecurity Intrusion Detection System 2017) — bộ dữ liệu thực tế thu thập trong 5 ngày làm việc tại một mạng thực nghiệm.

### Thông tin tổng quan

| Thông số | Giá trị |
|---|---|
| Tổng số bản ghi | **2.522.362 dòng** |
| Số cột | **79 cột** |
| Số cột sau khi chọn lọc | **17 đặc trưng** |
| Số lớp (nhãn) | **12 lớp** |
| Nguồn | [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) |

### Các tệp dữ liệu

- **Monday** — Lưu lượng bình thường (BENIGN)
- **Tuesday** — Tấn công Brute Force FTP/SSH
- **Wednesday** — Tấn công DoS (Hulk, GoldenEye, Slowloris, Slowhttptest)
- **Thursday (Morning)** — Tấn công ứng dụng Web (Brute Force, XSS, SQL Injection)
- **Thursday (Afternoon)** — Tấn công Infiltration
- **Friday (Morning)** — Tấn công Bot
- **Friday (Afternoon 1)** — Tấn công DDoS
- **Friday (Afternoon 2)** — PortScan

---

## 4. Cài đặt và chuẩn bị

### 4.1. Yêu cầu hệ thống

- Python 3.8 trở lên
- RAM tối thiểu 8GB (do kích thước bộ dữ liệu lớn)

### 4.2. Cài đặt thư viện

```bash
pip install pandas numpy scikit-learn imbalanced-learn joblib
```

Các thư viện cần thiết:

| Thư viện | Phiên bản | Mục đích |
|---|---|---|
| `pandas` | >= 1.5 | Đọc và xử lý dữ liệu dạng bảng |
| `numpy` | >= 1.23 | Tính toán số học, xử lý NaN/Inf |
| `scikit-learn` | >= 1.2 | Tiền xử lý, huấn luyện mô hình, đánh giá |
| `imbalanced-learn` | >= 0.10 | Xử lý mất cân bằng dữ liệu (SMOTE, RUS) |
| `joblib` | >= 1.2 | Lưu và tải mô hình đã huấn luyện |

### 4.3. Tải bộ dữ liệu CICIDS2017

1. Truy cập: https://www.unb.ca/cic/datasets/ids-2017.html
2. Đăng ký và tải bộ dữ liệu về
3. Giải nén và đặt **tất cả 8 tệp CSV** vào thư mục `data/`
4. Đảm bảo tên tệp chính xác như trong cấu trúc dự án

---

## 5. Huấn luyện mô hình

### 5.1. Mở Notebook

Mở tệp `src/TrainingModel.ipynb` bằng Jupyter Notebook hoặc VS Code (extension Jupyter):

```bash
jupyter notebook src/TrainingModel.ipynb
```

### 5.2. Chạy toàn bộ các ô (Run All Cells)

Thực thi lần lượt các ô trong notebook để hoàn thành pipeline:

#### 5.2.1. Tiền xử lý dữ liệu

- Đọc 8 tệp CSV từ thư mục `data/`
- Gộp thành một DataFrame thống nhất
- Xử lý giá trị thiếu, giá trị vô cùng (inf)
- Tối ưu bộ nhớ: chuyển cột float về `float32`
- Mã hóa nhãn (Label Encoding)

#### 5.2.2. Chọn đặc trưng (Feature Selection)

Hệ thống sử dụng **17 đặc trưng** được chọn lọc từ 79 cột gốc, bao gồm:

| # | Tên đặc trưng | Mô tả |
|---|---|---|
| 1 | Flow Duration | Thời gian tồn tại của luồng (microgiây) |
| 2 | Total Fwd Packets | Tổng số gói tin phía forward |
| 3 | Total Backward Packets | Tổng số gói tin phía backward |
| 4 | Total Length of Fwd Packets | Tổng kích thước gói forward (bytes) |
| 5 | Total Length of Bwd Packets | Tổng kích thước gói backward (bytes) |
| 6 | Fwd Packet Length Mean | Kích thước trung bình gói forward |
| 7 | Bwd Packet Length Mean | Kích thước trung bình gói backward |
| 8 | Flow Bytes/s | Tốc độ byte trên giây |
| 9 | Flow Packets/s | Tốc độ gói tin trên giây |
| 10 | Packet Length Mean | Độ dài trung bình gói tin |
| 11 | Packet Length Std | Độ lệch chuẩn độ dài gói tin |
| 12 | SYN Flag Count | Số lượng cờ SYN |
| 13 | ACK Flag Count | Số lượng cờ ACK |
| 14 | FIN Flag Count | Số lượng cờ FIN |
| 15 | RST Flag Count | Số lượng cờ RST |
| 16 | PSH Flag Count | Số lượng cờ PSH |
| 17 | URG Flag Count | Số lượng cờ URG |

#### 5.2.3. Xử lý mất cân bằng dữ liệu

Dữ liệu CICIDS2017 có **tỷ lệ mất cân bằng nghiêm trọng** — lớp BENIGN chiếm đa số áp đảo. Hệ thống sử dụng kết hợp hai kỹ thuật:

```
1. RandomUnderSampler (RUS) → Giảm số lượng mẫu lớp đa số
2. SMOTE → Tăng số lượng mẫu lớp thiểu số bằng nội suy
```

Quy trình:
```
Dữ liệu gốc
     │
     ▼
[RandomUnderSampler] ── Giảm lớp BENIGN xuống mức vừa phải
     │
     ▼
[SMOTE] ──────────────── Oversample các lớp tấn công thiểu số
     │
     ▼
Dữ liệu cân bằng (584,800 mẫu)
```

#### 5.2.4. Huấn luyện mô hình

Dữ liệu được chia: **80% train / 20% test**

Các thuật toán được huấn luyện và so sánh:

| Mô hình | Cấu hình | Ghi chú |
|---|---|---|
| Logistic Regression | `max_iter=1000, random_state=42` | Mô hình tuyến tính cơ bản |
| SVM | `kernel='linear'`, subset 30K mẫu | Do dữ liệu lớn nên huấn luyện trên tập con |
| Gaussian Naive Bayes | Mặc định | Mô hình xác suất |
| KNN | `n_neighbors=5` | Thuật toán hàng xóm gần nhất |
| **Random Forest** | `n_estimators=100, random_state=42` | **Mô hình được chọn** — hiệu suất tốt nhất |

#### 5.2.5. Đánh giá

Mô hình được đánh giá bằng các metric tiêu chuẩn:
- **Accuracy** — Độ chính xác tổng thể
- **Precision** — Độ chính xác dương tính
- **Recall** — Tỷ lệ phát hiện thực sự
- **F1-Score** — Trung bình điều hòa Precision và Recall
- **Confusion Matrix** — Ma trận nhầm lẫn giữa các lớp

**Kết quả đạt được (Random Forest):**
- Accuracy: ~89%
- Weighted F1-Score: ~0.91

#### 5.2.6. Lưu mô hình

Sau khi huấn luyện xong, notebook sẽ tự động lưu:

- `models/random_forest_model.pkl` — Mô hình Random Forest đã huấn luyện
- `models/label_encoder.pkl` — Bộ mã hóa nhãn (ánh xạ số → tên lớp tấn công)

---

## 6. Mô phỏng phát hiện xâm nhập thời gian thực

### 6.1. Bước 1 — Chuẩn bị dữ liệu đầu vào

Trước khi chạy mô phỏng, cần chạy script `prepare_input.py`:

```bash
python prepare_input.py
```

Script này thực hiện:

| Bước | Mô tả |
|---|---|
| 1 | Đọc toàn bộ 8 tệp CSV từ `data/` |
| 2 | Lấy mẫu 20 dòng benign + 10 dòng tấn công mỗi tệp |
| 3 | Xử lý cột toàn NaN, cột không có phương sai |
| 4 | Fit `StandardScaler` trên toàn bộ dữ liệu (đọc chunk 50K dòng để tiết kiệm RAM) |
| 5 | Lưu scaler vào `inputs/scaler.pkl` |
| 6 | Lưu mẫu vào `inputs/sample_flows.csv` |

**Tại sao dùng `partial_fit()`?** — Bộ dữ liệu CICIDS2017 có kích thước rất lớn (hàng triệu dòng). Việc đọc toàn bộ vào RAM có thể gây tràn bộ nhớ. Thuật toán đọc theo chunk 50,000 dòng và gọi `partial_fit()` để cập nhật scaler dần dần.

### 6.2. Bước 2 — Chạy mô phỏng

```bash
python realtime_alert.py
```

Script sẽ:

1. **Tải mô hình** từ `models/random_forest_model.pkl` và `models/label_encoder.pkl`
2. **Tải dữ liệu mẫu** từ `inputs/sample_flows.csv`
3. **Tiền xử lý** từng luồng: thay inf → NaN → điền NaN bằng median của cột → chuẩn hóa bằng scaler
4. **Dự đoán** nhãn cho từng luồng bằng `model.predict()`
5. **In cảnh báo** ra console và ghi vào log khi phát hiện tấn công
6. **Mô phỏng độ trễ** giữa các luồng (0.1–0.5 giây ngẫu nhiên)
7. **In tổng kết** khi hoàn thành: tổng luồng, số tấn công phát hiện, tỷ lệ cảnh báo

### 6.3. Output mẫu

```
======================================================================
  [ALERT] 2026-05-04 20:44:10.123
======================================================================
  Classification  : DoS Hulk
  Dest. Port      : 80
  Flow Duration   : 83,508,399 us
  Flow Bytes/s    : 143.82
  Flow Packets/s  : 0.16
  SYN Flags       : 0
  ACK Flags       : 0

  Suricata EVE JSON:
  {
    "timestamp": "2026-05-04 20:44:10.123",
    "event_type": "alert",
    "dest_port": 80,
    "alert": {
      "signature_id": 2000007,
      "rev": 1,
      "signature": "ML-IDS: DoS Hulk traffic detected"
    }
  }
======================================================================
```

**Nhật ký cảnh báo** được lưu vào: `logs/alerts_YYYYMMDD_HHMMSS.log`

---

## 7. Chi tiết kỹ thuật

### 7.1. Hàm chính trong `prepare_input.py`

| Hàm | Dòng | Mô tả |
|---|---|---|
| `collect_samples(csv_path, label, sample_size)` | 33–42 | Lấy mẫu ngẫu nhiên các dòng thuộc một nhãn cụ thể từ một tệp CSV |
| `main()` | 44–175 | Pipeline chính: quét nhãn → lấy mẫu → xử lý NaN → fit scaler → lưu |

### 7.2. Hàm chính trong `realtime_alert.py`

| Hàm | Dòng | Mô tả |
|---|---|---|
| `load_model()` | 60–66 | Tải mô hình và label encoder từ thư mục `models/` |
| `load_flows()` | 69–88 | Tải mẫu luồng từ `inputs/` và kiểm tra sự tồn tại của tệp |
| `preprocess(flow_df, scaler)` | 91–107 | Xử lý inf/NaN, chuẩn hóa đặc trưng bằng scaler đã fit |
| `build_alert_entry(pred_label, timestamp, flow_data)` | 110–147 | Tạo chuỗi cảnh báo định dạng Suricata EVE JSON |
| `simulate(model, flows, scaler)` | 150–210 | Vòng lặp chính: dự đoán, in cảnh báo, ghi log |
| `main()` | 213–229 | Điểm khởi đầu chương trình |

### 7.3. Thiết kế mô phỏng thời gian thực

Script `realtime_alert.py` hoạt động ở chế độ **mô phỏng** — đọc luồng từ file CSV và thêm độ trễ ngẫu nhiên giữa các lần dự đoán. Để chuyển thành hệ thống thời gian thực thực sự, có thể thay thế phần đọc CSV bằng:

- **Live packet capture** bằng thư viện `scapy` hoặc `pyshark`
- **Kafka consumer** nhận luồng từ broker mạng
- **Socket listener** nhận NetFlow/sFlow từ thiết bị mạng

---

## 8. Các mô hình được so sánh

### So sánh hiệu suất

| Mô hình | Ưu điểm | Nhược điểm |
|---|---|---|
| Logistic Regression | Nhanh, dễ diễn giải | Hiệu suất thấp với dữ liệu phức tạp |
| SVM | Hiệu quả trên không gian nhiều chiều | Quá chậm trên dữ liệu lớn; cần huấn luyện trên tập con |
| Gaussian Naive Bayes | Rất nhanh, ít tham số | Giả định độc lập giữa các đặc trưng |
| KNN | Đơn giản, không cần huấn luyện | Chậm khi suy luận, nhạy cảm với chiều cao |
| **Random Forest** | Kháng overfitting, xử lý tốt mất cân bằng, độ chính xác cao | Tốn bộ nhớ hơn một số mô hình khác |

**Mô hình được chọn: Random Forest** vì đạt hiệu suất tổng thể tốt nhất trên các metric Accuracy, F1-Score và khả năng phát hiện tốt trên nhiều loại tấn công khác nhau.

---

## 9. Định dạng cảnh báo

Cảnh báo được định dạng theo chuẩn **Suricata EVE JSON** — định dạng chuẩn của hệ thống IDS mã nguồn mở Suricata, tương thích với hầu hết các nền tảng SIEM (Security Information and Event Management) như Elasticsearch, Splunk, Graylog.

### Cấu trúc cảnh báo

```json
{
  "timestamp": "2026-05-04 20:44:10.123",
  "event_type": "alert",
  "src_ip": "192.168.1.101",
  "src_port": 45678,
  "dest_ip": "192.168.1.10",
  "dest_port": 80,
  "protocol": "TCP",
  "flow_duration_us": 83508399,
  "flow_bytes_per_sec": 143.82,
  "flow_packets_per_sec": 0.16,
  "alert": {
    "signature_id": 2000007,
    "rev": 1,
    "signature": "ML-IDS: DoS Hulk traffic detected",
    "category": "DoS Attack",
    "severity": 1
  }
}
```

### Mức độ nghiêm trọng (Severity)

| Mức | Màu | Mô tả |
|---|---|---|
| 1 | Green | Thông tin (BENIGN — không có xâm nhập) |
| 2 | Yellow | Cảnh báo nhẹ |
| 3 | Orange | Cảnh báo trung bình |
| 4 | Red | Cảnh báo nghiêm trọng (DDoS, Bot, DoS nặng) |

---

## 10. Giải thích các trường dữ liệu

### 10.1. Các trường luồng (Flow Fields)

| Trường | Mô tả | Ví dụ |
|---|---|---|
| `Flow Duration` | Thời gian tồn tại luồng (μs) | 83508399 |
| `Total Fwd Packets` | Số gói forward | 8 |
| `Total Backward Packets` | Số gói backward | 12 |
| `Total Length of Fwd Packets` | Tổng bytes forward | 640 |
| `Total Length of Bwd Packets` | Tổng bytes backward | 8960 |
| `Flow Bytes/s` | Tốc độ byte/giây | 143.82 |
| `Flow Packets/s` | Tốc độ gói tin/giây | 0.16 |

### 10.2. Các trường cờ TCP (TCP Flag Fields)

| Trường | Mô tả | Ý nghĩa tấn công |
|---|---|---|
| `SYN Flag Count` | Số gói có cờ SYN | DoS thường có SYN cao bất thường |
| `ACK Flag Count` | Số gói có cờ ACK | Xác nhận kết nối |
| `FIN Flag Count` | Số gói có cờ FIN | Kết thúc kết nối |
| `RST Flag Count` | Số gói có cờ RST | Reset kết nối — có thể là quét port |
| `PSH Flag Count` | Số gói có cờ PSH | Ép đẩy dữ liệu |
| `URG Flag Count` | Số gói có cờ URG | Dữ liệu khẩn cấp |

### 10.3. Các trường kích thước gói (Packet Length Fields)

| Trường | Mô tả | Ý nghĩa |
|---|---|---|
| `Fwd Packet Length Mean` | Kích thước TB gói forward | Phản ánh hành vi tải lên |
| `Bwd Packet Length Mean` | Kích thước TB gói backward | Phản ánh hành vi tải xuống |
| `Packet Length Mean` | Kích thước TB toàn bộ gói | Dấu hiệu nhận dạng loại tấn công |
| `Packet Length Std` | Độ lệch chuẩn kích thước gói | Đa dạng kích thước gói |

---

## Tài liệu tham khảo

- **CICIDS2017 Dataset**: Sharafaldin, I., et al. (2018). "Toward a Reliable Intrusion Detection Benchmark Dataset." *Software Networking*, 2018(1), 177–200.
- **Random Forest**: Breiman, L. (2001). "Random Forests." *Machine Learning*, 45(1), 5–32.
- **SMOTE**: Chawla, N.V., et al. (2002). "SMOTE: Synthetic Minority Over-sampling Technique." *JAIR*, 16, 321–357.
- **Suricata EVE JSON**: https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html
