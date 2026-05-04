import pandas as pd
import numpy as np
import glob
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline

# ==========================================
# 1. TẢI VÀ LÀM SẠCH DỮ LIỆU (MỤC 2.2)
# ==========================================
print("--- Đang tải dữ liệu ---")
data_path = os.path.join('data', "*.parquet")
all_files = glob.glob(data_path)

if not all_files:
    print("LỖI: Không tìm thấy file .parquet trong thư mục 'data/'")
    exit()

df = pd.concat((pd.read_parquet(f) for f in all_files), ignore_index=True)

# Lấy mẫu để thử nghiệm 
df = df.sample(frac=0.1, random_state=42) 

print("--- Đang làm sạch dữ liệu ---")
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(df.median(numeric_only=True), inplace=True)
df.drop_duplicates(inplace=True)

# ==========================================
# 2. LỰA CHỌN ĐẶC TRƯNG (MỤC 2.4 - FIX KEYERROR)
# ==========================================
required_features = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow Bytes/s', 
    'Flow Packets/s', 'Packet Length Mean', 'Packet Length Std', 
    'SYN Flag Count', 'ACK Flag Count', 'FIN Flag Count', 
    'RST Flag Count', 'PSH Flag Count', 'URG Flag Count'
]

final_features = []
for feat in required_features:
    # Tìm kiếm mờ để khớp tên cột bất kể định dạng file
    match = [c for c in df.columns if c.lower() == feat.lower() or 
             c.lower().replace(" ", "") in feat.lower().replace(" ", "")]
    if match:
        final_features.append(match[0])

X = df[final_features]
y = df['Label']
print(f"--- Đã khớp thành công {len(final_features)}/18 đặc trưng ---")

# ==========================================
# 3. TIỀN XỬ LÝ & LỌC LỚP HIẾM (MỤC 2.3 - FIX VALUEERROR)
# ==========================================
le = LabelEncoder()
y = le.fit_transform(y)

# Lọc bỏ các lớp có ít hơn 6 mẫu để thỏa mãn điều kiện Stratify và SMOTE[cite: 1]
class_counts = pd.Series(y).value_counts()
valid_classes = class_counts[class_counts >= 6].index
mask = np.isin(y, valid_classes)

X = X[mask]
y = y[mask]
print(f"--- Đã lọc dữ liệu. Còn lại {len(valid_classes)} lớp đủ điều kiện huấn luyện ---")

# Chia tập dữ liệu
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Chuẩn hóa
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# ==========================================
# 4. CÂN BẰNG DỮ LIỆU (SMOTE)[cite: 1]
# ==========================================
print("--- Đang thực hiện cân bằng dữ liệu (Vui lòng đợi...) ---")
over = SMOTE(sampling_strategy='auto', random_state=42)
under = RandomUnderSampler(sampling_strategy='auto', random_state=42)
resample_pipeline = Pipeline(steps=[('o', over), ('u', under)])

X_train_res, y_train_res = resample_pipeline.fit_resample(X_train, y_train)

# ==========================================
# 5. HUẤN LUYỆN & ĐÁNH GIÁ (MỤC 2.5)[cite: 1]
# ==========================================
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "SVM": LinearSVC(dual=False),
    "Naive Bayes": GaussianNB(),
    "KNN": KNeighborsClassifier(),
    "Random Forest": RandomForestClassifier(n_estimators=100)
}

for name, model in models.items():
    print(f"\nHuấn luyện mô hình: {name}")
    model.fit(X_train_res, y_train_res)
    y_pred = model.predict(X_test)
    current_classes = le.inverse_transform(np.unique(y_test))
    print(classification_report(y_test, y_pred, target_names=current_classes))

# ==========================================
# 6. LƯU MÔ HÌNH & CẢNH BÁO (MỤC 2.6)[cite: 1]
# ==========================================
if not os.path.exists('model'):
    os.makedirs('model')

# Lưu Random Forest theo yêu cầu lab[cite: 1]
joblib.dump(models["Random Forest"], 'model/best_rf_model.pkl')
joblib.dump(scaler, 'model/scaler.pkl')
joblib.dump(le, 'model/label_encoder.pkl')

def generate_alert(flow_data):
    """Mô phỏng cảnh báo thời gian thực[cite: 1]"""
    data_scaled = scaler.transform(flow_data)
    prediction = models["Random Forest"].predict(data_scaled)
    label_name = le.inverse_transform(prediction)[0]
    
   # Chuyển về chữ hoa để so sánh chính xác, tránh lỗi khớp chuỗi
    if label_name.upper() != 'BENIGN':
        msg = f"[ALERT] Suspicious traffic detected: {label_name}."
        print(msg)
        with open('alerts.log', 'a', encoding='utf-8') as f:
            f.write(msg + "\n")
    else:
        # Nếu là lưu lượng sạch thì không đưa vào alerts.log
        print(f"Lưu lượng: {label_name} (An toàn)")

print("\n--- Thử nghiệm Real-time Alert ---")
test_sample = X.iloc[[0]] 
generate_alert(test_sample)