<<<<<<< HEAD
# 🔒 PyScan Pro - Python Security Analyzer

**PyScan Pro** là công cụ phân tích bảo mật tĩnh (SAST) cho Python, tích hợp:
- ✅ AST Analysis (phân tích cú pháp)
- ✅ Taint Tracking (theo dõi luồng dữ liệu nguy hiểm)
- ✅ Pattern Matching (regex cho hardcoded secrets)
- ✅ Code Quality Checks
- ✅ Fuzzing Support
- ✅ Web Interface (Flask)
- ✅ HTML/JSON Reports

---
=======
# Python Static Analyzer (PyScan)

Một công cụ phân tích tĩnh (SAST) gọn nhẹ, được viết hoàn toàn bằng Python. Công cụ này được thiết kế để phát hiện các lỗ hổng bảo mật, lỗi logic và các vấn đề về kiểu dáng (style) trong mã nguồn Python.
>>>>>>> 9d8e0e8b3d48df05c76f3d41b247b074266c6379

## 📦 Cài Đặt

<<<<<<< HEAD
### 1. Clone hoặc tải project

```bash
cd python_static_analyzer_pro
```

### 2. Tạo virtual environment (khuyên dùng)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### 4. (Optional) Cài Atheris cho fuzzing

```bash
pip install atheris
```

---

## 🚀 Chạy Ứng Dụng

### Cách 1: Web Interface (Khuyên dùng)

```bash
python app.py
```

Mở trình duyệt: **http://127.0.0.1:5000**

### Cách 2: CLI (Command Line)

```bash
# Quét 1 file
python cli.py test_vulnerable.py

# Quét toàn bộ project
python cli.py .

# Xuất báo cáo HTML
python cli.py . --out-html report.html --verbose

# Chạy fuzzing
python cli.py --fuzz
```

---

## 🎯 Các Tính Năng

### 1. **Paste Code**
- Dán code Python trực tiếp vào web
- Phân tích ngay lập tức
- Hiển thị lỗi theo dòng

### 2. **Upload File**
- Upload file .py
- Quét và tạo báo cáo

### 3. **Scan Project**
- Quét toàn bộ thư mục project
- Bỏ qua `venv`, `__pycache__`, `.git`
- Báo cáo tổng hợp

### 4. **Fuzzing**
- Test analyzer với payload ngẫu nhiên
- Tìm edge cases
- Cần cài `atheris`

---

## 🔍 Các Lỗi Được Phát Hiện

### 🚨 Critical
- Hardcoded passwords/secrets
- SQL Injection
- Command Injection (os.system, eval, exec)
- Code Injection

### ⚠️ High
- Unsafe deserialization (pickle, yaml)
- Path Traversal
- SSRF (requests với user input)
- Weak cryptography (MD5, SHA1)

### 📝 Medium
- Bare except (che giấu lỗi)
- Mutable default arguments
- Global variable usage
- Open file without context manager

### ℹ️ Low
- Unused imports/variables
- Missing docstrings
- Print statements in production
- Assert usage

---

## 📊 Ví Dụ

### Code có lỗi:

```python
import os

# CRITICAL: Hardcoded password
password = "admin123"

# CRITICAL: Command injection
user_input = input("Enter command: ")
os.system(user_input)

# HIGH: Mutable default
def add_item(item, items=[]):
    items.append(item)
    return items

# MEDIUM: Bare except
try:
    risky_operation()
except:
    pass
```

### Kết quả quét:

```
[CRITICAL] Dòng 4: PHÁT HIỆN: HARDCODED PASSWORD!
[CRITICAL] Dòng 8: NGUY HIỂM: Dữ liệu tainted → os.system()
[HIGH] Dòng 11: Lỗi HỎNG BẢO MẬT: Mutable default argument
[MEDIUM] Dòng 16: Dùng except trống – bắt tất cả lỗi
```

---

## 📁 Cấu Trúc Project

```
python_static_analyzer_pro/
├── analyzer/
│   ├── __init__.py
│   ├── core.py          # Main analyzer
│   ├── ast_rules.py     # AST linting rules
│   ├── taint.py         # Taint analysis
│   ├── fuzzing.py       # Fuzzing engine
│   └── rules.py         # Security rules database
├── templates/
│   └── index.html       # Web UI
├── uploads/             # Uploaded files (auto-created)
├── web_reports/         # Generated reports (auto-created)
├── app.py               # Flask web app
├── cli.py               # Command line interface
├── requirements.txt
└── README.md
```

---

## 🛠️ Development

### Chạy tests (nếu có)

```bash
pytest tests/ -v
```

### Thêm rule mới

Edit `analyzer/rules.py` và thêm vào `BUILTIN_RULES`:

```python
"new_rule": {
    "category": RuleCategory.INJECTION,
    "severity": "high",
    "cwe": "CWE-XXX",
    "description": "Mô tả lỗi",
    "patterns": ["pattern1", "pattern2"],
    "recommendation": "Cách sửa"
}
```

---

## 📝 TODO / Cải Tiến

- [ ] Thêm support cho Python 3.12
- [ ] Tích hợp với CI/CD (GitHub Actions)
- [ ] Machine Learning cho phát hiện lỗi
- [ ] Plugin cho VS Code
- [ ] Docker support
- [ ] Real-time scanning

---

## 🤝 Đóng Góp

Mọi đóng góp đều được chào đón! Hãy:
1. Fork repo
2. Tạo branch mới
3. Commit changes
4. Push và tạo Pull Request

---

## 📄 License

MIT License - Tự do sử dụng cho mọi mục đích

---

## 📧 Liên Hệ

- **Author**: [Tên bạn]
- **Email**: your.email@example.com
- **GitHub**: https://github.com/yourusername

---

## 🎓 Dự Án Tốt Nghiệp

Đây là đồ án tốt nghiệp về **An Toàn Thông Tin** - chủ đề **Static Application Security Testing (SAST) cho Python**.

**Điểm mạnh:**
- ✅ Tích hợp 3 kỹ thuật phân tích (AST + Taint + Regex)
- ✅ Web interface đẹp và dễ dùng
- ✅ Báo cáo HTML chuyên nghiệp
- ✅ Hỗ trợ fuzzing
- ✅ CLI và Web đều có
- ✅ Mã nguồn sạch, có comments

**Công nghệ sử dụng:**
- Python 3.9+
- Flask (Web Framework)
- AST (Abstract Syntax Tree)
- Taint Analysis
- Regex Pattern Matching
- (Optional) Atheris Fuzzing

---

Made with ❤️ by [Your Name]
=======

---

## 🚀 Tính năng nổi bật

* **Kiến trúc Lai (Hybrid):** Kết hợp 3 engine phân tích khác nhau để đạt độ bao phủ tối đa.
* **Phân tích Taint (Taint Analysis):** Tích hợp engine theo dõi luồng dữ liệu (`taint.py`) để phát hiện các lỗ hổng nghiêm trọng như Command Injection, bằng cách theo dõi dữ liệu từ các "Nguồn" (như `input()`) đến các "Đích" (như `os.system`).
* **Engine Regex Thông minh:** Engine Regex (trong `core.py`) sử dụng `tokenize` để tự động bỏ qua các kết quả trong chuỗi (string) và bình luận (comment), giúp giảm đáng kể báo động sai (False Positive).
* **Engine AST Linting:** Một engine (`ast_rules.py`) chuyên phát hiện các lỗi logic, "code smell" và các vấn" "đề bảo trì (ví dụ: biến không sử dụng, `import` không sử dụng, `open()` không có `with`).
* **Khả năng tùy chỉnh:** Cho phép người dùng cung cấp tệp quy tắc JSON tùy chỉnh (`custom_rules.json`) cho Engine Regex.

---

## ⚙️ Kiến trúc hệ thống

PyScan sử dụng kiến trúc lai 3-engine chạy song song, được điều phối bởi `core.py`:

1.  **Engine 1: Phân tích Regex (Dựa trên `custom_rules.json`)**
    * Quét văn bản thô của mã nguồn.
    * Tìm kiếm các mẫu bề mặt như bí mật (ví dụ: `AKIA...`), mật khẩu hardcode, `TODO/FIXME`, và các hàm nguy hiểm đơn giản.
    * Đây là engine duy nhất hoạt động ngay cả khi mã nguồn bị lỗi cú pháp (`SyntaxError`).

2.  **Engine 2: Phân tích AST Linting (Dựa trên `ast_rules.py`)**
    * Phân tích Cây Cú pháp Trừu tượng (AST) để tìm các lỗi cấu trúc và logic.
    * Phát hiện các vấn đề như: biến/import không sử dụng, `bare except`, đối số mặc định có thể thay đổi (mutable default arguments), hàm quá dài, v.v..

3.  **Engine 3: Core SAST & Taint Analysis (Dựa trên `core.py` + `taint.py`)**
    * Đây là engine bảo mật cốt lõi, tích hợp chặt chẽ `AdvancedTaintEngine`.
    * Nó xác định các "Sink" (Đích) nguy hiểm như `eval()`, `exec()`, `subprocess.run(shell=True)`, `pickle`, `yaml.load`.
    * Quan trọng nhất, nó truy vấn Engine Taint để kiểm tra xem có dữ liệu "nhiễm độc" nào (từ `input()`) được truyền vào các Sink này hay không, cho phép phát hiện Command Injection.

---

## 🏃 Hướng dẫn nhanh (Quickstart)

### 1. Cài đặt

Chỉ cần clone repository này. Dự án không yêu cầu thư viện bên ngoài để chạy (chỉ sử dụng các thư viện tích hợp sẵn của Python).

```bash
git clone [URL_CỦA_REPOSITORY]
cd python_static_analyzer
2. Chạy qua dòng lệnh (CLI)
Bạn có thể chạy phân tích trực tiếp trên một tệp hoặc một thư mục. Kết quả có thể được xuất ra tệp HTML (để xem) và JSON (cho CI/CD).

2️⃣ Chạy qua dòng lệnh (CLI)

Bạn có thể phân tích trực tiếp một tệp hoặc thư mục.
Kết quả có thể xuất ra HTML (xem trực quan) và JSON (cho CI/CD).

python cli.py path/to/file_or_dir --out-html report.html --out-json report.json

3️⃣ Chạy Giao diện Web (Web UI)

Ví dụ: bạn có app.py để chạy máy chủ Flask.

# Cài đặt Flask (nếu chưa có)
pip install Flask

# Chạy máy chủ
python app.py


Sau đó, mở trình duyệt và truy cập:

👉 http://127.0.0.1:5000

🛠️ Hệ thống Quy tắc (Rule System)

Hệ thống quy tắc được chia làm 3 loại, tương ứng với 3 engine:

1. Quy tắc Regex (tùy chỉnh)

Lưu trong custom_rules.json

Dành cho việc tìm mẫu chuỗi, secrets, hoặc từ khóa nguy hiểm

Có thể thêm mới hoặc điều chỉnh linh hoạt.

2. Quy tắc Linting (AST)

Được định nghĩa sẵn trong analyzer/ast_rules.py

Kiểm tra chất lượng và logic code.

3. Quy tắc Bảo mật Cốt lõi (SAST)

Định nghĩa trong analyzer/core.py (trong lớp Analyzer)

Bao gồm các Sink và Taint Source cho phân tích luồng dữ liệu.


🧪 Kiểm thử (Testing)

Dự án sử dụng pytest để kiểm thử tự động.

# Cài đặt pytest
pip install pytest

# Chạy toàn bộ bộ test
pytest
>>>>>>> 9d8e0e8b3d48df05c76f3d41b247b074266c6379
