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

## 📦 Cài Đặt

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