# Python Static Analyzer (PyScan)

Một công cụ phân tích tĩnh (SAST) gọn nhẹ, được viết hoàn toàn bằng Python. Công cụ này được thiết kế để phát hiện các lỗ hổng bảo mật, lỗi logic và các vấn đề về kiểu dáng (style) trong mã nguồn Python.



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

Bash

python cli.py path/to/file_or_dir --out-html report.html --out-json report.json
3. Chạy Giao diện Web (Web UI)
(Giả sử bạn có một app.py để chạy máy chủ web, dựa trên demo)

Bash

# Cài đặt máy chủ (ví dụ)
pip install Flask
# Chạy máy chủ
python app.py
Sau đó, mở http://127.0.0.1:5000 trên trình duyệt của bạn.

🛠️ Hệ thống Quy tắc
Hệ thống quy tắc được phân chia theo 3 engine:

Quy tắc Regex (Tùy chỉnh):

Chỉnh sửa tệp custom_rules.json để thêm/xóa/sửa các quy tắc cho Engine 1.

Tệp này lý tưởng cho việc tìm kiếm các từ khóa cụ thể, bí mật (secrets), hoặc các mẫu code đơn giản.

Quy tắc Linting (Hardcode):

Các quy tắc về chất lượng code và logic được định nghĩa trực tiếp trong tệp analyzer/ast_rules.py.

Quy tắc Bảo mật Lõi (Hardcode):

Các quy tắc bảo mật chuyên sâu (bao gồm các "Sink" cho Taint Analysis) được định nghĩa trực tiếp trong tệp analyzer/core.py (bên trong lớp Analyzer).

🔎 Công cụ Gợi ý Quy tắc (Rule Discovery)
Dự án bao gồm một công cụ hỗ trợ (rule_discovery.py) để giúp bạn tạo các quy tắc regex mới từ một cơ sở mã nguồn hiện có.

Nó quét mã nguồn của bạn để tìm các mẫu lặp lại và tạo ra một tệp candidates.json.

Cách chạy:

Bash

python rule_discovery.py path/to/your_code --out candidates.json --min-count 2
Sau đó, bạn có thể xem lại tệp candidates.json, chọn các mẫu hữu ích và sao chép chúng vào tệp custom_rules.json chính của bạn.

🧪 Kiểm thử (Testing)
Dự án sử dụng pytest để kiểm thử.

Bash

# Cài đặt pytest
pip install pytest

# Chạy toàn bộ bộ test
pytest
