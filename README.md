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
