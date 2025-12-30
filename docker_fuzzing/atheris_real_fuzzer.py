#!/usr/bin/env python3
"""
REAL Atheris Fuzzer Wrapper - v7.0 (Fixed Instrumentation & Error Reporting)
"""

import sys
import os
import time
import subprocess
import tempfile
import re
from pathlib import Path

class RealAtherisFuzzer:
    def __init__(self, target_code: str, output_dir: str = "/fuzzing"):
        self.target_code = target_code
        self.output_dir = output_dir
        self.corpus_dir = Path(output_dir) / "corpus"
        self.crashes_dir = Path(output_dir) / "crashes"
        self.results_dir = Path(output_dir) / "results"
        
        # Tạo thư mục nếu chưa có
        for p in [self.corpus_dir, self.crashes_dir, self.results_dir]:
            p.mkdir(parents=True, exist_ok=True)

    def run(self):
        print(f"[RealAtheris] Preparing to fuzz...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # 1. Lưu code của user
            target_path = os.path.join(temp_dir, "target_module.py")
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(self.target_code)
            
            # 2. Tạo Runner Script (QUAN TRỌNG: Thêm instrument_all)
            runner_content = f"""
import sys
import os
import atheris
import traceback

# === CRITICAL: INSTRUMENTATION MUST BE FIRST ===
# Giúp Atheris nhìn thấy các lệnh if/else trong code của user
try:
    atheris.instrument_all()
except Exception as e:
    print(f"INSTRUMENTATION_ERROR: {{e}}")

# Thêm đường dẫn hiện tại
sys.path.append(os.getcwd())

# === IMPORT TARGET ===
try:
    # Patch để tránh target_module tự chạy main() nếu không có if __name__ == "__main__"
    import target_module
except Exception as e:
    print(f"IMPORT_ERROR: {{e}}")
    traceback.print_exc()
    sys.exit(1)

# === FIND ENTRY POINT ===
target_func = None

if hasattr(target_module, "TestOneInput"):
    target_func = target_module.TestOneInput
    print("ENTRY_POINT: TestOneInput")
elif hasattr(target_module, "vulnerable_function"):
    def harness(data):
        target_module.vulnerable_function(data)
    target_func = harness
    print("ENTRY_POINT: vulnerable_function (Wrapped)")
else:
    # Fallback cho hàm main hoặc fuzzing ngẫu nhiên
    def dummy_harness(data):
        pass
    target_func = dummy_harness
    print("WARNING: No explicit entry point found")

def run_fuzzer():
    try:
        # Chuẩn bị arguments cho libFuzzer
        # sys.argv đã được truyền từ subprocess
        print("Starting Atheris Setup...")
        atheris.Setup(sys.argv, target_func)
        print("Starting Atheris Fuzz...")
        atheris.Fuzz()
    except Exception as e:
        # Bắt lỗi Runtime (như ZeroDivisionError) và in ra để parse
        print(f"CRASH_DETECTED: {{e}}")
        traceback.print_exc()
        sys.exit(99) # Exit code đặc biệt cho crash

if __name__ == "__main__":
    run_fuzzer()
"""
            runner_path = os.path.join(temp_dir, "fuzz_runner.py")
            with open(runner_path, 'w') as f:
                f.write(runner_content)
            
            # 3. Chạy lệnh Fuzz
            # -runs=200000: Tăng số lần chạy để đảm bảo tìm thấy lỗi
            cmd = [
                sys.executable, runner_path,
                "-runs=200000",             
                str(self.corpus_dir),      
                "-max_len=2048",
                "-verbosity=1" # Ít log rác hơn
            ]
            
            print(f"[RealAtheris] Executing subprocess...")
            start_time = time.time()
            
            try:
                process = subprocess.run(
                    cmd,
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=30 # Timeout 30 giây
                )
                stdout = process.stdout
                stderr = process.stderr
                returncode = process.returncode
                
            except subprocess.TimeoutExpired as e:
                print("⚠️ Fuzzing timed out (Limit reached)")
                stdout = e.stdout if e.stdout else ""
                stderr = e.stderr if e.stderr else ""
                returncode = 0

            duration = time.time() - start_time
            return self._parse_results(stdout, stderr, returncode, duration)

    def _parse_results(self, stdout, stderr, returncode, duration):
        full_log = stdout + "\n" + stderr
        crashes = []
        
        # Debug: Ghi log ra console của Docker để bạn check nếu cần
        print("=== FUZZER OUTPUT START ===")
        print(full_log[-2000:]) # In 2000 ký tự cuối
        print("=== FUZZER OUTPUT END ===")

        # 1. Kiểm tra lỗi Import/Hệ thống
        if "IMPORT_ERROR" in full_log:
            return self._error_response("Lỗi khi import file Python của bạn. Hãy kiểm tra cú pháp.")
        
        # 2. Phân tích lỗi Crash (Runtime Errors)
        # Tìm dòng Traceback
        if "Traceback (most recent call last):" in full_log or "CRASH_DETECTED" in full_log:
            # Dùng Regex để bắt tên lỗi (Ví dụ: ZeroDivisionError: integer division or modulo by zero)
            # Regex tìm dòng dạng "TênLỗi: Thông báo" ở cuối traceback
            matches = re.findall(r'^(\w+Error): (.*)$', full_log, re.MULTILINE)
            
            if matches:
                for err_name, err_msg in matches:
                    # Loại bỏ các lỗi giả
                    if err_name not in ["ImportError", "SystemExit"]:
                        crashes.append({
                            "type": err_name,
                            "message": err_msg,
                            "severity": "critical"
                        })
            
            # Nếu Regex trượt, lấy dòng cuối cùng
            if not crashes and "CRASH_DETECTED" in full_log:
                 crashes.append({
                    "type": "Runtime Crash",
                    "message": "Fuzzer crashed the application",
                    "severity": "critical"
                })

        # Loại bỏ crash trùng lặp
        unique_crashes = {f"{c['type']}:{c['message']}": c for c in crashes}.values()

        return {
            'iterations': 200000, # Ước lượng
            'crashes': list(unique_crashes),
            'vulnerabilities': [
                {
                    "type": c["type"],
                    "line": 0, # Khó xác định chính xác dòng qua log text
                    "message": c["message"],
                    "severity": "critical",
                    "file": "uploaded_file.py"
                } for c in unique_crashes
            ],
            'total_crashes': len(unique_crashes),
            'risk_score': 100 if unique_crashes else 0,
            'execution_time': duration,
            'log_snippet': full_log[:500] # Gửi kèm một chút log để debug trên web
        }

    def _error_response(self, msg):
        return {
            'iterations': 0, 'crashes': [], 'vulnerabilities': [], 'risk_score': 0,
            'error': msg
        }