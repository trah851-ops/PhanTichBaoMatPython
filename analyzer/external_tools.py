# analyzer/external_tools.py
import subprocess
import json
import sys
import shutil

def run_external_scans(file_path):
    issues = []
    
    # Đọc file để lấy code context
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code_lines = f.readlines()
    except:
        code_lines = []
    
    # 1. BANDIT (Security Scan)
    if shutil.which("bandit"):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-f", "json", "-q", file_path],
                capture_output=True, text=True
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for res in data.get("results", []):
                    line_num = res["line_number"]
                    
                    # ✅ Thêm code context
                    code_context = _get_code_context(code_lines, line_num, 2)
                    
                    issues.append({
                        "type": "external_bandit",
                        "category": res["issue_text"],
                        "severity": res["issue_severity"].lower(),
                        "message": res['issue_text'],
                        "line": line_num,
                        "file": file_path,
                        "recommendation": "Tham khảo tài liệu bảo mật của Bandit.",
                        "code": code_context  # ✅ THÊM
                    })
        except Exception:
            pass

    # 2. FLAKE8 (Style & Logic Scan)
    if shutil.which("flake8"):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "flake8", "--format=default", file_path],
                capture_output=True, text=True
            )
            if result.stdout:
                for line in result.stdout.splitlines():
                    parts = line.split(":", 3)
                    if len(parts) >= 4:
                        msg = parts[3].strip()
                        line_num = int(parts[1])
                        
                        # Mapping lỗi Flake8 sang mức độ nghiêm trọng
                        sev = "low"
                        if msg.startswith("F"): sev = "high"
                        elif msg.startswith("E9"): sev = "critical"
                        
                        # ✅ Thêm code context
                        code_context = _get_code_context(code_lines, line_num, 2)
                        
                        issues.append({
                            "type": "external_flake8",
                            "category": "style_logic",
                            "severity": sev,
                            "message": msg,
                            "line": line_num,
                            "file": file_path,
                            "recommendation": "Tuân thủ chuẩn PEP8 và sửa lỗi logic.",
                            "code": code_context  # ✅ THÊM
                        })
        except Exception:
            pass

    return issues


def _get_code_context(lines, error_line, context=2):
    """Lấy code context xung quanh dòng lỗi"""
    if not lines:
        return ""
    
    start = max(0, error_line - context - 1)
    end = min(len(lines), error_line + context)
    
    result = []
    for i in range(start, end):
        line_num = i + 1
        line_content = lines[i].rstrip()
        result.append(f"{line_num}: {line_content}")
    
    return "\n".join(result)