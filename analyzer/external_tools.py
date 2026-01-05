import subprocess
import json
import sys
import shutil

def run_external_scans(file_path):
    issues = []
    
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
                    issues.append({
                        "type": "external_bandit",
                        "category": res["issue_text"],
                        "severity": res["issue_severity"].lower(),
                        "message": res['issue_text'],
                        "line": res["line_number"],
                        "file": file_path,
                        "recommendation": "Tham khảo tài liệu bảo mật của Bandit."
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
                        # Mapping lỗi Flake8 sang mức độ nghiêm trọng
                        sev = "low"
                        if msg.startswith("F"): sev = "high" # Logic error
                        elif msg.startswith("E9"): sev = "critical" # Syntax
                        
                        issues.append({
                            "type": "external_flake8",
                            "category": "style_logic",
                            "severity": sev,
                            "message": msg,
                            "line": int(parts[1]),
                            "file": file_path,
                            "recommendation": "Tuân thủ chuẩn PEP8 và sửa lỗi logic."
                        })
        except Exception:
            pass

    return issues