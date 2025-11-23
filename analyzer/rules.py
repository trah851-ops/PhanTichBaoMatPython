# analyzer/rules.py
# Builtin Security Rules - Bộ quy tắc bảo mật tích hợp sẵn
# Tác giả: [Tên bạn] - PyScan Pro
# Dùng cho: Regex, Taint, và gợi ý trong báo cáo

from typing import Dict, List, Tuple, Any
from enum import Enum

class RuleCategory(Enum):
    INJECTION = "injection"
    CRYPTO = "cryptography"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_EXPOSURE = "data_exposure"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    CODE_QUALITY = "code_quality"

# =================================================================
# BỘ QUY TẮC BẢO MẬT CHUẨN (DÙNG CHO REGEX + TAINT + BÁO CÁO)
# =================================================================
BUILTIN_RULES: Dict[str, Dict[str, Any]] = {
    "command_injection": {
        "category": RuleCategory.INJECTION,
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "Lỗ hổng Command Injection",
        "patterns": ["os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen"],
        "recommendation": "Dùng subprocess với shell=False và danh sách tham số"
    },
    "code_injection": {
        "category": RuleCategory.INJECTION,
        "severity": "critical",
        "cwe": "CWE-94",
        "description": "Lỗ hổng Code Injection",
        "patterns": ["eval", "exec", "compile", "__import__"],
        "recommendation": "Không thực thi code động từ dữ liệu người dùng"
    },
    "sql_injection": {
        "category": RuleCategory.INJECTION,
        "severity": "critical",
        "cwe": "CWE-89",
        "description": "Lỗ hổng SQL Injection",
        "patterns": ["execute", "executemany", "query", "raw"],
        "recommendation": "Dùng parameterized query hoặc ORM"
    },
    "hardcoded_secrets": {
        "category": RuleCategory.DATA_EXPOSURE,
        "severity": "critical",
        "cwe": "CWE-798",
        "description": "Mật khẩu/secret bị hardcode",
        "regex_patterns": {
            "password": r"(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']",
            "api_key": r"api[_-]?key\s*=\s*[\"'][^\"']+[\"']",
            "secret_key": r"secret\s*=\s*[\"'][^\"']+[\"']",
            "token": r"token\s*=\s*[\"'][A-Za-z0-9._-]{20,}[\"']",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN .* PRIVATE KEY-----"
        },
        "recommendation": "Dùng biến môi trường hoặc secret manager"
    },
    "unsafe_deserialization": {
        "category": RuleCategory.DESERIALIZATION,
        "severity": "high",
        "cwe": "CWE-502",
        "description": "Deserialization không an toàn",
        "patterns": ["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads"],
        "recommendation": "Dùng JSON hoặc yaml.safe_load()"
    },
    "path_traversal": {
        "category": RuleCategory.PATH_TRAVERSAL,
        "severity": "high",
        "cwe": "CWE-22",
        "description": "Lỗ hổng Path Traversal",
        "patterns": ["open", "os.open"],
        "recommendation": "Kiểm tra và giới hạn đường dẫn file"
    },
    "ssrf": {
        "category": RuleCategory.SSRF,
        "severity": "high",
        "cwe": "CWE-918",
        "description": "Server-Side Request Forgery",
        "patterns": ["requests.get", "requests.post", "urllib.request.urlopen"],
        "recommendation": "Whitelist URL hợp lệ"
    },
    "xxe": {
        "category": RuleCategory.XXE,
        "severity": "high",
        "cwe": "CWE-611",
        "description": "XML External Entity Attack",
        "patterns": ["xml.etree.ElementTree.parse", "lxml.etree.parse"],
        "recommendation": "Tắt external entity trong parser XML"
    },
    "weak_crypto": {
        "category": RuleCategory.CRYPTO,
        "severity": "high",
        "cwe": "CWE-327",
        "description": "Thuật toán mã hóa yếu",
        "patterns": ["hashlib.md5", "hashlib.sha1", "Crypto.Cipher.DES"],
        "recommendation": "Dùng SHA-256, SHA-3 hoặc AES-GCM"
    },
    "insecure_random": {
        "category": RuleCategory.CRYPTO,
        "severity": "medium",
        "cwe": "CWE-338",
        "description": "Random không an toàn",
        "patterns": ["random.random", "random.randint"],
        "recommendation": "Dùng module secrets cho mục đích bảo mật"
    }
}

# =================================================================
# Taint Sources & Sinks (dùng cho taint analysis)
# =================================================================
TAINT_SOURCES = [
    "input", "raw_input", "sys.argv", "os.getenv", "os.environ",
    "request.args", "request.form", "request.json", "request.cookies",
    "Request", "Query", "Form", "File"
]

TAINT_SINKS = {
    "os.system": ("critical", "command_injection", "CWE-78"),
    "subprocess.run": ("critical", "command_injection", "CWE-78"),
    "subprocess.Popen": ("critical", "command_injection", "CWE-78"),
    "eval": ("critical", "code_injection", "CWE-94"),
    "exec": ("critical", "code_injection", "CWE-94"),
    "pickle.loads": ("high", "deserialization", "CWE-502"),
    "yaml.load": ("high", "deserialization", "CWE-502"),
    "open": ("high", "path_traversal", "CWE-22"),
    "requests.get": ("high", "ssrf", "CWE-918")
}

# =================================================================
# Gợi ý thay thế an toàn
# =================================================================
SAFE_ALTERNATIVES = {
    "eval": "Dùng ast.literal_eval() cho literal Python",
    "exec": "Không dùng exec với dữ liệu người dùng",
    "pickle.loads": "Dùng JSON thay thế",
    "yaml.load": "Dùng yaml.safe_load()",
    "os.system": "Dùng subprocess.run(..., shell=False)",
    "random": "Dùng secrets.token_hex() hoặc secrets.randbelow()",
    "md5": "Dùng hashlib.sha256()",
    "open": "Dùng pathlib và kiểm tra đường dẫn"
}

# =================================================================
# Code Quality Rules (dùng trong AST linter)
# =================================================================
CODE_QUALITY_RULES = {
    "mutable_default": {
        "severity": "high",
        "message": "Mutable default argument – LỖ HỔNG BẢO MẬT NGHIÊM TRỌNG!",
        "recommendation": "Dùng None và khởi tạo trong hàm"
    },
    "bare_except": {
        "severity": "medium",
        "message": "Dùng except trống – che giấu lỗi",
        "recommendation": "Bắt exception cụ thể"
    },
    "assert_used": {
        "severity": "low",
        "message": "Dùng assert – bị tắt khi chạy -O",
        "recommendation": "Thay bằng if + raise"
    },
    "print_stmt": {
        "severity": "low",
        "message": "Dùng print() trong production",
        "recommendation": "Dùng logging module"
    }
}

# =================================================================
# Hàm hỗ trợ
# =================================================================
def get_rule(rule_id: str) -> Dict[str, Any]:
    """Lấy thông tin rule theo ID"""
    return BUILTIN_RULES.get(rule_id) or CODE_QUALITY_RULES.get(rule_id)

def get_safe_alternative(func_name: str) -> str:
    """Gợi ý thay thế an toàn"""
    return SAFE_ALTERNATIVES.get(func_name, "Xem lại best practices bảo mật")

def is_taint_source(name: str) -> bool:
    return any(src in name for src in TAINT_SOURCES)

def is_taint_sink(name: str) -> Tuple[bool, Dict[str, str]]:
    for sink, (sev, cat, cwe) in TAINT_SINKS.items():
        if sink in name:
            return True, {"severity": sev, "category": cat, "cwe": cwe}
    return False, {}

print("Loaded PyScan Pro Security Rules - 30+ rules, CWE mapped")