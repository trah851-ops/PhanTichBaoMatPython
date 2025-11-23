# analyzer/core.py - FIXED VERSION
import ast
import io
import re
import tokenize
from functools import lru_cache
from typing import List, Dict
from .ast_rules import ASTLinter
from .taint import TaintAnalyzer

class Analyzer:
    def __init__(self):
        # Regex patterns
        self.regex_patterns = {
            "hardcoded_password": r"(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "dangerous_func": r"\b(eval|exec|os\.system|subprocess\.(Popen|run|call))\b",
            "hardcoded_secret": r"(secret|token|key)\s*=\s*['\"][A-Za-z0-9+/=]{20,}['\"]"
        }
        
        # Taint sources & sinks
        self.taint_sources = [
            "input", "raw_input", "sys.argv", "os.getenv", "os.environ",
            "request.args", "request.form", "request.json", "request.cookies"
        ]
        
        self.taint_sinks = [
            "os.system", "subprocess.run", "subprocess.Popen", 
            "eval", "exec", "pickle.loads", "yaml.load", "open"
        ]

    def analyze_file(self, file_path: str) -> List[Dict]:
        """Phân tích một file Python"""
        issues = []
        
        # Đọc file
        code = self._read_file(file_path)
        if not code:
            return [{"type": "error", "message": "Không đọc được file", "file": file_path}]

        # 1. Regex scan
        issues.extend(self._regex_scan(code, file_path))

        # 2. AST Linter
        try:
            tree = ast.parse(code, filename=file_path)
            linter = ASTLinter(tree, code, file_path)
            issues.extend(linter.lint())
            
            # 3. Taint analysis - FIX: Truyền đúng tham số
            taint = TaintAnalyzer(tree, self.taint_sources, self.taint_sinks, file_path)
            issues.extend(taint.analyze())
        except SyntaxError as e:
            issues.append({
                "type": "syntax_error", 
                "message": f"Lỗi cú pháp: {str(e)}", 
                "file": file_path,
                "line": e.lineno or 1
            })
        except Exception as e:
            issues.append({
                "type": "parse_error", 
                "message": str(e), 
                "file": file_path
            })

        return issues

    def _read_file(self, path: str) -> str | None:
        """Đọc file với nhiều encoding"""
        encodings = ['utf-8', 'latin-1', 'cp1252']
        for encoding in encodings:
            try:
                with open(path, "r", encoding=encoding) as f:
                    return f.read()
            except:
                continue
        return None

    def _regex_scan(self, code: str, file_path: str) -> List[Dict]:
        """Quét code bằng regex"""
        issues = []
        lines = code.split('\n')
        
        for line_no, line in enumerate(lines, 1):
            for name, pattern in self.regex_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "regex",
                        "category": name,
                        "message": f"PHÁT HIỆN: {name.replace('_', ' ').upper()}!",
                        "line": line_no,
                        "file": file_path,
                        "severity": "critical" if "password" in name or "key" in name else "high"
                    })
        return issues