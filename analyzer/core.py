# core.py - FULLY INTEGRATED WITH ALL SECURITY CHECKS
import ast
import os
import json
import yaml
import xml.etree.ElementTree as ET
import configparser
from typing import List, Dict, Any
import re

from .ast_rules import ASTLinter
from .taint import TaintAnalyzer
from .sca import DependencyScanner
from .external_tools import run_external_scans

# Import advanced modules if available
try:
    from .advanced_security import analyze_advanced_security
    ADVANCED_SECURITY_AVAILABLE = True
except ImportError:
    ADVANCED_SECURITY_AVAILABLE = False
    print("[WARNING] Advanced security module not available")

try:
    from .metrics import analyze_code_metrics
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

try:
    from .dataflow import analyze_data_flow
    DATAFLOW_AVAILABLE = True
except ImportError:
    DATAFLOW_AVAILABLE = False


class FileTypeAnalyzer:
    """Phân tích các loại file khác nhau"""
    
    @staticmethod
    def analyze_config_file(file_path: str, content: str) -> List[Dict]:
        """Phân tích file cấu hình"""
        issues = []
        try:
            if file_path.endswith('.json'):
                data = json.loads(content)
                issues.extend(FileTypeAnalyzer._analyze_json_config(data, file_path))
            
            elif file_path.endswith(('.yaml', '.yml')):
                data = yaml.safe_load(content)
                issues.extend(FileTypeAnalyzer._analyze_yaml_config(data, file_path, content))
            
            elif file_path.endswith(('.ini', '.cfg')):
                config = configparser.ConfigParser()
                config.read_string(content)
                issues.extend(FileTypeAnalyzer._analyze_ini_config(config, file_path))
            
            elif file_path.endswith('.xml'):
                root = ET.fromstring(content)
                issues.extend(FileTypeAnalyzer._analyze_xml_config(root, file_path))
            
        except Exception as e:
            issues.append({
                "type": "config_error",
                "category": "config_parse",
                "severity": "medium",
                "message": f"Không thể phân tích file cấu hình: {str(e)}",
                "line": 1,
                "file": file_path,
                "recommendation": "Kiểm tra cú pháp file cấu hình"
            })
        
        return issues
    
    @staticmethod
    def _analyze_json_config(data: Any, file_path: str) -> List[Dict]:
        issues = []
        
        def traverse_json(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    sensitive_keys = ['password', 'secret', 'token', 'key', 'credential', 'auth']
                    if any(sk in key.lower() for sk in sensitive_keys):
                        if isinstance(value, str) and len(value) > 3:
                            issues.append({
                                "type": "config_analysis",
                                "category": "hardcoded_secret",
                                "severity": "critical",
                                "message": f"Phát hiện secret cứng trong config tại {current_path}",
                                "line": 1,
                                "file": file_path,
                                "recommendation": "Lưu trữ secret trong biến môi trường hoặc vault"
                            })
                    
                    traverse_json(value, current_path)
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    traverse_json(item, f"{path}[{i}]")
        
        traverse_json(data)
        return issues
    
    @staticmethod
    def _analyze_yaml_config(data: Any, file_path: str, content: str = "") -> List[Dict]:
        issues = []
        
        if content and ('!!python' in content or '!python' in content):
            issues.append({
                "type": "config_analysis",
                "category": "yaml_deserialization",
                "severity": "critical",
                "message": "YAML chứa Python object deserialization không an toàn",
                "line": 1,
                "file": file_path,
                "recommendation": "Dùng yaml.safe_load() thay vì yaml.load()"
            })
        
        issues.extend(FileTypeAnalyzer._analyze_json_config(data, file_path))
        return issues
    
    @staticmethod
    def _analyze_xml_config(root: ET.Element, file_path: str) -> List[Dict]:
        issues = []
        
        for elem in root.iter():
            if elem.text and ('SYSTEM' in elem.text or 'ENTITY' in elem.text):
                issues.append({
                    "type": "config_analysis",
                    "category": "xxe_vulnerability",
                    "severity": "high",
                    "message": "XML có thể chứa XXE (XML External Entity) vulnerability",
                    "line": 1,
                    "file": file_path,
                    "recommendation": "Disable external entity processing khi parse XML"
                })
            
            for key, value in elem.attrib.items():
                sensitive_keys = ['password', 'secret', 'token', 'key', 'credential']
                if any(sk in key.lower() for sk in sensitive_keys):
                    if len(value) > 3:
                        issues.append({
                            "type": "config_analysis",
                            "category": "hardcoded_secret",
                            "severity": "critical",
                            "message": f"Phát hiện secret cứng trong XML attribute '{key}'",
                            "line": 1,
                            "file": file_path,
                            "recommendation": "Lưu trữ secret trong biến môi trường"
                        })
        
        return issues
    
    @staticmethod
    def _analyze_ini_config(config: configparser.ConfigParser, file_path: str) -> List[Dict]:
        issues = []
        
        for section in config.sections():
            for key, value in config[section].items():
                sensitive_keys = ['pass', 'secret', 'token', 'key', 'cred']
                if any(sk in key.lower() for sk in sensitive_keys):
                    if len(value) > 3:
                        issues.append({
                            "type": "config_analysis",
                            "category": "hardcoded_secret",
                            "severity": "critical",
                            "message": f"Phát hiện secret cứng trong config [{section}].{key}",
                            "line": 1,
                            "file": file_path,
                            "recommendation": "Lưu trữ secret trong biến môi trường"
                        })
        
        return issues


class DeepCodeAnalyzer:
    """Phân tích code sâu với multiple passes"""
    
    def __init__(self):
        self.taint_sources = [
            "input", "raw_input", "sys.argv", "os.environ", "os.getenv",
            "request.form", "request.args", "request.json", "request.cookies",
            "request.values", "request.files", "request.data", "flask.request",
            "django.http.request"
        ]
        self.taint_sinks = [
            "eval", "exec", "os.system", "os.popen", "subprocess.call", 
            "subprocess.run", "subprocess.Popen", "pickle.loads", "yaml.load",
            "marshal.loads", "sqlite3.execute", "cursor.execute", "open",
            "execfile", "compile", "setattr", "delattr", "__import__"
        ]


class Analyzer:
    def __init__(self, deep_scan: bool = True, enable_advanced: bool = True):
        self.deep_scan = deep_scan
        self.enable_advanced = enable_advanced and ADVANCED_SECURITY_AVAILABLE
        self.file_analyzer = FileTypeAnalyzer()
        self.deep_analyzer = DeepCodeAnalyzer()
        
        self.taint_sources = self.deep_analyzer.taint_sources
        self.taint_sinks = self.deep_analyzer.taint_sinks
        
        # Print available features
        print(f"[PyScan] Deep Scan: {self.deep_scan}")
        print(f"[PyScan] Advanced Security: {self.enable_advanced}")
        print(f"[PyScan] Metrics: {METRICS_AVAILABLE}")
        print(f"[PyScan] Data Flow: {DATAFLOW_AVAILABLE}")

    def analyze_file(self, file_path: str) -> List[Dict]:
        """Hàm chính để phân tích một file - FULLY INTEGRATED"""
        issues = []
        
        file_type = self._get_file_type(file_path)
        
        code = self._read_file(file_path)
        if code is None:
            return [{
                "type": "error", 
                "message": "Không thể đọc file hoặc encoding không hỗ trợ", 
                "file": file_path, 
                "severity": "low"
            }]

        print(f"[*] Đang quét ({file_type}): {file_path}")

        if file_type == "python":
            issues.extend(self._analyze_python_file(file_path, code))
        
        elif file_type == "config":
            issues.extend(self.file_analyzer.analyze_config_file(file_path, code))
        
        elif file_type == "requirements":
            sca = DependencyScanner()
            issues.extend(sca.scan(code, file_path))
        
        elif file_type == "shell":
            issues.extend(self._analyze_shell_file(file_path, code))
        
        elif file_type == "docker":
            issues.extend(self._analyze_docker_file(file_path, code))
        
        elif file_type == "html":
            issues.extend(self._analyze_html_file(file_path, code))
        
        elif file_type == "javascript":
            issues.extend(self._analyze_javascript_file(file_path, code))
        
        issues.extend(self._analyze_general_secrets(file_path, code))
        
        return issues

    def _analyze_python_file(self, file_path: str, code: str) -> List[Dict]:
        """Phân tích file Python - WITH ALL CHECKS"""
        issues = []
        
        # 1. External tools (Bandit & Flake8)
        issues.extend(run_external_scans(file_path))

        # 2. Internal engines
        try:
            tree = ast.parse(code, filename=file_path)
            
            # AST Linting
            linter = ASTLinter(tree, code, file_path)
            issues.extend(linter.lint())

            # Taint Analysis
            taint = TaintAnalyzer(tree, self.taint_sources, self.taint_sinks, file_path)
            issues.extend(taint.analyze())
            
            # Deep Analysis
            if self.deep_scan:
                issues.extend(self._deep_ast_analysis(tree, code, file_path))
            
            # ✨ ADVANCED SECURITY (NEW)
            if self.enable_advanced and ADVANCED_SECURITY_AVAILABLE:
                adv_issues = analyze_advanced_security(file_path, code)
                issues.extend(adv_issues)
                print(f"  [+] Advanced Security: {len(adv_issues)} issues")
            
            # ✨ CODE METRICS (if enabled)
            if METRICS_AVAILABLE:
                try:
                    metrics_result = analyze_code_metrics(file_path, code)
                    if 'metrics' in metrics_result:
                        for smell in metrics_result['metrics'].get('code_smells', []):
                            issues.append({
                                "type": "code_quality",
                                "category": smell['type'],
                                "severity": smell['severity'],
                                "message": smell['message'],
                                "line": smell['line'],
                                "file": file_path,
                                "recommendation": smell['recommendation']
                            })
                except Exception as e:
                    print(f"  [!] Metrics error: {e}")
            
            # ✨ DATA FLOW ANALYSIS (if enabled)
            if DATAFLOW_AVAILABLE:
                try:
                    flow_result = analyze_data_flow(file_path, code)
                    for vuln in flow_result.get('vulnerabilities', []):
                        issues.append(vuln)
                except Exception as e:
                    print(f"  [!] Data flow error: {e}")

        except SyntaxError as e:
            issues.append({
                "type": "syntax_error",
                "category": "syntax",
                "severity": "critical",
                "message": f"Lỗi cú pháp Python: {e.msg}",
                "line": e.lineno,
                "file": file_path,
                "recommendation": "Sửa lỗi cú pháp để code có thể chạy."
            })
        except Exception as e:
            issues.append({
                "type": "analysis_error",
                "category": "internal_error",
                "severity": "low",
                "message": f"Lỗi khi phân tích AST: {str(e)}",
                "line": 1,
                "file": file_path,
                "recommendation": "File có thể chứa cú pháp không chuẩn"
            })
        
        return issues

    def _analyze_shell_file(self, file_path: str, code: str) -> List[Dict]:
        issues = []
        lines = code.split('\n')
        
        dangerous_patterns = [
            (r'\$\([^)]*\)', "Command substitution có thể bị injection"),
            (r'eval\s+', "Sử dụng eval trong shell script"),
            (r'exec\s+', "Sử dụng exec có thể nguy hiểm"),
            (r'\|\s*bash', "Pipe to bash có thể bị command injection"),
            (r'curl\s+.*\|\s*sh', "Curl pipe to shell - rất nguy hiểm"),
            (r'wget\s+.*-O\s*-\s*\|', "Wget pipe có thể bị tấn công"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, message in dangerous_patterns:
                if re.search(pattern, line):
                    issues.append({
                        "type": "shell_analysis",
                        "category": "shell_injection",
                        "severity": "high",
                        "message": f"Shell script: {message}",
                        "line": i,
                        "file": file_path,
                        "recommendation": "Validate input và tránh dynamic command execution"
                    })
        
        return issues

    def _analyze_docker_file(self, file_path: str, code: str) -> List[Dict]:
        issues = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_upper = line.strip().upper()
            
            if line_upper.startswith('USER ROOT'):
                issues.append({
                    "type": "docker_analysis",
                    "category": "docker_security",
                    "severity": "high",
                    "message": "Container chạy với user ROOT - nguy hiểm",
                    "line": i,
                    "file": file_path,
                    "recommendation": "Tạo non-root user và dùng USER directive"
                })
            
            if ':LATEST' in line_upper or (line_upper.startswith('FROM') and ':' not in line):
                issues.append({
                    "type": "docker_analysis",
                    "category": "docker_best_practice",
                    "severity": "medium",
                    "message": "Sử dụng :latest tag - nên pin specific version",
                    "line": i,
                    "file": file_path,
                    "recommendation": "Dùng specific tag thay vì :latest"
                })
            
            if line_upper.startswith('ADD '):
                issues.append({
                    "type": "docker_analysis",
                    "category": "docker_best_practice",
                    "severity": "low",
                    "message": "Dùng ADD thay vì COPY - không recommended",
                    "line": i,
                    "file": file_path,
                    "recommendation": "Dùng COPY thay vì ADD trừ khi cần auto-extract"
                })
        
        return issues

    def _analyze_html_file(self, file_path: str, code: str) -> List[Dict]:
        issues = []
        lines = code.split('\n')
        
        xss_patterns = [
            (r'<script[^>]*>.*document\.write\(', "Sử dụng document.write() - XSS risk"),
            (r'eval\s*\(', "Sử dụng eval() trong HTML/JS"),
            (r'innerHTML\s*=', "Sử dụng innerHTML - XSS risk"),
            (r'on\w+\s*=\s*["\'].*["\']', "Inline event handlers - XSS risk"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, message in xss_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "html_analysis",
                        "category": "xss_risk",
                        "severity": "high",
                        "message": f"HTML: {message}",
                        "line": i,
                        "file": file_path,
                        "recommendation": "Sanitize user input và dùng textContent thay vì innerHTML"
                    })
        
        return issues

    def _analyze_javascript_file(self, file_path: str, code: str) -> List[Dict]:
        issues = []
        lines = code.split('\n')
        
        js_patterns = [
            (r'eval\s*\(', "Sử dụng eval() - code injection risk"),
            (r'new\s+Function\s*\(', "Sử dụng Function constructor - tương tự eval"),
            (r'document\.write\s*\(', "document.write() - XSS risk"),
            (r'\.innerHTML\s*=', "innerHTML assignment - XSS risk"),
            (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML - XSS risk"),
            (r'localStorage\.setItem.*password', "Lưu password trong localStorage"),
            (r'console\.log.*password', "Log password ra console"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, message in js_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": "javascript_analysis",
                        "category": "js_security",
                        "severity": "high",
                        "message": f"JavaScript: {message}",
                        "line": i,
                        "file": file_path,
                        "recommendation": "Tránh dùng eval, sanitize HTML, không log sensitive data"
                    })
        
        return issues

    def _deep_ast_analysis(self, tree: ast.AST, code: str, file_path: str) -> List[Dict]:
        issues = []
        
        dangerous_patterns = [
            ("eval", "Sử dụng eval() với user input"),
            ("exec", "Sử dụng exec() không an toàn"),
            ("pickle.loads", "Deserialization pickle không an toàn"),
            ("yaml.load", "YAML deserialization không an toàn"),
            ("os.system", "Command injection risk"),
            ("subprocess.call", "Command injection với shell=True"),
        ]
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                
                for pattern, message in dangerous_patterns:
                    if pattern in func_name:
                        for arg in node.args:
                            if isinstance(arg, (ast.Name, ast.JoinedStr, ast.BinOp)):
                                issues.append({
                                    "type": "deep_analysis",
                                    "category": "dangerous_pattern",
                                    "severity": "critical",
                                    "message": f"Phát hiện mẫu nguy hiểm: {message}",
                                    "line": node.lineno,
                                    "file": file_path,
                                    "recommendation": f"Tránh dùng {pattern} với input không tin cậy"
                                })
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                if "hash" in func_name or "encrypt" in func_name:
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if arg.value.lower() in ['md5', 'sha1']:
                                issues.append({
                                    "type": "deep_analysis",
                                    "category": "weak_crypto",
                                    "severity": "high",
                                    "message": f"Sử dụng thuật toán hash yếu: {arg.value}",
                                    "line": node.lineno,
                                    "file": file_path,
                                    "recommendation": "Dùng SHA256, SHA512, hoặc bcrypt/argon2"
                                })
        
        return issues

    def _analyze_general_secrets(self, file_path: str, content: str) -> List[Dict]:
        issues = []
        
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Secret Key"),
            (r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', "JWT Token"),
            (r'-----BEGIN RSA PRIVATE KEY-----', "RSA Private Key"),
            (r'-----BEGIN PRIVATE KEY-----', "Private Key"),
            (r'ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}', "SSH Public Key"),
            (r'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}', "Slack Bot Token"),
        ]
        
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, secret_type in secret_patterns:
                if re.search(pattern, line):
                    issues.append({
                        "type": "secret_detection",
                        "category": "exposed_secret",
                        "severity": "critical",
                        "message": f"Phát hiện {secret_type} trong file",
                        "line": i,
                        "file": file_path,
                        "recommendation": "Không commit secret vào repository. Dùng .gitignore và secret manager."
                    })
        
        return issues

    def _get_file_type(self, file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        basename = os.path.basename(file_path).lower()
        
        if ext == '.py':
            return "python"
        elif ext in ['.json', '.yaml', '.yml', '.xml', '.ini', '.cfg']:
            return "config"
        elif 'requirements' in basename:
            return "requirements"
        elif ext in ['.sh', '.bash'] or 'dockerfile' in basename:
            return "shell"
        elif 'dockerfile' in basename:
            return "docker"
        elif ext in ['.html', '.htm']:
            return "html"
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            return "javascript"
        else:
            return "unknown"

    def _read_file(self, path: str) -> str:
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except Exception:
                break
        
        try:
            with open(path, 'rb') as f:
                content = f.read()
                return content.decode('utf-8', errors='ignore')
        except:
            return None

    def _get_func_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_func_name(node.value) + '.' + node.attr
        return ""