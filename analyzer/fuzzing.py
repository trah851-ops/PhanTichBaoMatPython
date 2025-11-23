# analyzer/fuzzing.py - CROSS-PLATFORM FUZZING ENGINE
# Không cần atheris - chạy được trên Windows/Linux/Mac
import sys
import random
import string
import tempfile
import os
from typing import List, Dict
import time

def is_fuzzing_available():
    """Fuzzing luôn available vì không cần thư viện external"""
    return True


class FuzzPayloadGenerator:
    """Generator cho các payload tấn công"""
    
    def __init__(self):
        # Payload templates cho các loại tấn công
        self.sql_injection = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM passwords--",
            "admin'--",
            "1' AND 1=1--",
        ]
        
        self.command_injection = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "$(cat /etc/shadow)",
            "`rm -rf /`",
            "; ping -c 10 attacker.com",
        ]
        
        self.code_injection = [
            "__import__('os').system('whoami')",
            "eval('print(open(\"/etc/passwd\").read())')",
            "exec('import os; os.system(\"ls\")')",
            "compile('malicious_code', '<string>', 'exec')",
        ]
        
        self.path_traversal = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]
        
        self.template_injection = [
            "{{7*7}}",
            "${7*7}",
            "{{config.items()}}",
            "{%print(open('/etc/passwd').read())%}",
        ]
        
        self.deserialization = [
            "O:8:\"stdClass\":0:{}",  # PHP
            "csubprocess\nsystem\n(S'ls'\ntR.",  # Python pickle
        ]
        
        self.secrets = [
            "password=admin123",
            "api_key=sk_live_1234567890abcdef",
            "AKIA1234567890ABCDEF",  # AWS key format
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",  # GitHub token
        ]
    
    def get_random_payload(self) -> str:
        """Lấy random payload từ tất cả categories"""
        all_payloads = (
            self.sql_injection +
            self.command_injection +
            self.code_injection +
            self.path_traversal +
            self.xss_payloads +
            self.template_injection +
            self.deserialization +
            self.secrets
        )
        return random.choice(all_payloads)
    
    def generate_random_string(self, length: int = None) -> str:
        """Tạo chuỗi random với ký tự đặc biệt"""
        if length is None:
            length = random.randint(10, 100)
        
        chars = string.ascii_letters + string.digits + "';\"\\<>(){}[]|&$`"
        return ''.join(random.choices(chars, k=length))
    
    def generate_fuzzed_code(self) -> str:
        """Tạo Python code với payload để test"""
        payload = self.get_random_payload()
        
        templates = [
            # Template 1: Input + dangerous function
            f"""
import os
user_input = "{payload}"
os.system(user_input)
""",
            # Template 2: Hardcoded secret
            f"""
password = "{payload}"
api_key = "sk_test_{self.generate_random_string(32)}"
""",
            # Template 3: Eval/exec
            f"""
data = "{payload}"
eval(data)
""",
            # Template 4: Pickle loads
            f"""
import pickle
data = b"{payload}"
pickle.loads(data)
""",
            # Template 5: SQL query
            f"""
query = "SELECT * FROM users WHERE name = '{payload}'"
cursor.execute(query)
""",
            # Template 6: Path operation
            f"""
filename = "{payload}"
open(filename, 'r')
""",
        ]
        
        return random.choice(templates)


class PythonFuzzEngine:
    """Fuzzing engine thuần Python - không cần atheris"""
    
    def __init__(self):
        self.generator = FuzzPayloadGenerator()
        self.results = {
            "total_iterations": 0,
            "vulnerabilities_found": 0,
            "missed_vulnerabilities": 0,
            "false_positives": 0,
            "crashes": [],
            "findings": []
        }
    
    def fuzz_analyzer(self, iterations: int = 1000, callback=None):
        """
        Fuzz analyzer với callback để report progress
        callback(current, total, message)
        """
        from analyzer.core import Analyzer
        
        analyzer = Analyzer()
        start_time = time.time()
        
        print(f"\n{'='*70}")
        print(f"🔥 PYTHON FUZZING ENGINE - Cross-Platform")
        print(f"{'='*70}")
        print(f"Iterations: {iterations}")
        print(f"Platform: {sys.platform}")
        print(f"{'='*70}\n")
        
        for i in range(iterations):
            self.results["total_iterations"] += 1
            
            # Progress callback
            if callback and i % 10 == 0:
                callback(i, iterations, f"Testing iteration {i}/{iterations}")
            
            # Progress print mỗi 100 iterations
            if i % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                print(f"[{i}/{iterations}] Speed: {rate:.1f} iter/s | Found: {self.results['vulnerabilities_found']}")
            
            try:
                # Tạo code fuzzed
                fuzzed_code = self.generator.generate_fuzzed_code()
                
                # Tạo temp file
                with tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='.py',
                    delete=False,
                    encoding='utf-8'
                ) as f:
                    f.write(fuzzed_code)
                    temp_path = f.name
                
                # Analyze
                issues = analyzer.analyze_file(temp_path)
                
                # Kiểm tra kết quả
                has_critical = any(
                    i.get("severity") in ["critical", "high"]
                    for i in issues
                )
                
                if has_critical:
                    self.results["vulnerabilities_found"] += 1
                    
                    # Lưu một số findings tiêu biểu
                    if len(self.results["findings"]) < 50:
                        self.results["findings"].append({
                            "iteration": i,
                            "code_snippet": fuzzed_code[:200],
                            "issues_found": len(issues),
                            "severity": [x.get("severity") for x in issues]
                        })
                else:
                    # Nếu code có payload nguy hiểm mà không detect được
                    if any(keyword in fuzzed_code.lower() for keyword in 
                           ["os.system", "eval", "exec", "pickle.loads"]):
                        self.results["missed_vulnerabilities"] += 1
                
                # Cleanup
                os.unlink(temp_path)
                
            except Exception as e:
                # Analyzer crash - đây là lỗi nghiêm trọng
                self.results["crashes"].append({
                    "iteration": i,
                    "error": str(e),
                    "error_type": type(e).__name__
                })
                
                # Cleanup nếu có
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
        
        elapsed_time = time.time() - start_time
        
        # Final report
        print(f"\n{'='*70}")
        print(f"📊 FUZZING RESULTS")
        print(f"{'='*70}")
        print(f"✅ Total iterations: {self.results['total_iterations']}")
        print(f"🎯 Vulnerabilities found: {self.results['vulnerabilities_found']}")
        print(f"⚠️  Missed vulnerabilities: {self.results['missed_vulnerabilities']}")
        print(f"💥 Analyzer crashes: {len(self.results['crashes'])}")
        print(f"⏱️  Total time: {elapsed_time:.2f}s")
        print(f"⚡ Speed: {iterations/elapsed_time:.1f} iterations/sec")
        print(f"{'='*70}\n")
        
        return self.results
    
    def get_summary(self) -> Dict:
        """Lấy summary của fuzzing session"""
        detection_rate = 0
        if self.results["total_iterations"] > 0:
            detected = self.results["vulnerabilities_found"]
            missed = self.results["missed_vulnerabilities"]
            total = detected + missed
            if total > 0:
                detection_rate = (detected / total) * 100
        
        return {
            "total_iterations": self.results["total_iterations"],
            "vulnerabilities_found": self.results["vulnerabilities_found"],
            "missed_vulnerabilities": self.results["missed_vulnerabilities"],
            "crashes": len(self.results["crashes"]),
            "detection_rate": f"{detection_rate:.1f}%",
            "sample_findings": self.results["findings"][:10]  # Top 10
        }


def run_fuzz_on_analyzer(runs=1000, callback=None):
    """
    Main fuzzing function - được gọi từ web hoặc CLI
    
    Args:
        runs: Số lần fuzzing
        callback: Function(current, total, message) để report progress
    
    Returns:
        Dict với kết quả fuzzing
    """
    engine = PythonFuzzEngine()
    results = engine.fuzz_analyzer(runs, callback)
    return engine.get_summary()


# Compatibility với code cũ
class FuzzEngine:
    """Backward compatibility"""
    def __init__(self):
        self.engine = PythonFuzzEngine()
    
    def fuzz_function(self, func, iterations=1000):
        print("[Deprecated] Use run_fuzz_on_analyzer() instead")
        return []


if __name__ == "__main__":
    # Test fuzzing engine
    print("Testing Python Fuzzing Engine...")
    results = run_fuzz_on_analyzer(runs=100)
    print("\n📊 Summary:")
    print(f"Detection Rate: {results['detection_rate']}")
    print(f"Total Findings: {results['vulnerabilities_found']}")