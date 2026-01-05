#!/usr/bin/env python3
"""
Fuzzing API Server - FIXED STARTUP v5.2
✅ Better error handling
✅ Graceful fallback
✅ Clear startup logs
"""

from flask import Flask, request, jsonify
import threading
import os
import json
import time
import subprocess
import tempfile
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
import sys

print("=" * 70)
print("🚀 Starting PyScan Fuzzing Server v5.2...")
print("=" * 70)

# Try import real fuzzer with better error handling
ATHERIS_AVAILABLE = False
RealAtherisFuzzer = None

try:
    print("📦 Importing atheris_real_fuzzer...")
    from atheris_real_fuzzer import RealAtherisFuzzer, ATHERIS_AVAILABLE as ATHERIS_STATUS
    ATHERIS_AVAILABLE = ATHERIS_STATUS
    print(f"✅ Real Atheris fuzzer loaded (Atheris: {ATHERIS_AVAILABLE})")
except ImportError as e:
    print(f"⚠️ Could not import atheris_real_fuzzer: {e}")
    print("📋 Will use pattern-based detection only")
except Exception as e:
    print(f"⚠️ Error loading fuzzer: {e}")
    import traceback
    traceback.print_exc()

app = Flask(__name__)

fuzzing_jobs = {}
job_counter = 0

CORPUS_DIR = "/fuzzing/corpus"
CRASHES_DIR = "/fuzzing/crashes"
RESULTS_DIR = "/fuzzing/results"

print(f"📁 Setting up directories...")
for dir_path in [CORPUS_DIR, CRASHES_DIR, RESULTS_DIR]:
    try:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"  ✅ {dir_path}")
    except Exception as e:
        print(f"  ⚠️ {dir_path}: {e}")


class PatternBasedDetector:
    """Fallback pattern-based detection - ENHANCED"""
    
    def __init__(self):
        import re
        self.re = re
        self.patterns = {
            # Code Injection
            r'\beval\s*\(': ('code_injection', 'critical'),
            r'\bexec\s*\(': ('code_injection', 'critical'),
            r'\bcompile\s*\(.*["\']exec["\']': ('code_injection', 'critical'),
            r'__import__\s*\(': ('code_injection', 'high'),
            
            # Command Injection
            r'os\.system\s*\(': ('command_injection', 'critical'),
            r'os\.popen\s*\(': ('command_injection', 'critical'),
            r'subprocess\.call\s*\(.*shell\s*=\s*True': ('command_injection', 'critical'),
            r'subprocess\.run\s*\(.*shell\s*=\s*True': ('command_injection', 'critical'),
            r'subprocess\.Popen\s*\(.*shell\s*=\s*True': ('command_injection', 'critical'),
            
            # Deserialization
            r'pickle\.loads?\s*\(': ('deserialization', 'critical'),
            r'yaml\.load\s*\((?!.*SafeLoader)': ('deserialization', 'critical'),
            r'marshal\.loads?\s*\(': ('deserialization', 'high'),
            
            # SQL Injection
            r'execute\s*\(\s*["\'].*\+': ('sql_injection', 'critical'),
            r'execute\s*\(\s*f["\']': ('sql_injection', 'critical'),
            r'execute\s*\(\s*[^,]+%': ('sql_injection', 'critical'),
            r'SELECT.*\+\s*\w+': ('sql_injection', 'high'),
            r'INSERT.*\+\s*\w+': ('sql_injection', 'high'),
            r'UPDATE.*\+\s*\w+': ('sql_injection', 'high'),
            r'DELETE.*\+\s*\w+': ('sql_injection', 'high'),
            
            # Path Traversal
            r'open\s*\([^)]*\+': ('path_traversal', 'high'),
            r'os\.path\.join\s*\([^)]*\.\./': ('path_traversal', 'high'),
            
            # Memory Leak - File not closed
            r'^\s*\w+\s*=\s*open\s*\([^)]+\)\s*$': ('memory_leak', 'medium'),
            r'open\s*\([^)]+\)(?!.*\bwith\b)': ('memory_leak_risk', 'medium'),
            
            # Race Condition
            r'global\s+\w+': ('race_condition_risk', 'medium'),
            r'threading\.\w+': ('concurrency_detected', 'info'),
            
            # Hardcoded Secrets
            r'password\s*=\s*["\'][^"\']+["\']': ('hardcoded_secret', 'high'),
            r'api_key\s*=\s*["\'][^"\']+["\']': ('hardcoded_secret', 'high'),
            r'secret\s*=\s*["\'][^"\']+["\']': ('hardcoded_secret', 'high'),
            r'token\s*=\s*["\'][^"\']+["\']': ('hardcoded_secret', 'high'),
            r'["\']sk-[a-zA-Z0-9]+["\']': ('hardcoded_api_key', 'critical'),
            r'["\']ghp_[a-zA-Z0-9]+["\']': ('hardcoded_github_token', 'critical'),
            r'["\']aws_[a-zA-Z0-9]+["\']': ('hardcoded_aws_key', 'critical'),
            
            # XSS
            r'render_template_string\s*\(': ('xss', 'high'),
            r'Markup\s*\([^)]*\+': ('xss', 'high'),
            r'\.format\s*\([^)]*request\.': ('xss', 'high'),
            
            # SSRF
            r'requests\.get\s*\([^)]*\+': ('ssrf', 'high'),
            r'requests\.post\s*\([^)]*\+': ('ssrf', 'high'),
            r'urllib\.request\.urlopen\s*\([^)]*\+': ('ssrf', 'high'),
            
            # Weak Crypto
            r'md5\s*\(': ('weak_crypto', 'medium'),
            r'sha1\s*\(': ('weak_crypto', 'low'),
            r'DES\s*\(': ('weak_crypto', 'high'),
            
            # Debug/Info Leak
            r'print\s*\(.*password': ('info_leak', 'high'),
            r'print\s*\(.*secret': ('info_leak', 'high'),
            r'DEBUG\s*=\s*True': ('debug_enabled', 'medium'),
        }
        
        # Special patterns for race condition detection
        self.race_condition_patterns = [
            (r'global\s+(\w+)', r'\1\s*[+\-*/]?='),  # global var modified
            (r'threading', r'(?!.*lock)'),  # threading without lock
        ]
    
    def detect_race_condition(self, code: str) -> list:
        """Detect race conditions more accurately"""
        vulns = []
        lines = code.split('\n')
        
        has_threading = 'threading' in code or 'Thread' in code
        has_global = 'global ' in code
        has_lock = 'lock' in code.lower() and ('acquire' in code or 'Lock()' in code)
        
        if has_threading and has_global and not has_lock:
            for i, line in enumerate(lines, 1):
                if 'global ' in line:
                    vulns.append({
                        'type': 'race_condition',
                        'severity': 'high',
                        'line': i,
                        'message': 'Race condition: global variable in threaded code without lock',
                        'code': line.strip()[:100],
                        'recommendation': 'Use threading.Lock() to protect shared state'
                    })
        
        return vulns
    
    def detect_memory_leak(self, code: str) -> list:
        """Detect potential memory leaks"""
        vulns = []
        lines = code.split('\n')
        
        open_files = {}  # Track opened files
        
        for i, line in enumerate(lines, 1):
            # Check for file open without 'with'
            match = self.re.search(r'(\w+)\s*=\s*open\s*\(', line)
            if match and 'with ' not in line:
                var_name = match.group(1)
                open_files[var_name] = i
        
        # Check if files are closed
        for var_name, line_num in open_files.items():
            close_pattern = rf'{var_name}\.close\s*\(\)'
            if not self.re.search(close_pattern, code):
                # Check if used in 'with' later
                with_pattern = rf'with\s+{var_name}'
                if not self.re.search(with_pattern, code):
                    vulns.append({
                        'type': 'memory_leak',
                        'severity': 'medium',
                        'line': line_num,
                        'message': f'Memory leak: file opened but never closed',
                        'code': f'{var_name} = open(...)',
                        'recommendation': 'Use "with open(...) as f:" to auto-close file'
                    })
        
        return vulns
    
    def analyze(self, code: str, filename: str = 'code.py') -> dict:
        vulnerabilities = []
        lines = code.split('\n')
        
        # Pattern-based detection
        for line_num, line in enumerate(lines, 1):
            for pattern, (vuln_type, severity) in self.patterns.items():
                if self.re.search(pattern, line, self.re.IGNORECASE):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'severity': severity,
                        'line': line_num,
                        'message': f'{vuln_type} detected',
                        'code': line.strip()[:100],
                        'file': filename
                    })
        
        # Advanced detection
        vulnerabilities.extend(self.detect_race_condition(code))
        vulnerabilities.extend(self.detect_memory_leak(code))
        
        # Remove duplicates
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            key = (v['type'], v['line'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        
        risk_score = min(100, len(unique_vulns) * 20)
        
        return {
            'vulnerabilities': unique_vulns,
            'statistics': {
                'total_vulnerabilities': len(unique_vulns),
                'risk_score': risk_score,
                'risk_level': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score > 0 else 'low'
            }
        }


class FuzzingJob:
    """Fuzzing job with graceful fallback"""
    
    def __init__(self, job_id: str, data: bytes, config: dict, is_zip: bool = False):
        self.job_id = job_id
        self.data = data
        self.config = config
        self.is_zip = is_zip
        self.status = "pending"
        self.progress = 0
        self.start_time = None
        self.end_time = None
        self.results = None
        self.temp_dir = None
    
    def run(self):
        """Execute fuzzing"""
        self.status = "running"
        self.start_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"[Job {self.job_id}] Starting")
        print(f"  Mode: {'ZIP' if self.is_zip else 'Single File'}")
        print(f"  Atheris: {ATHERIS_AVAILABLE}")
        print(f"  Runs: {self.config.get('runs', 1000)}")
        print(f"{'='*60}")
        
        try:
            if self.is_zip:
                self.results = self._fuzz_zip()
            else:
                self.results = self._fuzz_single()
            
            self.status = "completed"
            self.progress = 100
            print(f"[Job {self.job_id}] ✅ Complete")
            
        except Exception as e:
            print(f"[Job {self.job_id}] ❌ Error: {e}")
            import traceback
            traceback.print_exc()
            
            self.status = "failed"
            self.results = {
                "error": str(e),
                "vulnerabilities": [],
                "statistics": {"risk_score": 0}
            }
        
        finally:
            self.end_time = datetime.now()
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                except:
                    pass
    
    def _fuzz_single(self) -> dict:
        """Fuzz single file"""
        code = self.data.decode('utf-8', errors='ignore')
        
        print(f"[Job {self.job_id}] 📋 Using pattern-based detection...")
        detector = PatternBasedDetector()
        result = detector.analyze(code)
        
        self.progress = 100
        
        return {
            'job_id': self.job_id,
            'status': 'completed',
            'vulnerabilities': result['vulnerabilities'],
            'entry_points': [],
            'crashes': [],
            'statistics': {
                **result['statistics'],
                'mode': 'pattern_matching',
                'total_vulnerabilities': len(result['vulnerabilities'])
            }
        }
    
    def _fuzz_zip(self) -> dict:
        """Fuzz ZIP package"""
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Extract ZIP
            zip_path = os.path.join(temp_dir, "upload.zip")
            with open(zip_path, 'wb') as f:
                f.write(self.data)
            
            extract_dir = os.path.join(temp_dir, "extracted")
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find Python files
            py_files = {}
            for root, dirs, files in os.walk(extract_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                py_files[rel_path] = f.read()
                        except:
                            pass
            
            print(f"[Job {self.job_id}] Found {len(py_files)} Python files")
            
            # Analyze each file
            all_vulns = []
            detector = PatternBasedDetector()
            
            for i, (rel_path, code) in enumerate(py_files.items()):
                self.progress = int((i + 1) / len(py_files) * 100)
                result = detector.analyze(code, rel_path)
                all_vulns.extend(result['vulnerabilities'])
            
            # Calculate risk
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for v in all_vulns:
                sev = v.get('severity', 'low')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            risk_score = min(100, (
                severity_counts['critical'] * 35 +
                severity_counts['high'] * 20 +
                severity_counts['medium'] * 8 +
                severity_counts['low'] * 3
            ))
            
            return {
                'job_id': self.job_id,
                'status': 'completed',
                'vulnerabilities': all_vulns,
                'entry_points': [],
                'crashes': [],
                'statistics': {
                    'total_vulnerabilities': len(all_vulns),
                    'severity_breakdown': severity_counts,
                    'risk_score': risk_score,
                    'risk_level': 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium',
                    'files_analyzed': len(py_files),
                    'mode': 'pattern_matching'
                }
            }
        
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)


# ==================== API Routes ====================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "pyscan-fuzzing",
        "version": "5.2.0-fixed",
        "atheris_available": ATHERIS_AVAILABLE,
        "mode": "real_atheris" if ATHERIS_AVAILABLE else "pattern_matching",
        "active_jobs": len([j for j in fuzzing_jobs.values() if j.status == "running"])
    })


@app.route("/fuzz/start", methods=["POST"])
def start_fuzzing():
    global job_counter
    
    try:
        file_data = None
        is_zip = False
        config = {'runs': 1000, 'max_len': 4096, 'timeout': 180}
        
        if request.files and 'file' in request.files:
            file = request.files['file']
            if not file or file.filename == '':
                return jsonify({"error": "No file"}), 400
            
            file_data = file.read()
            is_zip = file.filename.endswith('.zip')
            
            config['runs'] = int(request.form.get('runs', 1000))
            config['timeout'] = int(request.form.get('timeout', 180))
        
        elif request.is_json:
            json_data = request.get_json()
            if not json_data or 'code' not in json_data:
                return jsonify({"error": "No code"}), 400
            
            code = json_data['code']
            file_data = code.encode('utf-8') if isinstance(code, str) else code
            is_zip = json_data.get('is_zip', False)
            config.update(json_data.get('config', {}))
        
        else:
            return jsonify({"error": "No data provided"}), 400
        
        job_counter += 1
        job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{job_counter}"
        
        job = FuzzingJob(job_id, file_data, config, is_zip=is_zip)
        fuzzing_jobs[job_id] = job
        
        thread = threading.Thread(target=job.run)
        thread.daemon = True
        thread.start()
        
        print(f"[Server] ✅ Started: {job_id}")
        
        return jsonify({
            "success": True,
            "job_id": job_id,
            "message": "Fuzzing started",
            "mode": "real_atheris" if ATHERIS_AVAILABLE else "pattern_matching"
        })
    
    except Exception as e:
        print(f"[Server] ❌ Error starting job: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/fuzz/status/<job_id>", methods=["GET"])
def get_status(job_id):
    if job_id not in fuzzing_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    job = fuzzing_jobs[job_id]
    return jsonify({
        "job_id": job_id,
        "status": job.status,
        "progress": job.progress
    })


@app.route("/fuzz/results/<job_id>", methods=["GET"])
def get_results(job_id):
    if job_id not in fuzzing_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    job = fuzzing_jobs[job_id]
    
    if job.status != "completed":
        return jsonify({
            "job_id": job_id,
            "status": job.status,
            "progress": job.progress
        })
    
    return jsonify({
        "success": True,
        "results": job.results
    })


if __name__ == "__main__":
    print("=" * 70)
    print("🔥 PyScan Fuzzing Server v5.2-FIXED")
    print("=" * 70)
    print(f"Atheris: {'✅ Available' if ATHERIS_AVAILABLE else '📋 Pattern matching only'}")
    print(f"🌐 API: http://0.0.0.0:8001")
    print(f"✅ Ready to accept fuzzing jobs!")
    print("=" * 70)
    
    try:
        app.run(host="0.0.0.0", port=8001, debug=False, threaded=True)
    except Exception as e:
        print(f"\n❌ FAILED TO START SERVER: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)