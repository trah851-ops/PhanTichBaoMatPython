#!/usr/bin/env python3
"""
Fuzzing API Server - FIXED FOR PROCESS ISOLATION v6.0
✅ Compatible with new Atheris wrapper
✅ Handles import errors gracefully
✅ Runs Real Fuzzing correctly
"""

from flask import Flask, request, jsonify
import threading
import os
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
import sys

print("=" * 70)
print("🚀 Starting PyScan Fuzzing Server v6.0...")
print("=" * 70)

# Import Real Fuzzer
try:
    print("📦 Importing atheris_real_fuzzer...")
    from atheris_real_fuzzer import RealAtherisFuzzer
    # Vì chúng ta đang chạy trong Docker Ubuntu 24.04 đã cài sẵn mọi thứ
    # nên mặc định là True. Class RealAtherisFuzzer sẽ tự lo phần còn lại.
    ATHERIS_AVAILABLE = True 
    print(f"✅ Real Atheris fuzzer wrapper loaded")
except ImportError as e:
    print(f"⚠️ Could not import atheris_real_fuzzer: {e}")
    ATHERIS_AVAILABLE = False
    RealAtherisFuzzer = None

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
    except Exception as e:
        print(f"  ⚠️ {dir_path}: {e}")

class PatternBasedDetector:
    """Fallback pattern-based detection (Only used when Atheris fails)"""
    def __init__(self):
        import re
        self.re = re
        self.patterns = {
            r'\beval\s*\(': ('code_injection', 'critical'),
            r'\bexec\s*\(': ('code_injection', 'critical'),
            r'os\.system\s*\(': ('command_injection', 'critical'),
        }
    
    def analyze(self, code: str, filename: str = 'code.py') -> dict:
        vulnerabilities = []
        lines = code.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern, (vuln_type, severity) in self.patterns.items():
                if self.re.search(pattern, line):
                    vulnerabilities.append({
                        'type': vuln_type, 'severity': severity, 'line': line_num,
                        'message': f'{vuln_type} detected (Static)', 'code': line.strip()[:100], 'file': filename
                    })
        return {
            'vulnerabilities': vulnerabilities,
            'statistics': {'total_vulnerabilities': len(vulnerabilities), 'risk_score': min(100, len(vulnerabilities) * 25)}
        }

class FuzzingJob:
    def __init__(self, job_id: str, data: bytes, config: dict, is_zip: bool = False):
        self.job_id = job_id
        self.data = data
        self.config = config
        self.is_zip = is_zip
        self.status = "pending"
        self.progress = 0
        self.results = None
    
    def run(self):
        self.status = "running"
        print(f"\n[Job {self.job_id}] Starting (Mode: {'ZIP' if self.is_zip else 'Single'})")
        
        try:
            if self.is_zip:
                self.results = self._fuzz_zip() # Zip tạm thời dùng pattern matching hoặc giải nén fuzz từng file (chưa implement full)
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
            self.results = {"error": str(e)}

    def _fuzz_single(self) -> dict:
        code = self.data.decode('utf-8', errors='ignore')
        
        # 1. Ưu tiên dùng Atheris (Real Fuzzing)
        if ATHERIS_AVAILABLE and RealAtherisFuzzer:
            print(f"[Job {self.job_id}] 🚀 Executing Real Atheris Fuzzer...")
            try:
                # Gọi wrapper mới
                fuzzer = RealAtherisFuzzer(
                    target_code=code,
                    output_dir="/fuzzing"
                )
                # Chạy (sẽ block cho đến khi xong timeout)
                results = fuzzer.run()
                
                # Bổ sung thông tin job
                return {
                    'job_id': self.job_id,
                    'status': 'completed',
                    'vulnerabilities': results.get('vulnerabilities', []),
                    'crashes': results.get('crashes', []),
                    'statistics': {
                        'risk_score': results.get('risk_score', 0),
                        'total_crashes': results.get('total_crashes', 0),
                        'execution_time': results.get('execution_time', 0),
                        'mode': 'real_atheris_process'
                    }
                }
            except Exception as e:
                print(f"[Job {self.job_id}] ⚠️ Atheris crashed: {e}. Falling back...")
                # Nếu lỗi thì fallback xuống dưới

        # 2. Fallback: Pattern Matching
        print(f"[Job {self.job_id}] 📋 Using pattern-based detection (Fallback)...")
        detector = PatternBasedDetector()
        result = detector.analyze(code)
        
        return {
            'job_id': self.job_id,
            'status': 'completed',
            'vulnerabilities': result['vulnerabilities'],
            'crashes': [],
            'statistics': {**result['statistics'], 'mode': 'pattern_matching'}
        }

    def _fuzz_zip(self) -> dict:
        # Zip handling simplified for demo
        return {"error": "ZIP fuzzing not fully supported in Real Atheris mode yet. Please upload single .py file."}

# ==================== API Routes ====================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "pyscan-fuzzing",
        "atheris_available": ATHERIS_AVAILABLE
    })

@app.route("/fuzz/start", methods=["POST"])
def start_fuzzing():
    global job_counter
    try:
        file_data = None
        is_zip = False
        config = {'runs': 1000, 'timeout': 60}
        
        if request.files and 'file' in request.files:
            file = request.files['file']
            file_data = file.read()
            is_zip = file.filename.endswith('.zip')
        elif request.is_json:
            json_data = request.get_json()
            code = json_data['code']
            file_data = code.encode('utf-8')
        
        job_counter += 1
        job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{job_counter}"
        job = FuzzingJob(job_id, file_data, config, is_zip=is_zip)
        fuzzing_jobs[job_id] = job
        
        thread = threading.Thread(target=job.run)
        thread.daemon = True
        thread.start()
        
        return jsonify({"success": True, "job_id": job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fuzz/status/<job_id>", methods=["GET"])
def get_status(job_id):
    if job_id not in fuzzing_jobs:
        return jsonify({"error": "Job not found"}), 404
    job = fuzzing_jobs[job_id]
    return jsonify({"job_id": job_id, "status": job.status, "progress": job.progress})

@app.route("/fuzz/results/<job_id>", methods=["GET"])
def get_results(job_id):
    if job_id not in fuzzing_jobs:
        return jsonify({"error": "Job not found"}), 404
    job = fuzzing_jobs[job_id]
    return jsonify({"success": True, "results": job.results})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=False, threaded=True)