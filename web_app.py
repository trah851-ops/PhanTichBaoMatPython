# web_app.py - FIXED VERSION v3.4.0
from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import zipfile
import tempfile
from datetime import datetime
import shutil
from pathlib import Path
from analyzer.core import Analyzer
import threading
import time
import requests
import html 

app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, "uploads")
REPORT_FOLDER = os.path.join(APP_ROOT, "web_reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

analyzer = Analyzer()
APP_VERSION = "3.4.0-FIXED"

# Fuzzing Service Configuration
FUZZING_SERVICE_URL = os.getenv('FUZZING_SERVICE_URL', 'http://localhost:8001')

# Global fuzzing state
fuzzing_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "message": "",
    "results": None,
    "job_id": None
}

@app.route("/")
def index():
    return render_template("index.html", version=APP_VERSION)

@app.route("/scan", methods=["POST"])
def scan():
    """Quét code Python"""
    results = {"issues": [], "summary": {"total": 0, "files_scanned": 0}}
    temp_extract_path = None

    try:
        paste_code = request.form.get("paste_code", "").strip()
        uploaded_file = request.files.get("file")
        scan_project = request.form.get("scan_project") == "true"

        if paste_code:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
                f.write(paste_code)
                temp_path = f.name
            
            issues = analyzer.analyze_file(temp_path)
            for issue in issues:
                issue["file"] = "Pasted Code"
            results["issues"] = issues
            results["summary"]["files_scanned"] = 1
            os.unlink(temp_path)

        elif uploaded_file:
            filename = uploaded_file.filename
            
            if filename.endswith(".zip"):
                print("[Web] Đang xử lý file ZIP...")
                temp_extract_path = tempfile.mkdtemp()
                zip_path = os.path.join(UPLOAD_FOLDER, filename)
                uploaded_file.save(zip_path)
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_extract_path)
                
                for root, dirs, files in os.walk(temp_extract_path):
                    for file in files:
                        if file.endswith(".py"):
                            file_path = os.path.join(root, file)
                            rel_path = os.path.relpath(file_path, temp_extract_path)
                            
                            try:
                                issues = analyzer.analyze_file(file_path)
                                for issue in issues:
                                    issue["file"] = f"📦 {rel_path}"
                                    results["issues"].append(issue)
                                results["summary"]["files_scanned"] += 1
                            except Exception as e:
                                print(f"[Error] {rel_path}: {e}")
                
                os.unlink(zip_path)
                shutil.rmtree(temp_extract_path)
            
            elif filename.endswith(".py"):
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                uploaded_file.save(save_path)
                
                issues = analyzer.analyze_file(save_path)
                for issue in issues:
                    issue["file"] = filename
                results["issues"] = issues
                results["summary"]["files_scanned"] = 1
                
                try:
                    os.unlink(save_path)
                except:
                    pass
            else:
                return jsonify({"success": False, "error": "Chỉ chấp nhận file .py hoặc .zip"})

        elif scan_project:
            print("[Web] Đang quét toàn bộ project...")
            exclude_dirs = ["uploads", "web_reports", "__pycache__", ".git", "venv", ".venv", "env", "node_modules"]
            
            for root, dirs, files in os.walk(APP_ROOT):
                dirs[:] = [d for d in dirs if d not in exclude_dirs]
                
                for file in files:
                    if file.endswith(".py"):
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, APP_ROOT)
                        
                        try:
                            issues = analyzer.analyze_file(file_path)
                            for issue in issues:
                                issue["file"] = rel_path
                                results["issues"].append(issue)
                            results["summary"]["files_scanned"] += 1
                        except Exception as e:
                            print(f"[Error] {rel_path}: {e}")

        results["summary"]["total"] = len(results["issues"])

        # Generate reports
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_name = f"report_{now}.json"
        html_name = f"report_{now}.html"

        json_path = os.path.join(REPORT_FOLDER, json_name)
        html_path = os.path.join(REPORT_FOLDER, html_name)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        html_content = generate_html_report(results, now)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return jsonify({
            "success": True,
            "total_issues": len(results["issues"]),
            "files_scanned": results["summary"]["files_scanned"],
            "report_html": html_name,
            "report_json": json_name
        })

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        
        if temp_extract_path and os.path.exists(temp_extract_path):
            shutil.rmtree(temp_extract_path)
        
        return jsonify({"success": False, "error": str(e)})


@app.route("/fuzz", methods=["POST"])
def fuzz():
    """Fuzzing - FIXED WITH EXTENDED TIMEOUTS v2.0"""
    global fuzzing_state
    
    if fuzzing_state["running"]:
        return jsonify({"success": False, "error": "Fuzzing đang chạy!"})
    
    try:
        iterations = int(request.form.get("iterations", 100))
        
        # FIXED: Extended timeout - 5 minutes minimum or 3 seconds per iteration
        timeout_seconds = max(300, iterations * 3)
        
        print(f"[Fuzzing] Iterations: {iterations}, Timeout: {timeout_seconds}s ({timeout_seconds//60}min)")
        
        # Check fuzzing service health
        try:
            health_response = requests.get(
                f"{FUZZING_SERVICE_URL}/health", 
                timeout=5
            )
            if health_response.status_code != 200:
                return jsonify({
                    "success": False, 
                    "error": "Fuzzing service không khả dụng"
                })
            
            health_data = health_response.json()
            print(f"[Fuzzing] Service status: {health_data}")
            
        except Exception as e:
            return jsonify({
                "success": False, 
                "error": f"Không thể kết nối tới Fuzzing service: {e}"
            })
        
        # Prepare data
        files = {}
        data = {
            'runs': iterations,
            'max_len': 4096,
            'timeout': timeout_seconds
        }
        
        # Check if pasted code or uploaded file
        paste_code = request.form.get("code", "").strip()
        uploaded_file = request.files.get("fuzz_file")
        
        if paste_code:
            files = {
                'file': ('code.py', paste_code.encode('utf-8'), 'text/x-python')
            }
            print(f"[Fuzzing] Sending pasted code ({len(paste_code)} chars)")
        
        elif uploaded_file:
            file_data = uploaded_file.read()
            filename = uploaded_file.filename
            is_zip = filename.endswith('.zip')
            mime_type = 'application/zip' if is_zip else 'text/x-python'
            
            files = {
                'file': (filename, file_data, mime_type)
            }
            
            print(f"[Fuzzing] Sending file: {filename} ({len(file_data)} bytes, ZIP: {is_zip})")
        
        else:
            return jsonify({"success": False, "error": "Vui lòng paste code hoặc upload file!"})
        
        # Reset state
        fuzzing_state["running"] = True
        fuzzing_state["progress"] = 0
        fuzzing_state["total"] = iterations
        fuzzing_state["message"] = "Starting fuzzing..."
        fuzzing_state["results"] = None
        fuzzing_state["job_id"] = None
        
        def run_fuzzing_thread():
            global fuzzing_state
            
            try:
                print(f"[Fuzzing] Starting job with timeout={timeout_seconds}s...")
                
                # Start fuzzing job with EXTENDED TIMEOUT
                response = requests.post(
                    f"{FUZZING_SERVICE_URL}/fuzz/start",
                    files=files,
                    data=data,
                    timeout=90  # 90 seconds to start the job
                )
                
                if response.status_code != 200:
                    print(f"[Fuzzing] ❌ Start failed: HTTP {response.status_code}")
                    print(f"[Fuzzing] Response: {response.text[:500]}")
                    fuzzing_state["results"] = {"error": f"Failed to start: HTTP {response.status_code}"}
                    fuzzing_state["running"] = False
                    return
                
                result = response.json()
                job_id = result.get('job_id')
                fuzzing_state["job_id"] = job_id
                
                print(f"[Fuzzing] ✅ Job started: {job_id}")
                
                # FIXED: Much longer polling with proper timeout handling
                max_polls = max(600, timeout_seconds * 3)  # 30 minutes minimum or 3x timeout
                poll_count = 0
                poll_interval = 3  # Poll every 3 seconds
                max_wait_time = timeout_seconds + 120  # Add 2 minutes grace period
                start_time = time.time()
                
                print(f"[Fuzzing] Will poll up to {max_polls} times (max {max_wait_time}s)")
                
                while poll_count < max_polls:
                    time.sleep(poll_interval)
                    poll_count += 1
                    elapsed = time.time() - start_time
                    
                    # Check if we've exceeded max wait time
                    if elapsed > max_wait_time:
                        print(f"[Fuzzing] ⏱️  Max wait time ({max_wait_time}s) exceeded")
                        fuzzing_state["results"] = {"error": f"Timeout after {int(elapsed)}s"}
                        break
                    
                    try:
                        status_response = requests.get(
                            f"{FUZZING_SERVICE_URL}/fuzz/status/{job_id}",
                            timeout=15
                        )
                        
                        if status_response.status_code == 200:
                            status_data = status_response.json()
                            current_progress = status_data.get('progress', 0)
                            current_status = status_data.get('status', 'unknown')
                            
                            fuzzing_state["progress"] = current_progress
                            fuzzing_state["message"] = f"Progress: {current_progress}% (poll {poll_count}/{max_polls}, {int(elapsed)}s elapsed)"
                            
                            # Log every 5 polls (15 seconds)
                            if poll_count % 5 == 0:
                                print(f"[Fuzzing] Poll {poll_count}: status={current_status}, progress={current_progress}%, elapsed={int(elapsed)}s")
                            
                            if current_status == 'completed':
                                print(f"[Fuzzing] ✅ Job completed! Getting results...")
                                
                                # Get full results with extended timeout
                                results_response = requests.get(
                                    f"{FUZZING_SERVICE_URL}/fuzz/results/{job_id}",
                                    timeout=30
                                )
                                
                                if results_response.status_code == 200:
                                    results_data = results_response.json()
                                    
                                    print(f"[Fuzzing] Results received: {len(str(results_data))} chars")
                                    
                                    if results_data.get('success'):
                                        actual_results = results_data.get('results', {})
                                        
                                        fuzzing_state["results"] = {
                                            "vulnerabilities": actual_results.get('vulnerabilities', []),
                                            "entry_points": actual_results.get('entry_points', []),
                                            "crashes": actual_results.get('crashes', []),
                                            "statistics": actual_results.get('statistics', {}),
                                            "total_vulnerabilities": len(actual_results.get('vulnerabilities', [])),
                                            "total_entry_points": len(actual_results.get('entry_points', [])),
                                            "total_crashes": len(actual_results.get('crashes', [])),
                                            "risk_score": actual_results.get('statistics', {}).get('risk_score', 0),
                                            "execution_time": int(elapsed)
                                        }
                                        
                                        fuzzing_state["message"] = "Fuzzing complete!"
                                        print(f"[Fuzzing] ✅ Found {len(actual_results.get('vulnerabilities', []))} vulnerabilities")
                                        print(f"[Fuzzing] ✅ Found {len(actual_results.get('crashes', []))} crashes")
                                        print(f"[Fuzzing] Risk score: {actual_results.get('statistics', {}).get('risk_score', 0)}/100")
                                    else:
                                        print(f"[Fuzzing] ⚠️  No success flag in results")
                                        fuzzing_state["results"] = {"error": "No valid results returned"}
                                else:
                                    print(f"[Fuzzing] ❌ Failed to get results: HTTP {results_response.status_code}")
                                    fuzzing_state["results"] = {"error": f"Failed to get results: HTTP {results_response.status_code}"}
                                
                                break
                            
                            elif current_status in ['failed', 'stopped']:
                                print(f"[Fuzzing] ❌ Job {current_status}")
                                fuzzing_state["results"] = {"error": f"Fuzzing {current_status}"}
                                break
                        
                        else:
                            print(f"[Fuzzing] ⚠️  Status check failed: HTTP {status_response.status_code}")
                            # Don't break, continue trying
                    
                    except requests.exceptions.Timeout:
                        print(f"[Fuzzing] ⚠️  Poll timeout at {poll_count}")
                        # Continue trying
                        continue
                    
                    except Exception as e:
                        print(f"[Fuzzing] Poll error: {e}")
                        # Don't break on poll error, continue trying
                        continue
                
                if poll_count >= max_polls:
                    total_time = poll_count * poll_interval
                    print(f"[Fuzzing] ⏱️  Max polls reached: {poll_count} polls ({total_time}s)")
                    fuzzing_state["results"] = {"error": f"Polling timeout after {total_time}s"}
                
            except requests.exceptions.Timeout as e:
                print(f"[Fuzzing Error] Request timeout: {e}")
                fuzzing_state["results"] = {"error": f"Request timeout: {e}"}
            
            except Exception as e:
                print(f"[Fuzzing Error] {e}")
                import traceback
                traceback.print_exc()
                fuzzing_state["results"] = {"error": str(e)}
            
            finally:
                fuzzing_state["running"] = False
                error_msg = fuzzing_state.get('results', {}).get('error', 'OK')
                print(f"[Fuzzing] Thread finished. Status: {error_msg}")
        
        thread = threading.Thread(target=run_fuzzing_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "success": True, 
            "message": f"Fuzzing started with {iterations} iterations (timeout: {timeout_seconds}s)"
        })
    
    except Exception as e:
        print(f"[Fuzz Error] {e}")
        import traceback
        traceback.print_exc()
        fuzzing_state["running"] = False
        return jsonify({"success": False, "error": str(e)})


@app.route("/fuzz/progress", methods=["GET"])
def fuzz_progress():
    """Lấy progress của fuzzing"""
    return jsonify({
        "running": fuzzing_state["running"],
        "progress": fuzzing_state["progress"],
        "total": fuzzing_state["total"],
        "message": fuzzing_state["message"],
        "results": fuzzing_state["results"],
        "job_id": fuzzing_state["job_id"]
    })


@app.route("/reports/<filename>")
def serve_report(filename):
    file_path = os.path.join(REPORT_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    return "Report not found", 404


@app.route("/clear_reports", methods=["POST"])
def clear_reports():
    try:
        if os.path.exists(REPORT_FOLDER):
            shutil.rmtree(REPORT_FOLDER)
            os.makedirs(REPORT_FOLDER)
        if os.path.exists(UPLOAD_FOLDER):
            shutil.rmtree(UPLOAD_FOLDER)
            os.makedirs(UPLOAD_FOLDER)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


def generate_html_report(results, timestamp):
    """Generate HTML report with syntax highlighting"""
    issues = results["issues"]
    total = len(issues)
    files_scanned = results["summary"]["files_scanned"]
    
    severity_counts = {
        "critical": sum(1 for i in issues if i.get("severity") == "critical"),
        "high": sum(1 for i in issues if i.get("severity") == "high"),
        "medium": sum(1 for i in issues if i.get("severity") == "medium"),
        "low": sum(1 for i in issues if i.get("severity") == "low"),
    }
    
    issues_by_file = {}
    for issue in issues:
        file = issue.get("file", "Unknown")
        if file not in issues_by_file:
            issues_by_file[file] = []
        issues_by_file[file].append(issue)
    
    issues_html = ""
    if total > 0:
        for file, file_issues in issues_by_file.items():
            issue_count = len(file_issues)
            issues_html += f"""
            <div style="margin: 40px 0; background: white; border-radius: 15px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h3 style="color: #333;">📄 {file} ({issue_count} issues)</h3>
            """
            
            for idx, issue in enumerate(file_issues, 1):
                severity = issue.get("severity", "low")
                color = {
                    "critical": "#dc3545", 
                    "high": "#fd7e14", 
                    "medium": "#ffc107", 
                    "low": "#28a745"
                }.get(severity, "#6c757d")
                
                # Get code context with line highlighting
                code_html = ""
                if issue.get('code'):
                    code_lines = issue['code'].split('\n')
                    error_line = issue.get('line', 0)
                    
                    code_html = '<div style="background: #2d2d2d; border-radius: 8px; padding: 15px; margin: 15px 0; overflow-x: auto;">'
                    code_html += '<pre style="margin: 0; color: #f8f8f2; font-family: \'Consolas\', \'Monaco\', monospace; font-size: 13px; line-height: 1.5;">'
                    
                    for line in code_lines:
                        # Extract line number from format "123: code here"
                        if ':' in line:
                            parts = line.split(':', 1)
                            try:
                                line_num = int(parts[0].strip())
                                line_content = parts[1] if len(parts) > 1 else ""
                                
                                # Highlight error line
                                if line_num == error_line:
                                    code_html += f'<span style="display: block; background: rgba(255, 0, 0, 0.2); border-left: 4px solid {color}; padding: 2px 8px; margin-left: -15px; padding-left: 11px;">'
                                    code_html += f'<span style="color: #ff6b6b; font-weight: bold;">{line_num}:</span>'
                                    code_html += f'<span style="color: #fff;">{html.escape(line_content)}</span>'
                                    code_html += f'<span style="color: #ff6b6b; margin-left: 10px;">← ⚠️ VULNERABILITY HERE</span>'
                                    code_html += '</span>\n'
                                else:
                                    code_html += f'<span style="color: #6c757d;">{line_num}:</span>'
                                    code_html += f'<span style="color: #f8f8f2;">{html.escape(line_content)}</span>\n'
                            except:
                                code_html += f'<span style="color: #f8f8f2;">{html.escape(line)}</span>\n'
                        else:
                            code_html += f'<span style="color: #f8f8f2;">{html.escape(line)}</span>\n'
                    
                    code_html += '</pre></div>'
                
                issues_html += f"""
                <div style="border-left: 5px solid {color}; padding: 20px; margin: 20px 0; background: #fafafa; border-radius: 0 8px 8px 0;">
                    <div style="margin-bottom: 15px;">
                        <span style="background: {color}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: 600; font-size: 12px;">{severity.upper()}</span>
                        <span style="color: #666; margin-left: 15px;">Line {issue.get('line', 'N/A')}</span>
                    </div>
                    <h4 style="color: #333; margin: 10px 0;">{idx}. {issue.get('message', 'Unknown issue')}</h4>
                    
                    {code_html}
                    
                    {f'''<div style="background: #e7f3ff; border-left: 4px solid #2196F3; padding: 15px; margin-top: 15px; border-radius: 4px;">
                        <strong style="color: #2196F3;">💡 How to Fix:</strong>
                        <p style="margin: 8px 0 0 0; color: #333;">{issue.get('recommendation', '')}</p>
                    </div>''' if issue.get('recommendation') else ''}
                </div>
                """
            
            issues_html += "</div>"
    
    # Add import for html.escape at the top of function
    
    html_content = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PyScan Security Report - {timestamp}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ 
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
        padding: 20px; 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
    }}
    .container {{
        max-width: 1400px; 
        margin: 0 auto; 
        background: white; 
        padding: 40px; 
        border-radius: 20px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }}
    h1 {{ 
        color: #667eea; 
        font-size: 2.5em; 
        margin-bottom: 10px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }}
    .timestamp {{ color: #666; margin-bottom: 30px; }}
    .stats-grid {{ 
        display: grid; 
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
        gap: 20px; 
        margin: 30px 0; 
    }}
    .stat-card {{ 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white; 
        padding: 25px; 
        border-radius: 15px; 
        text-align: center;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
    }}
    .stat-card h2 {{ font-size: 2.5em; margin-bottom: 5px; }}
    .stat-card p {{ font-size: 0.9em; opacity: 0.9; }}
    
    .severity-grid {{ 
        display: grid; 
        grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); 
        gap: 15px; 
        margin: 20px 0; 
    }}
    .severity-card {{ 
        color: white; 
        padding: 20px; 
        border-radius: 12px; 
        text-align: center;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    }}
    .severity-card h3 {{ font-size: 2em; margin-bottom: 5px; }}
    
    h2 {{ color: #333; margin: 40px 0 20px 0; font-size: 1.8em; }}
    
    @media print {{
        body {{ background: white; }}
        .container {{ box-shadow: none; }}
    }}
</style>
</head>
<body>
<div class="container">
    <h1>🔒 PyScan Security Report</h1>
    <p class="timestamp">Generated: {timestamp}</p>
    
    <div class="stats-grid">
        <div class="stat-card">
            <h2>{files_scanned}</h2>
            <p>Files Scanned</p>
        </div>
        <div class="stat-card">
            <h2>{total}</h2>
            <p>Total Issues</p>
        </div>
    </div>
    
    <h2>Severity Breakdown</h2>
    <div class="severity-grid">
        <div class="severity-card" style="background: #dc3545;">
            <h3>{severity_counts['critical']}</h3>
            <p>Critical</p>
        </div>
        <div class="severity-card" style="background: #fd7e14;">
            <h3>{severity_counts['high']}</h3>
            <p>High</p>
        </div>
        <div class="severity-card" style="background: #ffc107; color: #333;">
            <h3>{severity_counts['medium']}</h3>
            <p>Medium</p>
        </div>
        <div class="severity-card" style="background: #28a745;">
            <h3>{severity_counts['low']}</h3>
            <p>Low</p>
        </div>
    </div>
    
    <h2>📋 Detailed Issues</h2>
    {issues_html if issues_html else '<p style="text-align: center; color: #28a745; font-size: 1.2em; padding: 40px;">✅ No issues found! Your code is clean.</p>'}
</div>
</body>
</html>"""
    
    return html_content

if __name__ == "__main__":
    print("=" * 70)
    print("🔒 PyScan Pro v3.4.0-FIXED - WITH REAL ATHERIS FUZZING")
    print("=" * 70)
    print(f"🌐 Web: http://127.0.0.1:5000")
    print(f"🔥 Fuzzing: {FUZZING_SERVICE_URL}")
    print("=" * 70)
    print("✅ Extended timeouts for Atheris fuzzing")
    print("✅ Better progress tracking")
    print("✅ Improved error handling")
    print("=" * 70)
    
    app.run(host="0.0.0.0", port=5000, debug=True)