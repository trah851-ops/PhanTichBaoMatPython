# web_app.py - COMPLETELY FIXED VERSION v2.2.2
from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import zipfile
import tempfile
from datetime import datetime
import shutil
from pathlib import Path
from analyzer.core import Analyzer
from analyzer.fuzzing import fuzz_user_code, fuzz_uploaded_file, is_fuzzing_available
import threading
import time

app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, "uploads")
REPORT_FOLDER = os.path.join(APP_ROOT, "web_reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

analyzer = Analyzer()
APP_VERSION = "2.2.2"

# Global fuzzing state
fuzzing_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "message": "",
    "results": None
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
                
                # Cleanup
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
    """Fuzzing - FIXED: Save file FIRST before threading"""
    global fuzzing_state
    
    if fuzzing_state["running"]:
        return jsonify({"success": False, "error": "Fuzzing đang chạy!"})
    
    try:
        iterations = int(request.form.get("iterations", 100))
        code = request.form.get("code", "").strip()
        uploaded_file = request.files.get("fuzz_file")
        
        # Check có input không
        if not code and not uploaded_file:
            return jsonify({"success": False, "error": "Vui lòng paste code hoặc upload file!"})
        
        if not is_fuzzing_available():
            return jsonify({"success": False, "error": "Fuzzing engine không khả dụng"})
        
        # CRITICAL FIX: Save file IMMEDIATELY, BEFORE threading
        saved_file_path = None
        if uploaded_file:
            filename = uploaded_file.filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            safe_filename = f"fuzz_{timestamp}_{filename}"
            saved_file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
            
            # Save ngay lập tức
            uploaded_file.save(saved_file_path)
            uploaded_file.close()  # Close file object
            
            # Verify file exists
            if not os.path.exists(saved_file_path):
                return jsonify({"success": False, "error": "Không thể save file"})
            
            print(f"[Fuzzing] File saved: {saved_file_path} ({os.path.getsize(saved_file_path)} bytes)")
        
        # Reset state
        fuzzing_state["running"] = True
        fuzzing_state["progress"] = 0
        fuzzing_state["total"] = iterations
        fuzzing_state["message"] = "Starting fuzzing..."
        fuzzing_state["results"] = None
        
        # Chạy fuzzing trong thread riêng
        def run_fuzzing_thread(file_path, code_str):
            global fuzzing_state
            
            def progress_callback(current, total, message):
                fuzzing_state["progress"] = current
                fuzzing_state["total"] = total
                fuzzing_state["message"] = message
            
            try:
                # Fuzzing từ file đã save
                if file_path:
                    print(f"[Fuzzing] Starting fuzz on: {file_path}")
                    results = fuzz_uploaded_file(file_path, iterations, callback=progress_callback)
                # Fuzzing từ paste code
                else:
                    print("[Fuzzing] Starting fuzz on pasted code")
                    results = fuzz_user_code(code_str, iterations, callback=progress_callback)
                
                fuzzing_state["results"] = results
                fuzzing_state["message"] = "Fuzzing complete!"
                print("[Fuzzing] Completed successfully")
                
            except Exception as e:
                import traceback
                error_detail = traceback.format_exc()
                print(f"[Fuzzing Error] {error_detail}")
                fuzzing_state["results"] = {"error": str(e)}
                fuzzing_state["message"] = f"Fuzzing failed: {str(e)}"
            finally:
                fuzzing_state["running"] = False
                
                # Cleanup file sau khi fuzz xong
                if file_path:
                    try:
                        time.sleep(1)  # Đợi 1s để đảm bảo file không còn đang được dùng
                        if os.path.exists(file_path):
                            os.unlink(file_path)
                            print(f"[Fuzzing] Cleaned up: {file_path}")
                    except Exception as cleanup_error:
                        print(f"[Fuzzing] Cleanup error: {cleanup_error}")
        
        # Start thread với file đã save hoặc code
        thread = threading.Thread(target=run_fuzzing_thread, args=(saved_file_path, code))
        thread.daemon = True
        thread.start()
        
        return jsonify({"success": True, "message": "Fuzzing started!"})
    
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        fuzzing_state["running"] = False
        
        # Cleanup nếu có lỗi
        if 'saved_file_path' in locals() and saved_file_path and os.path.exists(saved_file_path):
            try:
                os.unlink(saved_file_path)
            except:
                pass
        
        return jsonify({"success": False, "error": str(e)})


@app.route("/fuzz/progress", methods=["GET"])
def fuzz_progress():
    """Lấy progress của fuzzing"""
    return jsonify({
        "running": fuzzing_state["running"],
        "progress": fuzzing_state["progress"],
        "total": fuzzing_state["total"],
        "message": fuzzing_state["message"],
        "results": fuzzing_state["results"]
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


def get_code_context(file_path, line_num, context_lines=2):
    """Lấy code context xung quanh line bị lỗi"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        context = []
        for i in range(start, end):
            line_content = lines[i].rstrip()
            is_error_line = (i == line_num - 1)
            context.append({
                'num': i + 1,
                'content': line_content,
                'is_error': is_error_line
            })
        
        return context
    except Exception as e:
        print(f"Error getting context: {e}")
        return []


def generate_html_report(results, timestamp):
    """Generate complete HTML report with CODE CONTEXT"""
    issues = results["issues"]
    total = len(issues)
    files_scanned = results["summary"]["files_scanned"]
    
    # Calculate severity counts
    severity_counts = {
        "critical": sum(1 for i in issues if i.get("severity") == "critical"),
        "high": sum(1 for i in issues if i.get("severity") == "high"),
        "medium": sum(1 for i in issues if i.get("severity") == "medium"),
        "low": sum(1 for i in issues if i.get("severity") == "low"),
    }
    
    # Group issues by file
    issues_by_file = {}
    for issue in issues:
        file = issue.get("file", "Unknown")
        if file not in issues_by_file:
            issues_by_file[file] = []
        issues_by_file[file].append(issue)
    
    # Build detailed issues HTML
    issues_html = ""
    if total > 0:
        for file, file_issues in issues_by_file.items():
            # File header với count
            issue_count = len(file_issues)
            issues_html += f"""
            <div style="margin: 40px 0; background: white; border-radius: 15px; padding: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 25px; padding-bottom: 15px; border-bottom: 3px solid #667eea;">
                    <h3 style="color: #667eea; font-size: 1.6em; margin: 0; flex: 1;">📄 {file}</h3>
                    <span style="background: #dc3545; color: white; padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 0.9em;">
                        {issue_count} issue{"s" if issue_count > 1 else ""}
                    </span>
                </div>
            """
            
            for idx, issue in enumerate(file_issues, 1):
                severity = issue.get("severity", "low")
                severity_colors = {
                    "critical": "#dc3545",
                    "high": "#fd7e14",
                    "medium": "#ffc107",
                    "low": "#28a745"
                }
                color = severity_colors.get(severity, "#6c757d")
                
                line = issue.get('line', 'N/A')
                column = issue.get('column', 'N/A')
                
                issues_html += f"""
                <div style="background: #f8f9fa; border-left: 5px solid {color}; padding: 25px; margin: 20px 0; border-radius: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; flex-wrap: wrap; gap: 15px; margin-bottom: 15px;">
                        <div style="flex: 1;">
                            <div style="display: inline-block; background: {color}; color: white; padding: 6px 18px; border-radius: 20px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; margin-bottom: 12px;">
                                {severity}
                            </div>
                            <h4 style="font-size: 1.2em; margin: 10px 0; color: #333;">
                                {idx}. {issue.get('message', 'Unknown issue')}
                            </h4>
                        </div>
                        <div style="background: white; padding: 12px 20px; border-radius: 10px; border: 2px solid {color};">
                            <strong style="color: {color}; font-size: 1.1em;">
                                Line {line}, Col {column}
                            </strong>
                        </div>
                    </div>
                """
                
                # CODE CONTEXT với highlight
                if issue.get('code'):
                    code_escaped = issue['code'].replace('<', '&lt;').replace('>', '&gt;')
                    issues_html += f"""
                    <div style="background: white; padding: 20px; border-radius: 8px; margin: 15px 0; border: 1px solid #ddd;">
                        <div style="color: #666; font-size: 0.85em; font-weight: 600; margin-bottom: 10px; text-transform: uppercase;">
                            ⚠️ Problematic Code:
                        </div>
                        <pre style="background: #2d2d2d; color: #f8f8f2; padding: 20px; border-radius: 8px; overflow-x: auto; margin: 0; border-left: 4px solid {color};"><code style="font-family: 'Courier New', monospace; font-size: 0.95em; line-height: 1.6;">{code_escaped}</code></pre>
                    </div>
                    """
                
                # RECOMMENDATION
                if issue.get('recommendation'):
                    issues_html += f"""
                    <div style="background: linear-gradient(135deg, #e7f3ff 0%, #d4e9ff 100%); border-left: 4px solid #2196F3; padding: 20px; margin-top: 15px; border-radius: 8px;">
                        <div style="display: flex; align-items: start; gap: 12px;">
                            <span style="font-size: 1.5em;">💡</span>
                            <div>
                                <strong style="color: #2196F3; font-size: 1.05em; display: block; margin-bottom: 8px;">
                                    How to Fix:
                                </strong>
                                <p style="margin: 0; color: #333; line-height: 1.7; font-size: 0.95em;">
                                    {issue['recommendation']}
                                </p>
                            </div>
                        </div>
                    </div>
                    """
                
                issues_html += "</div>"
            
            issues_html += "</div>"
    else:
        issues_html = """
        <div style="text-align: center; padding: 80px 30px; background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); border-radius: 20px; margin: 40px 0; box-shadow: 0 8px 25px rgba(0,0,0,0.1);">
            <div style="font-size: 5em; margin-bottom: 25px;">✅</div>
            <h2 style="color: #28a745; font-size: 2.8em; margin-bottom: 20px; font-weight: 700;">No Issues Found!</h2>
            <p style="font-size: 1.3em; color: #155724; line-height: 1.8;">Your code appears to be clean and secure.</p>
        </div>
        """
    
    # Generate full HTML
    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PyScan Pro Security Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            padding: 20px; 
            line-height: 1.6; 
            color: #333;
        }}
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background: #fafafa; 
            border-radius: 25px; 
            padding: 50px; 
            box-shadow: 0 25px 70px rgba(0,0,0,0.3); 
        }}
        h1 {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-align: center; 
            font-size: 3.2em; 
            margin-bottom: 15px;
            font-weight: 800;
        }}
        .timestamp {{
            text-align: center;
            color: #666;
            font-size: 1.1em;
            margin-bottom: 50px;
            font-weight: 500;
        }}
        .summary {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); 
            gap: 25px; 
            margin: 40px 0; 
        }}
        .stat-card {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 35px; 
            border-radius: 18px; 
            text-align: center;
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.35);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 15px 35px rgba(102, 126, 234, 0.45);
        }}
        .stat-card h3 {{ font-size: 3.5em; margin-bottom: 10px; font-weight: 800; }}
        .stat-card p {{ font-size: 1.1em; opacity: 0.95; font-weight: 600; }}
        .section-title {{
            color: #333;
            font-size: 2.3em;
            margin: 60px 0 30px 0;
            padding-bottom: 20px;
            border-bottom: 4px solid #667eea;
            font-weight: 700;
        }}
        .severity-breakdown {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 25px;
            margin: 35px 0;
        }}
        .severity-card {{
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            color: white;
            box-shadow: 0 6px 20px rgba(0,0,0,0.25);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .severity-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 12px 30px rgba(0,0,0,0.35);
        }}
        .severity-card h4 {{ font-size: 3em; margin-bottom: 10px; font-weight: 800; }}
        .severity-card p {{ font-size: 1.1em; opacity: 0.95; font-weight: 600; }}
        .critical {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }}
        .high {{ background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); }}
        .medium {{ background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); }}
        .low {{ background: linear-gradient(135deg, #28a745 0%, #218838 100%); }}
        .footer {{
            text-align: center;
            margin-top: 70px;
            padding-top: 35px;
            border-top: 3px solid #ddd;
            color: #666;
            font-size: 1em;
        }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .stat-card, .severity-card {{ box-shadow: none; }}
        }}
        @media (max-width: 768px) {{
            .container {{ padding: 25px; }}
            h1 {{ font-size: 2em; }}
            .section-title {{ font-size: 1.6em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 PyScan Pro Security Report</h1>
        <p class="timestamp">📅 Generated: {timestamp.replace('_', ' ')}</p>
        
        <div class="summary">
            <div class="stat-card">
                <h3>{files_scanned}</h3>
                <p>Files Scanned</p>
            </div>
            <div class="stat-card">
                <h3>{total}</h3>
                <p>Total Issues</p>
            </div>
        </div>
        
        <h2 class="section-title">📊 Severity Breakdown</h2>
        <div class="severity-breakdown">
            <div class="severity-card critical">
                <h4>{severity_counts['critical']}</h4>
                <p>Critical</p>
            </div>
            <div class="severity-card high">
                <h4>{severity_counts['high']}</h4>
                <p>High</p>
            </div>
            <div class="severity-card medium">
                <h4>{severity_counts['medium']}</h4>
                <p>Medium</p>
            </div>
            <div class="severity-card low">
                <h4>{severity_counts['low']}</h4>
                <p>Low</p>
            </div>
        </div>
        
        <h2 class="section-title">🔍 Detailed Issues by File</h2>
        {issues_html}
        
        <div class="footer">
            <p style="font-weight: 700; font-size: 1.2em; margin-bottom: 10px;">Generated by PyScan Pro v{APP_VERSION}</p>
            <p style="color: #999;">Python Security Scanner & Fuzzing Tool</p>
            <p style="margin-top: 15px; color: #999; font-size: 0.9em;">Report contains detailed analysis with line numbers and fix recommendations</p>
        </div>
    </div>
</body>
</html>"""
    return html


if __name__ == "__main__":
    print("=" * 70)
    print("🔒 PyScan Pro v2.2.2 - Security Analyzer + Fuzzing")
    print("=" * 70)
    print(f"📁 Project: {APP_ROOT}")
    print(f"🌐 Web Interface: http://127.0.0.1:5000")
    print(f"🔥 Fuzzing Support: Code / .py File / .zip Project")
    print(f"📊 Reports: HTML + JSON with line numbers")
    print("=" * 70)
    print("\n✅ Server is ready! Open browser and go to http://127.0.0.1:5000\n")
    
    app.run(host="0.0.0.0", port=5000, debug=True)