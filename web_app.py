# web_app.py - FIXED VERSION WITH COMPLETE HTML REPORTS
from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import zipfile
import tempfile
from datetime import datetime
import shutil
from pathlib import Path
from analyzer.core import Analyzer
from analyzer.fuzzing import run_fuzz_on_analyzer, is_fuzzing_available
import threading

app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, "uploads")
REPORT_FOLDER = os.path.join(APP_ROOT, "web_reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

analyzer = Analyzer()
APP_VERSION = "2.1.0"

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
    """Quét code Python - hỗ trợ paste, single file, và ZIP"""
    results = {"issues": [], "summary": {"total": 0, "files_scanned": 0}}
    temp_extract_path = None

    try:
        paste_code = request.form.get("paste_code", "").strip()
        uploaded_file = request.files.get("file")
        scan_project = request.form.get("scan_project") == "true"

        # 1. Quét từ paste code
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

        # 2. Quét file upload (Python file hoặc ZIP)
        elif uploaded_file:
            filename = uploaded_file.filename
            
            # Kiểm tra file ZIP
            if filename.endswith(".zip"):
                print("[Web] Đang xử lý file ZIP...")
                temp_extract_path = tempfile.mkdtemp()
                zip_path = os.path.join(UPLOAD_FOLDER, filename)
                uploaded_file.save(zip_path)
                
                # Giải nén
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_extract_path)
                
                # Quét tất cả file .py trong ZIP
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
                                print(f"[Error] Không quét được {rel_path}: {e}")
                
                # Cleanup
                os.unlink(zip_path)
                shutil.rmtree(temp_extract_path)
            
            # File Python đơn
            elif filename.endswith(".py"):
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                uploaded_file.save(save_path)
                
                issues = analyzer.analyze_file(save_path)
                for issue in issues:
                    issue["file"] = filename
                results["issues"] = issues
                results["summary"]["files_scanned"] = 1
            else:
                return jsonify({
                    "success": False,
                    "error": "Chỉ chấp nhận file .py hoặc .zip"
                })

        # 3. Quét toàn bộ project
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
                            print(f"[Error] Không quét được {rel_path}: {e}")

        results["summary"]["total"] = len(results["issues"])

        # Tạo báo cáo
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_name = f"report_{now}.json"
        html_name = f"report_{now}.html"

        json_path = os.path.join(REPORT_FOLDER, json_name)
        html_path = os.path.join(REPORT_FOLDER, html_name)

        # Lưu JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # Tạo HTML report
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
        
        # Cleanup nếu có lỗi
        if temp_extract_path and os.path.exists(temp_extract_path):
            shutil.rmtree(temp_extract_path)
        
        return jsonify({"success": False, "error": str(e)})


@app.route("/fuzz", methods=["POST"])
def fuzz():
    """Chạy fuzzing với progress tracking"""
    global fuzzing_state
    
    if fuzzing_state["running"]:
        return jsonify({
            "success": False,
            "error": "Fuzzing đang chạy! Vui lòng đợi..."
        })
    
    try:
        iterations = int(request.form.get("iterations", 1000))
        
        if not is_fuzzing_available():
            return jsonify({
                "success": False,
                "error": "Fuzzing engine không khả dụng"
            })
        
        # Reset state
        fuzzing_state["running"] = True
        fuzzing_state["progress"] = 0
        fuzzing_state["total"] = iterations
        fuzzing_state["message"] = "Starting fuzzing..."
        fuzzing_state["results"] = None
        
        # Chạy fuzzing trong thread riêng
        def run_fuzzing_thread():
            global fuzzing_state
            
            def progress_callback(current, total, message):
                fuzzing_state["progress"] = current
                fuzzing_state["total"] = total
                fuzzing_state["message"] = message
            
            try:
                results = run_fuzz_on_analyzer(iterations, callback=progress_callback)
                fuzzing_state["results"] = results
                fuzzing_state["message"] = "Fuzzing complete!"
            except Exception as e:
                fuzzing_state["results"] = {"error": str(e)}
                fuzzing_state["message"] = f"Fuzzing failed: {str(e)}"
            finally:
                fuzzing_state["running"] = False
        
        thread = threading.Thread(target=run_fuzzing_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "success": True,
            "message": "Fuzzing started! Check progress..."
        })
    
    except Exception as e:
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
        "results": fuzzing_state["results"]
    })


@app.route("/reports/<filename>")
def serve_report(filename):
    """Phục vụ file report"""
    file_path = os.path.join(REPORT_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    return "Report not found", 404


@app.route("/clear_reports", methods=["POST"])
def clear_reports():
    """Xóa tất cả reports"""
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
    """Tạo HTML report ĐẦY ĐỦ với tất cả issues"""
    issues = results["issues"]
    total = len(issues)
    files_scanned = results["summary"]["files_scanned"]
    
    # Phân loại theo severity
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
    
    # HTML template - ĐẦY ĐỦ
    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PyScan Pro Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ 
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        h1 {{ 
            color: #667eea;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
            font-weight: 700;
        }}
        .subtitle {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card h3 {{ font-size: 2.5em; margin-bottom: 5px; font-weight: 700; }}
        .stat-card p {{ opacity: 0.9; font-size: 1.1em; }}
        .stat-card.critical {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }}
        .stat-card.high {{ background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); }}
        .stat-card.medium {{ background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); }}
        .stat-card.low {{ background: linear-gradient(135deg, #6c757d 0%, #495057 100%); }}
        
        .file-section {{
            margin: 30px 0;
            background: #f8f9fa;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .file-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-weight: 600;
            font-size: 1.2em;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .issue-count {{
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        
        .issue {{
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-left: 5px solid #667eea;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: all 0.3s;
        }}
        .issue:hover {{
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        .issue.critical {{ border-left-color: #dc3545; background: #fff5f5; }}
        .issue.high {{ border-left-color: #fd7e14; background: #fff8f0; }}
        .issue.medium {{ border-left-color: #ffc107; background: #fffef0; }}
        .issue.low {{ border-left-color: #6c757d; background: #f8f9fa; }}
        
        .issue-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .severity-badge.critical {{ background: #dc3545; color: white; }}
        .severity-badge.high {{ background: #fd7e14; color: white; }}
        .severity-badge.medium {{ background: #ffc107; color: #000; }}
        .severity-badge.low {{ background: #6c757d; color: white; }}
        
        .issue-meta {{
            color: #666;
            font-size: 0.9em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .issue-message {{
            font-size: 1.1em;
            color: #333;
            margin: 12px 0;
            font-weight: 500;
            line-height: 1.6;
        }}
        .category-tag {{
            background: #e9ecef;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            color: #495057;
        }}
        .recommendation {{
            margin-top: 12px;
            padding: 15px;
            background: #d4edda;
            border-left: 4px solid #28a745;
            border-radius: 8px;
            color: #155724;
        }}
        .recommendation strong {{
            color: #28a745;
            display: block;
            margin-bottom: 5px;
        }}
        
        .no-issues {{
            text-align: center;
            padding: 80px 20px;
            color: #28a745;
        }}
        .no-issues h2 {{
            font-size: 4em;
            margin-bottom: 20px;
        }}
        .no-issues p {{
            font-size: 1.5em;
            color: #666;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid #eee;
            color: #666;
        }}
        .footer p {{ margin: 5px 0; }}
        
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .issue {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 PyScan Pro Report</h1>
        <p class="subtitle">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <div class="stat-card">
                <h3>{files_scanned}</h3>
                <p>Files Scanned</p>
            </div>
            <div class="stat-card">
                <h3>{total}</h3>
                <p>Total Issues</p>
            </div>
            <div class="stat-card critical">
                <h3>{severity_counts['critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card high">
                <h3>{severity_counts['high']}</h3>
                <p>High</p>
            </div>
            <div class="stat-card medium">
                <h3>{severity_counts['medium']}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-card low">
                <h3>{severity_counts['low']}</h3>
                <p>Low</p>
            </div>
        </div>
"""
    
    if not issues:
        html += """
        <div class="no-issues">
            <h2>✅</h2>
            <p><strong>Excellent!</strong></p>
            <p>No security issues detected!</p>
            <p style="font-size: 1em; margin-top: 20px; color: #999;">Your code passed all security checks.</p>
        </div>
"""
    else:
        html += '<h2 style="margin: 40px 0 25px 0; color: #333; font-size: 2em;">📋 Detected Issues by File</h2>'
        
        for file, file_issues in issues_by_file.items():
            html += f"""
        <div class="file-section">
            <div class="file-header">
                <span>📄 {file}</span>
                <span class="issue-count">{len(file_issues)} issue{"s" if len(file_issues) > 1 else ""}</span>
            </div>
"""
            
            for issue in file_issues:
                severity = issue.get("severity", "low")
                message = issue.get("message", "Unknown issue")
                line = issue.get("line", "?")
                category = issue.get("category", "")
                recommendation = issue.get("recommendation", "")
                cwe = issue.get("cwe_id", "")
                
                html += f"""
            <div class="issue {severity}">
                <div class="issue-header">
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <span class="severity-badge {severity}">{severity}</span>
                        {f'<span class="category-tag">{category}</span>' if category else ''}
                        {f'<span class="category-tag">{cwe}</span>' if cwe else ''}
                    </div>
                    <span class="issue-meta">
                        <span>📍 Line {line}</span>
                    </span>
                </div>
                <div class="issue-message">{message}</div>
                {f'<div class="recommendation"><strong>💡 Recommendation:</strong> {recommendation}</div>' if recommendation else ''}
            </div>
"""
            
            html += "</div>"  # Close file-section
    
    html += """
        <div class="footer">
            <p style="font-size: 1.2em;"><strong>PyScan Pro v2.1</strong> - Python Static Analysis Security Tool</p>
            <p>Powered by AST Analysis • Taint Tracking • Regex Patterns • Fuzzing Engine</p>
            <p style="margin-top: 10px; color: #999;">Cross-Platform • Windows Compatible • Open Source</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


if __name__ == "__main__":
    print("=" * 70)
    print("🔒 PyScan Pro v2.1 - Python Security Analyzer")
    print("=" * 70)
    print(f"📁 Project: {APP_ROOT}")
    print(f"🌐 Web: http://127.0.0.1:5000")
    print(f"🔥 Fuzzing: Native Python (Cross-platform)")
    print("=" * 70)
    
    app.run(host="0.0.0.0", port=5000, debug=True)