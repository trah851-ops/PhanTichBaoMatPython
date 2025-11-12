#!/usr/bin/env python3
# web_app.py - Flask web UI for python_static_analyzer
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
import os, io, json, tempfile, datetime
from analyzer.core import analyze_code, analyze_file
from reporter.html_report import build_html_report
from werkzeug.utils import secure_filename

app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, "uploads")
REPORT_FOLDER = os.path.join(APP_ROOT, "web_reports")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    # Accept either uploaded file(s) or pasted code
    rules = request.form.get("rules") or os.path.join(APP_ROOT, "custom_rules.json")
    # handle paste
    paste_code = request.form.get("paste_code","").strip()
    uploaded = request.files.get("file")
    results = {"issues": [], "summary": {"total":0}}
    try:
        if paste_code:
            res = analyze_code(paste_code, filename="pasted_code.py", rules_path=rules)
            results = res
        elif uploaded and uploaded.filename:
            filename = secure_filename(uploaded.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            uploaded.save(save_path)
            res = analyze_file(save_path, rules_path=rules)
            # attach filename to each issue for display
            for it in res["issues"]:
                it["file"] = filename
            results = res
        else:
            # if neither, scan project root
            res = {"issues": [], "summary": {"total": 0}}
            # scan files under APP_ROOT (but avoid node_modules/.git)
            for root, dirs, files in os.walk(APP_ROOT):
                # skip web_reports and uploads
                if root.startswith(REPORT_FOLDER) or root.startswith(UPLOAD_FOLDER):
                    continue
                for f in files:
                    if f.endswith(".py"):
                        p = os.path.join(root, f)
                        r = analyze_file(p, rules_path=rules)
                        for it in r["issues"]:
                            it["file"] = os.path.relpath(p, APP_ROOT)
                            results["issues"].append(it)
            results["summary"]["total"] = len(results["issues"])
        # write JSON and HTML reports with timestamp
        now = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        json_path = os.path.join(REPORT_FOLDER, f"report_{now}.json")
        html_path = os.path.join(REPORT_FOLDER, f"report_{now}.html")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        html = build_html_report(results, title=f"Static Analysis Report - {now}")
        with open(html_path, "w", encoding='utf-8') as fh:
            fh.write(html)
        return jsonify({"ok": True, "html": os.path.basename(html_path), "json": os.path.basename(json_path), "issues": results["summary"].get("total",0)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/reports/<name>")
def reports(name):
    p = os.path.join(REPORT_FOLDER, name)
    if os.path.exists(p):
        return send_file(p)
    return "Report not found", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
