#!/usr/bin/env python3
# gui_tk.py
# Simple Tkinter GUI wrapper for the python_static_analyzer CLI.
# Usage: python gui_tk.py
import threading
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import webbrowser
# ensure project root in path so imports work when launching from the project dir
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from cli import scan  # import the scan function

class AnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Python Static Analyzer - GUI")
        self.geometry("900x600")

        self.path_var = tk.StringVar(value=PROJECT_ROOT)
        self.rules_var = tk.StringVar(value=os.path.join(PROJECT_ROOT, "custom_rules.json"))
        self.status_var = tk.StringVar(value="Ready")

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(frm)
        top.pack(fill=tk.X, pady=(0,10))

        ttk.Label(top, text="Scan path:").pack(side=tk.LEFT)
        self.path_entry = ttk.Entry(top, textvariable=self.path_var, width=60)
        self.path_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Browse", command=self.browse_path).pack(side=tk.LEFT, padx=4)

        ttk.Label(top, text="Rules:").pack(side=tk.LEFT, padx=(12,0))
        self.rules_entry = ttk.Entry(top, textvariable=self.rules_var, width=40)
        self.rules_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Browse", command=self.browse_rules).pack(side=tk.LEFT, padx=4)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=(0,10))
        self.run_btn = ttk.Button(btn_frame, text="Run Scan", command=self.run_scan)
        self.run_btn.pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Open HTML Report", command=self.open_report).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Open JSON Report", command=self.open_json).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Exit", command=self.quit).pack(side=tk.RIGHT)

        # Treeview for results
        self.tree = ttk.Treeview(frm, columns=("file","line","type","severity","msg"), show="headings")
        self.tree.heading("file", text="File")
        self.tree.heading("line", text="Line")
        self.tree.heading("type", text="Type")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("msg", text="Message")
        self.tree.column("file", width=240)
        self.tree.column("line", width=50, anchor="center")
        self.tree.column("type", width=120)
        self.tree.column("severity", width=80, anchor="center")
        self.tree.column("msg", width=380)
        self.tree.pack(fill=tk.BOTH, expand=True)

        status = ttk.Frame(self)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT, padx=8, pady=4)

        # paths for reports
        self.html_report = os.path.join(PROJECT_ROOT, "report.html")
        self.json_report = os.path.join(PROJECT_ROOT, "report.json")

    def browse_path(self):
        p = filedialog.askdirectory(initialdir=self.path_var.get() or PROJECT_ROOT)
        if p:
            self.path_var.set(p)

    def browse_rules(self):
        p = filedialog.askopenfilename(filetypes=[("JSON files","*.json")], initialdir=PROJECT_ROOT)
        if p:
            self.rules_var.set(p)

    def run_scan(self):
        path = self.path_var.get().strip()
        rules = self.rules_var.get().strip() or None
        if not path:
            messagebox.showwarning("Select path", "Please select a file or directory to scan.")
            return
        # disable button while running
        self.run_btn.config(state=tk.DISABLED)
        self.status_var.set("Running scan...")
        self.tree.delete(*self.tree.get_children())
        thread = threading.Thread(target=self._run_scan_thread, args=(path, rules), daemon=True)
        thread.start()

    def _run_scan_thread(self, path, rules):
        try:
            # scan expects list of paths
            res = scan([path], rules=rules)
            issues = res.get("issues", [])
            # write reports
            try:
                import json
                with open(self.json_report, "w", encoding="utf-8") as fh:
                    json.dump(res, fh, indent=2, ensure_ascii=False)
                # build html quickly similar to reporter
                from reporter.html_report import build_html_report
                html = build_html_report(res)
                with open(self.html_report, "w", encoding='utf-8') as fh:
                    fh.write(html)
            except Exception as e:
                print("Failed to write reports:", e)
            # update UI in main thread
            self.after(0, self._show_results, issues)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.after(0, lambda: self.run_btn.config(state=tk.NORMAL))
            self.after(0, lambda: self.status_var.set("Ready"))

    def _show_results(self, issues):
        for it in issues:
            self.tree.insert("", "end", values=(it.get("file",""), it.get("lineno",0), it.get("type",""), it.get("severity",""), it.get("msg","")))
        self.status_var.set(f"Found {len(issues)} issue(s).")

    def open_report(self):
        if os.path.exists(self.html_report):
            webbrowser.open("file://" + os.path.abspath(self.html_report))
        else:
            messagebox.showinfo("No report", "HTML report not found. Run a scan first.")

    def open_json(self):
        if os.path.exists(self.json_report):
            os.startfile(self.json_report) if sys.platform.startswith("win") else webbrowser.open("file://" + os.path.abspath(self.json_report))
        else:
            messagebox.showinfo("No report", "JSON report not found. Run a scan first.")

if __name__ == "__main__":
    app = AnalyzerGUI()
    app.mainloop()
