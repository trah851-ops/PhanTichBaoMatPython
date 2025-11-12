# reporter/html_report.py
import html
import json
from datetime import datetime
from typing import Dict, Any

def severity_class(sev: str) -> str:
    s = (sev or "").strip().lower()
    if s == "high": return "high"
    if s == "medium": return "medium"
    return "low"

def severity_badge(sev: str) -> str:
    s = severity_class(sev)
    if s == "high": return '<span class="badge bg-danger">High</span>'
    if s == "medium": return '<span class="badge bg-warning text-dark">Medium</span>'
    return '<span class="badge bg-success">Low</span>'

def build_html_report(result: Dict[str, Any], title: str = "PyScan - Static Analysis Report") -> str:
    issues = result.get("issues", [])
    summary = result.get("summary", {})
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(issues)

    # ✅ Tự đếm số lượng lỗi theo mức độ
    high = sum(1 for i in issues if i.get("severity", "").lower() == "high")
    medium = sum(1 for i in issues if i.get("severity", "").lower() == "medium")
    low = sum(1 for i in issues if i.get("severity", "").lower() == "low")
    parts = []

    # === HTML Head ===
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang='en'>")
    parts.append("<head>")
    parts.append("  <meta charset='utf-8'>")
    parts.append("  <meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"  <title>{html.escape(title)}</title>")

    # Bootstrap 5 + Icons + DataTables
    parts.append("  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>")
    parts.append("  <link href='https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css' rel='stylesheet'>")
    parts.append("  <link href='https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css' rel='stylesheet'>")
    parts.append("  <link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap' rel='stylesheet'>")
    parts.append("  <link href='https://cdn.jsdelivr.net/npm/firacode@6.2.0/distr/css/fira_code.css' rel='stylesheet'>")

    # === Custom Styles ===
    parts.append("<style>")
    parts.append("  :root { --bs-body-font-family: 'Inter', sans-serif; }")
    parts.append("  body { background: linear-gradient(135deg, #f5f7fa 0%, #e4edf5 100%); color: #2d3436; }")
    parts.append("  .dark-mode { background: #0f0f0f !important; color: #e0e0e0; }")
    parts.append("  .dark-mode .card, .dark-mode .table { background: #1e1e1e; border-color: #333; color: #ddd; }")
    parts.append("  .dark-mode .table-striped > tbody > tr:nth-of-type(odd) > * { background-color: #252525; }")
    parts.append("  .card { border: none; border-radius: 16px; box-shadow: 0 8px 25px rgba(0,0,0,0.08); }")
    parts.append("  .hero-title { font-weight: 700; font-size: 2.5rem; background: linear-gradient(90deg, #4361ee, #7209b7);")
    parts.append("    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }")
    parts.append("  .severity-high { background: #ffe6e9; border-left: 4px solid #ef476f; }")
    parts.append("  .severity-medium { background: #fff7e6; border-left: 4px solid #ffd166; }")
    parts.append("  .severity-low { background: #e6fff2; border-left: 4px solid #06d6a0; }")
    parts.append("  .table th { font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; color: #6c757d; }")
    parts.append("  .badge { font-weight: 600; }")
    parts.append("  code { font-family: 'Fira Code', monospace; }")
    parts.append("  @media (prefers-color-scheme: dark) { body:not(.light-mode) { @apply dark-mode; } }")
    parts.append("</style>")
    parts.append("</head>")

    # === Body ===
    parts.append("<body class='light-mode'>")
    parts.append("  <div class='container py-5'>")

    # Header
    parts.append(f"    <div class='text-center mb-5'>")
    parts.append(f"      <h1 class='hero-title mb-3'>PyScan Report</h1>")
    parts.append(f"      <p class='lead text-muted'>Static analysis completed on {scan_time}</p>")
    parts.append(f"    </div>")

    # Summary Cards
    parts.append("    <div class='row g-3 mb-4'>")
    parts.append(f"      <div class='col-sm-6 col-lg-3'><div class='card text-center p-3'><h3 class='text-danger mb-0'>{high}</h3><small>High</small></div></div>")
    parts.append(f"      <div class='col-sm-6 col-lg-3'><div class='card text-center p-3'><h3 class='text-warning mb-0'>{medium}</h3><small>Medium</small></div></div>")
    parts.append(f"      <div class='col-sm-6 col-lg-3'><div class='card text-center p-3'><h3 class='text-success mb-0'>{low}</h3><small>Low</small></div></div>")
    parts.append(f"      <div class='col-sm-6 col-lg-3'><div class='card text-center p-3'><h3 class='text-primary mb-0'>{total}</h3><small>Total</small></div></div>")
    parts.append("    </div>")

    # Issues Table
    parts.append("    <div class='card'>")
    parts.append("      <div class='card-body p-4'>")
    parts.append("        <h5 class='card-title mb-4'>")
    parts.append("          <i class='bi bi-bug-fill text-danger'></i> Detected Issues")
    parts.append("        </h5>")
    parts.append("        <div class='table-responsive'>")
    parts.append("          <table id='issuesTable' class='table table-hover table-striped align-middle'>")
    parts.append("            <thead class='table-light'>")
    parts.append("              <tr>")
    parts.append("                <th>File</th>")
    parts.append("                <th>Line</th>")
    parts.append("                <th>Type</th>")
    parts.append("                <th>Severity</th>")
    parts.append("                <th>Message</th>")
    parts.append("              </tr>")
    parts.append("            </thead>")
    parts.append("            <tbody>")

    # Issues Rows
    for it in issues:
        file = html.escape(it.get("file", "inline"))
        line = it.get("lineno", "-")
        typ = html.escape(it.get("type", "unknown"))
        sev = html.escape(it.get("severity", "low"))
        msg = html.escape(it.get("msg", ""))
        cls = severity_class(sev)
        badge = severity_badge(sev)

        parts.append(f"              <tr class='severity-{cls}'>")
        parts.append(f"                <td><code>{file}</code></td>")
        parts.append(f"                <td><strong>{line}</strong></td>")
        parts.append(f"                <td><small class='text-muted'>{typ}</small></td>")
        parts.append(f"                <td>{badge}</td>")
        parts.append(f"                <td>{msg}</td>")
        parts.append(f"              </tr>")

    parts.append("            </tbody>")
    parts.append("          </table>")
    parts.append("        </div>")
    parts.append("      </div>")
    parts.append("    </div>")

    # Footer
    parts.append("    <div class='text-center mt-5 text-muted small'>")
    parts.append("      Generated by <strong>PyScan</strong> • Open Source Python Static Analyzer")
    parts.append("    </div>")

    parts.append("  </div>")

    # === Scripts ===
    parts.append("  <script src='https://code.jquery.com/jquery-3.7.1.min.js'></script>")
    parts.append("  <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>")
    parts.append("  <script src='https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js'></script>")
    parts.append("  <script src='https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js'></script>")

    # DataTables Init + Dark Mode Auto
    parts.append("  <script>")
    parts.append("    $(document).ready(function() {")
    parts.append("      $('#issuesTable').DataTable({")
    parts.append("        pageLength: 25,")
    parts.append("        lengthMenu: [10, 25, 50, 100],")
    parts.append("        order: [[1, 'asc']],")
    parts.append("        columnDefs: [{ targets: 1, type: 'num' }],")
    parts.append("        language: { search: 'Filter issues:' }")
    parts.append("      });")

    # Auto Dark Mode
    parts.append("      if (window.matchMedia('(prefers-color-scheme: dark)').matches) {")
    parts.append("        document.body.classList.remove('light-mode');")
    parts.append("        document.body.classList.add('dark-mode');")
    parts.append("      }")
    parts.append("    });")
    parts.append("  </script>")

    parts.append("</body></html>")
    return "\n".join(parts)