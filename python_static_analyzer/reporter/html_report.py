# reporter/html_report.py
import html
def build_html_report(result):
    issues = result.get('issues', [])
    lines = []
    lines.append('<html><head><meta charset="utf-8"><title>Static Analysis Report</title></head><body>')
    lines.append('<h1>Static Analysis Report</h1>')
    lines.append(f'<p>Total issues: {len(issues)}</p>')
    lines.append('<table border="1" cellpadding="6" style="border-collapse:collapse">')
    lines.append('<tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Message</th></tr>')
    for it in issues:
        f = html.escape(it.get('file','<unknown>'))
        ln = it.get('lineno', 0)
        t = html.escape(it.get('type',''))
        sev = html.escape(it.get('severity',''))
        msg = html.escape(it.get('msg',''))
        lines.append(f'<tr><td>{f}</td><td>{ln}</td><td>{t}</td><td>{sev}</td><td>{msg}</td></tr>')
    lines.append('</table></body></html>')
    return '\\n'.join(lines)
