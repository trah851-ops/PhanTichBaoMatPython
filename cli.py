# cli.py - Python Security Scanner CLI (PyScan Pro)
# Chạy: python cli.py . --out-html report.html --verbose

#!/usr/bin/env python3
import argparse
import sys
import os
import json
from pathlib import Path
import time
from typing import List, Dict

# Import từ analyzer (dự án của bạn)
from analyzer.core import Analyzer
from analyzer.fuzzing import run_fuzz_on_analyzer, is_fuzzing_available

class ProjectScanner:
    def __init__(self, project_path: str, exclude_dirs: List[str] = None):
        self.project_path = Path(project_path).resolve()
        self.exclude_dirs = exclude_dirs or [
            'venv', '.venv', 'env', '__pycache__', '.git',
            'node_modules', 'build', 'dist', 'htmlcov', 'uploads', 'web_reports'
        ]
        self.results: Dict[str, List[dict]] = {}
        self.stats = {
            'files_scanned': 0,
            'files_with_issues': 0,
            'total_issues': 0,
            'scan_time': 0.0
        }

    def find_python_files(self):
        for root, dirs, files in os.walk(self.project_path):
            # Loại bỏ thư mục không cần quét
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for file in files:
                if file.endswith('.py'):
                    yield Path(root) / file

    def scan_file(self, filepath: Path):
        try:
            analyzer = Analyzer()
            issues = analyzer.analyze_file(str(filepath))
            rel_path = filepath.relative_to(self.project_path)
            return str(rel_path), issues
        except Exception as e:
            rel_path = filepath.relative_to(self.project_path)
            return str(rel_path), [{"type": "error", "message": f"Không đọc được: {e}", "file": str(rel_path)}]

    def scan_project(self, verbose: bool = False):
        start_time = time.time()
        files = list(self.find_python_files())
        
        print(f"\nPyScan Pro - Đang quét {len(files)} file Python...")
        print("=" * 70)

        for filepath in files:
            rel_path, issues = self.scan_file(filepath)
            self.stats['files_scanned'] += 1

            if issues:
                self.results[rel_path] = issues
                self.stats['files_with_issues'] += 1
                self.stats['total_issues'] += len(issues)

                if verbose:
                    high = sum(1 for i in issues if i.get("severity", "").lower() in ["high", "critical"])
                    print(f"[{high and 'CẢNH BÁO' or 'OK'}] {rel_path} → {len(issues)} vấn đề")
            elif verbose:
                print(f"[SẠCH] {rel_path}")

        self.stats['scan_time'] = time.time() - start_time

    def print_summary(self):
        print("\n" + "="*70)
        print("KẾT QUẢ QUÉT BẢO MẬT - PYSCAN PRO")
        print("="*70)
        print(f"Thư mục: {self.project_path}")
        print(f"File đã quét: {self.stats['files_scanned']}")
        print(f"File có vấn đề: {self.stats['files_with_issues']}")
        print(f"Tổng số lỗi: {self.stats['total_issues']}")
        print(f"Thời gian: {self.stats['scan_time']:.2f}s")
        
        if self.stats['total_issues'] > 0:
            critical = sum(1 for issues in self.results.values() for i in issues if i.get("severity", "").lower() == "critical")
            high = sum(1 for issues in self.results.values() for i in issues if i.get("severity", "").lower() == "high")
            medium = sum(1 for issues in self.results.values() for i in issues if i.get("severity", "").lower() == "medium")
            
            print(f"\nMỨC ĐỘ NGUY HIỂM:")
            if critical: print(f"   CRITICAL: {critical}")
            if high:     print(f"   HIGH: {high}")
            if medium:   print(f"   MEDIUM: {medium}")
            
            if critical + high > 0:
                print(f"\nCẢNH BÁO: Phát hiện {critical + high} lỗ hổng NGHIÊM TRỌNG!")
                print("   Cần sửa ngay trước khi deploy!")
            else:
                print("\nTỐT: Không có lỗ hổng nghiêm trọng!")
        else:
            print("\nXUẤT SẮC: Không phát hiện lỗi nào!")
        
        print("="*70)

    def export_json(self, filepath: str):
        output = {
            "summary": {
                "total_files": self.stats['files_scanned'],
                "files_with_issues": self.stats['files_with_issues'],
                "total_issues": self.stats['total_issues'],
                "scan_time": round(self.stats['scan_time'], 2)
            },
            "results": self.results
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"JSON report: {filepath}")

    def export_html(self, filepath: str):
        # HTML đơn giản nhưng đẹp
        html = f"""
        <!DOCTYPE html>
        <html><head><title>PyScan Pro Report</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: system-ui, sans-serif; margin: 40px; background: #f8f9fa; }}
            h1 {{ color: #d63384; text-align: center; }}
            .summary {{ background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }}
            .issue {{ background: white; padding: 16px; margin: 12px 0; border-left: 6px solid #d63384; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .critical {{ border-left-color: #dc3545; background: #ffe6e6; }}
            .high {{ border-left-color: #fd7e14; }}
            .medium {{ border-left-color: #ffc107; }}
        </style>
        </head><body>
        <h1>PyScan Pro - Báo Cáo Bảo Mật</h1>
        <div class="summary">
            <h2>Tổng Quan</h2>
            <p><strong>File quét:</strong> {self.stats['files_scanned']} | <strong>Lỗi:</strong> {self.stats['total_issues']} | <strong>Thời gian:</strong> {self.stats['scan_time']:.2f}s</p>
        </div>
        <h2>Chi Tiết Lỗi</h2>
        """
        for file, issues in self.results.items():
            html += f"<h3>{file}</h3>"
            for i in issues:
                sev = i.get("severity", "low").lower()
                cls = "critical" if sev == "critical" else "high" if sev == "high" else "medium" if sev == "medium" else ""
                msg = i.get("message") or i.get("rule", "Unknown")
                line = i.get("line", "?")
                html += f'<div class="issue {cls}"><b>[{sev.upper()}] Dòng {line}</b>: {msg}</div>'
        html += "</body></html>"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"HTML report: {filepath}")

def main():
    parser = argparse.ArgumentParser(
        description="PyScan Pro - Công cụ quét bảo mật Python (SAST + Fuzzing)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ sử dụng:
  python cli.py .                    # Quét toàn bộ project
  python cli.py app.py               # Quét 1 file
  python cli.py . --out-html report.html --verbose
  python cli.py --fuzz               # Chạy fuzzing (cần atheris)
        """
    )
    
    parser.add_argument('path', nargs='?', default=".", help='Thư mục hoặc file cần quét')
    parser.add_argument('--out-json', help='Xuất báo cáo JSON')
    parser.add_argument('--out-html', help='Xuất báo cáo HTML')
    parser.add_argument('--verbose', '-v', action='store_true', help='Hiển thị chi tiết')
    parser.add_argument('--fuzz', action='store_true', help='Chạy chế độ fuzzing (Atheris)')
    
    args = parser.parse_args()
    
    # Chế độ fuzzing
    if args.fuzz:
        if not is_fuzzing_available():
            print("Cần cài atheris: pip install atheris")
            return 1
        print("Bắt đầu fuzzing analyzer...")
        run_fuzz_on_analyzer(runs=50000)
        return 0
    
    # Chế độ quét bình thường
    path = Path(args.path)
    if not path.exists():
        print(f"Không tìm thấy: {args.path}")
        return 1
    
    if path.is_file():
        analyzer = Analyzer()
        issues = analyzer.analyze_file(str(path))
        print(f"\nKết quả quét: {path.name}")
        print(f"Tìm thấy {len(issues)} vấn đề:\n")
        for i in issues:
            sev = i.get("severity", "low").upper()
            print(f"[{sev}] Dòng {i.get('line','-')}: {i.get('message','')}")
        return 0
    
    # Quét project
    scanner = ProjectScanner(str(path))
    scanner.scan_project(verbose=args.verbose)
    scanner.print_summary()
    
    if args.out_json:
        scanner.export_json(args.out_json)
    if args.out_html:
        scanner.export_html(args.out_html)
    
    return 0 if scanner.stats['total_issues'] == 0 else 1

if __name__ == "__main__":
    sys.exit(main())