#

import argparse
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import subprocess

# Import analyzer
try:
    from analyzer.core import Analyzer
    from analyzer.metrics import analyze_code_metrics
    from analyzer.dataflow import analyze_data_flow
except ImportError:
    print("⚠️  Error: Cannot import analyzer modules. Make sure you're in the project directory.")
    sys.exit(1)


class PyScanCLI:
    """Main CLI class"""
    
    def __init__(self):
        self.analyzer = Analyzer(deep_scan=True)
        self.version = "3.0.0"
    
    def scan(self, path: str, args: argparse.Namespace) -> Dict:
        """Scan một path (file hoặc directory)"""
        print(f"\n🔍 PyScan Pro v{self.version} - Starting scan...")
        print(f"📂 Target: {path}")
        print(f"⚙️  Deep scan: {args.deep}")
        print(f"🎯 Fail on: {args.fail_on or 'none'}\n")
        
        start_time = datetime.now()
        
        # Resolve path
        target_path = Path(path).resolve()
        
        if not target_path.exists():
            print(f"❌ Error: Path '{path}' does not exist")
            sys.exit(1)
        
        all_issues = []
        files_scanned = 0
        
        # Scan files
        if target_path.is_file():
            if target_path.suffix == '.py':
                issues = self._scan_file(str(target_path), args)
                all_issues.extend(issues)
                files_scanned = 1
        
        elif target_path.is_dir():
            py_files = self._find_python_files(target_path, args)
            
            for i, py_file in enumerate(py_files, 1):
                print(f"[{i}/{len(py_files)}] Scanning: {py_file.relative_to(target_path)}")
                
                issues = self._scan_file(str(py_file), args)
                all_issues.extend(issues)
                files_scanned += 1
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        # Prepare results
        results = {
            "scan_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "version": self.version,
            "target": str(target_path),
            "timestamp": datetime.now().isoformat(),
            "files_scanned": files_scanned,
            "total_issues": len(all_issues),
            "issues": all_issues,
            "severity_breakdown": self._count_by_severity(all_issues),
            "category_breakdown": self._count_by_category(all_issues),
            "elapsed_time": round(elapsed, 2)
        }
        
        # Print summary
        self._print_summary(results)
        
        # Save output
        if args.output:
            self._save_results(results, args.output, args.format)
        
        # Check fail conditions
        if args.fail_on:
            if self._should_fail(results, args.fail_on):
                print(f"\n❌ FAILED: Found {args.fail_on} or higher severity issues")
                sys.exit(1)
        
        return results
    
    def _scan_file(self, file_path: str, args: argparse.Namespace) -> List[Dict]:
        """Scan một file Python"""
        issues = []
        
        try:
            # Basic scan
            basic_issues = self.analyzer.analyze_file(file_path)
            issues.extend(basic_issues)
            
            # Advanced metrics (if enabled)
            if args.metrics:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                metrics_result = analyze_code_metrics(file_path, code)
                
                # Convert metrics to issues format
                if 'metrics' in metrics_result:
                    metrics = metrics_result['metrics']
                    
                    # Add code smells as issues
                    for smell in metrics.get('code_smells', []):
                        issues.append({
                            "type": "code_quality",
                            "category": smell['type'],
                            "severity": smell['severity'],
                            "message": smell['message'],
                            "line": smell['line'],
                            "file": file_path,
                            "recommendation": smell['recommendation']
                        })
            
            # Data flow analysis (if enabled)
            if args.dataflow:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                flow_result = analyze_data_flow(file_path, code)
                
                # Add vulnerabilities as issues
                for vuln in flow_result.get('vulnerabilities', []):
                    issues.append(vuln)
        
        except Exception as e:
            print(f"⚠️  Warning: Error scanning {file_path}: {e}")
        
        return issues
    
    def _find_python_files(self, directory: Path, args: argparse.Namespace) -> List[Path]:
        """Tìm tất cả Python files trong directory"""
        exclude_dirs = {
            '__pycache__', '.git', '.venv', 'venv', 'env',
            'node_modules', '.idea', '.vscode', 'build', 'dist'
        }
        
        if args.exclude:
            exclude_dirs.update(args.exclude.split(','))
        
        py_files = []
        
        for py_file in directory.rglob('*.py'):
            # Check if in excluded directory
            if any(excluded in py_file.parts for excluded in exclude_dirs):
                continue
            
            py_files.append(py_file)
        
        return sorted(py_files)
    
    def _count_by_severity(self, issues: List[Dict]) -> Dict[str, int]:
        """Đếm issues theo severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for issue in issues:
            severity = issue.get("severity", "low").lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _count_by_category(self, issues: List[Dict]) -> Dict[str, int]:
        """Đếm issues theo category"""
        from collections import Counter
        categories = [issue.get("category", "unknown") for issue in issues]
        return dict(Counter(categories))
    
    def _print_summary(self, results: Dict):
        """In summary ra console"""
        print("\n" + "="*70)
        print("📊 SCAN RESULTS SUMMARY")
        print("="*70)
        
        print(f"Files Scanned: {results['files_scanned']}")
        print(f"Total Issues: {results['total_issues']}")
        print(f"Time Elapsed: {results['elapsed_time']}s")
        
        print("\n🎯 Severity Breakdown:")
        severity_breakdown = results['severity_breakdown']
        
        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️"
        }
        
        for severity, count in severity_breakdown.items():
            if count > 0:
                icon = severity_icons.get(severity, "•")
                print(f"  {icon} {severity.upper()}: {count}")
        
        if results['total_issues'] == 0:
            print("\n✅ No issues found! Your code is clean.")
        else:
            print(f"\n⚠️  Found {results['total_issues']} issues. Review the report for details.")
        
        print("="*70 + "\n")
    
    def _save_results(self, results: Dict, output: str, format: str):
        """Lưu results ra file"""
        try:
            if format == 'json':
                with open(output, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
            
            elif format == 'sarif':
                sarif = self._convert_to_sarif(results)
                with open(output, 'w', encoding='utf-8') as f:
                    json.dump(sarif, f, indent=2)
            
            elif format == 'junit':
                junit_xml = self._convert_to_junit(results)
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(junit_xml)
            
            print(f"✅ Results saved to: {output}")
        
        except Exception as e:
            print(f"⚠️  Warning: Could not save results: {e}")
    
    def _convert_to_sarif(self, results: Dict) -> Dict:
        """Convert results sang SARIF format (GitHub Code Scanning)"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "PyScan Pro",
                        "version": self.version,
                        "informationUri": "https://github.com/yourusername/pyscan-pro"
                    }
                },
                "results": []
            }]
        }
        
        for issue in results['issues']:
            sarif["runs"][0]["results"].append({
                "ruleId": issue.get("category", "unknown"),
                "level": self._severity_to_sarif_level(issue.get("severity", "warning")),
                "message": {
                    "text": issue.get("message", "")
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": issue.get("file", ""),
                        },
                        "region": {
                            "startLine": issue.get("line", 1)
                        }
                    }
                }]
            })
        
        return sarif
    
    def _convert_to_junit(self, results: Dict) -> str:
        """Convert results sang JUnit XML format"""
        failures = [i for i in results['issues'] if i.get('severity') in ['critical', 'high']]
        
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="PyScan Pro Security Scan" tests="{results['files_scanned']}" failures="{len(failures)}" time="{results['elapsed_time']}">
"""
        
        for issue in failures:
            xml += f"""  <testcase name="{issue.get('file', 'unknown')}" classname="security">
    <failure message="{issue.get('message', '')}" type="{issue.get('category', 'security_issue')}">
Line {issue.get('line', 0)}: {issue.get('message', '')}
Severity: {issue.get('severity', 'unknown')}
Recommendation: {issue.get('recommendation', 'N/A')}
    </failure>
  </testcase>
"""
        
        xml += "</testsuite>"
        return xml
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity sang SARIF level"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return mapping.get(severity.lower(), "warning")
    
    def _should_fail(self, results: Dict, fail_on: str) -> bool:
        """Kiểm tra có nên fail build không"""
        severity_order = ["info", "low", "medium", "high", "critical"]
        fail_level = severity_order.index(fail_on.lower())
        
        severity_breakdown = results['severity_breakdown']
        
        for severity in severity_order[fail_level:]:
            if severity_breakdown.get(severity, 0) > 0:
                return True
        
        return False
    
    def baseline(self, path: str, args: argparse.Namespace):
        """Tạo baseline scan để so sánh sau này"""
        print(f"\n📸 Creating baseline scan for: {path}")
        
        results = self.scan(path, args)
        
        baseline_file = args.save or "pyscan_baseline.json"
        
        with open(baseline_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Baseline saved to: {baseline_file}")
        print("Use this for future comparisons with: pyscan compare <baseline> <current>")
    
    def compare(self, baseline_file: str, current_file: str):
        """So sánh 2 scan results"""
        print(f"\n🔄 Comparing scans...")
        print(f"Baseline: {baseline_file}")
        print(f"Current:  {current_file}")
        
        try:
            with open(baseline_file, 'r') as f:
                baseline = json.load(f)
            
            with open(current_file, 'r') as f:
                current = json.load(f)
        
        except FileNotFoundError as e:
            print(f"❌ Error: File not found: {e.filename}")
            sys.exit(1)
        
        # Compare
        baseline_issues = set(self._issue_signature(i) for i in baseline['issues'])
        current_issues = set(self._issue_signature(i) for i in current['issues'])
        
        new_issues = current_issues - baseline_issues
        fixed_issues = baseline_issues - current_issues
        
        print("\n" + "="*70)
        print("📊 COMPARISON RESULTS")
        print("="*70)
        
        print(f"Baseline Issues: {baseline['total_issues']}")
        print(f"Current Issues:  {current['total_issues']}")
        print(f"\n✅ Fixed: {len(fixed_issues)}")
        print(f"🆕 New:   {len(new_issues)}")
        
        if len(new_issues) > 0:
            print(f"\n⚠️  WARNING: {len(new_issues)} new issues introduced!")
            sys.exit(1)
        
        print("\n✅ No new issues introduced!")
    
    def _issue_signature(self, issue: Dict) -> str:
        """Tạo unique signature cho issue"""
        return f"{issue.get('file')}:{issue.get('line')}:{issue.get('category')}:{issue.get('message')}"


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="PyScan Pro - Python Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pyscan scan . --format json --output report.json
  pyscan scan src/ --fail-on high --metrics --dataflow
  pyscan baseline . --save baseline.json
  pyscan compare baseline.json current.json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan Python files')
    scan_parser.add_argument('path', help='File or directory to scan')
    scan_parser.add_argument('--deep', action='store_true', default=True, help='Deep scan (default: True)')
    scan_parser.add_argument('--metrics', action='store_true', help='Include code metrics')
    scan_parser.add_argument('--dataflow', action='store_true', help='Include data flow analysis')
    scan_parser.add_argument('--format', choices=['json', 'sarif', 'junit'], default='json', help='Output format')
    scan_parser.add_argument('--output', '-o', help='Output file')
    scan_parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low'], help='Fail build on severity')
    scan_parser.add_argument('--exclude', help='Comma-separated list of directories to exclude')
    
    # Baseline command
    baseline_parser = subparsers.add_parser('baseline', help='Create baseline scan')
    baseline_parser.add_argument('path', help='File or directory to scan')
    baseline_parser.add_argument('--save', help='Baseline file name (default: pyscan_baseline.json)')
    baseline_parser.add_argument('--format', choices=['json'], default='json')
    baseline_parser.add_argument('--exclude', help='Comma-separated list of directories to exclude')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two scan results')
    compare_parser.add_argument('baseline', help='Baseline scan file')
    compare_parser.add_argument('current', help='Current scan file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = PyScanCLI()
    
    try:
        if args.command == 'scan':
            cli.scan(args.path, args)
        
        elif args.command == 'baseline':
            cli.baseline(args.path, args)
        
        elif args.command == 'compare':
            cli.compare(args.baseline, args.current)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()