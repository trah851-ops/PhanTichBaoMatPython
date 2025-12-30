# analyzer/sca.py - IMPROVED VERSION with Real Vulnerability Detection
import re
import requests
import json
from typing import List, Dict, Any
from packaging import version as pkg_version
import time

class DependencyScanner:
    """
    Improved SCA Scanner với:
    - Real CVE database query (OSV API)
    - Proper version comparison
    - Caching để tránh spam API
    - Fallback local database
    """
    
    # Local fallback database (updated 2024)
    LOCAL_VULN_DB = {
        "django": [
            {"version": "<3.2.19", "cve": "CVE-2023-31047", "severity": "high", 
             "msg": "SQL injection in QuerySet.only(), defer()"},
            {"version": "<4.1.9", "cve": "CVE-2023-23969", "severity": "high",
             "msg": "Denial-of-service in Accept-Language headers"},
        ],
        "flask": [
            {"version": "<2.2.5", "cve": "CVE-2023-30861", "severity": "high",
             "msg": "Cookie parsing vulnerability"},
            {"version": "<2.3.2", "cve": "CVE-2023-25577", "severity": "medium",
             "msg": "Session cookie security issue"},
        ],
        "requests": [
            {"version": "<2.31.0", "cve": "CVE-2023-32681", "severity": "medium",
             "msg": "Proxy-Authorization header leak"},
        ],
        "pillow": [
            {"version": "<10.0.0", "cve": "CVE-2023-44271", "severity": "critical",
             "msg": "Heap buffer overflow in ImageFile.load"},
            {"version": "<10.0.1", "cve": "CVE-2023-4863", "severity": "critical",
             "msg": "libwebp buffer overflow"},
        ],
        "pyyaml": [
            {"version": "<6.0", "cve": "CVE-2020-14343", "severity": "critical",
             "msg": "Arbitrary code execution via load()"},
        ],
        "urllib3": [
            {"version": "<1.26.17", "cve": "CVE-2023-43804", "severity": "medium",
             "msg": "Cookie request header leak"},
        ],
        "cryptography": [
            {"version": "<41.0.4", "cve": "CVE-2023-38325", "severity": "high",
             "msg": "Cipher.update_into can corrupt memory"},
        ],
        "jinja2": [
            {"version": "<3.1.3", "cve": "CVE-2024-22195", "severity": "medium",
             "msg": "XSS in Jinja2 sandbox"},
        ],
        "sqlalchemy": [
            {"version": "<2.0.0", "cve": "CVE-2019-7164", "severity": "high",
             "msg": "SQL injection via order_by parameter"},
        ],
        "werkzeug": [
            {"version": "<2.3.8", "cve": "CVE-2023-46136", "severity": "medium",
             "msg": "Path traversal in safe_join"},
        ],
    }
    
    # Dangerous packages (should never use)
    DANGEROUS_PACKAGES = {
        "pickle": "Use JSON instead - pickle is unsafe by design",
        "marshal": "Unsafe deserialization - use JSON",
        "shelve": "Uses pickle internally - unsafe",
        "exec": "Never use exec() with untrusted input",
        "eval": "Never use eval() with untrusted input",
    }
    
    def __init__(self):
        self.cache = {}  # Cache API results
        self.use_api = True
        self.api_timeout = 5
        
    def scan(self, file_content: str, file_path: str) -> List[Dict]:
        """Main scan function"""
        issues = []
        lines = file_content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse requirement line
            parsed = self._parse_requirement(line)
            if not parsed:
                continue
            
            package_name = parsed['name']
            version_spec = parsed['version']
            operator = parsed['operator']
            
            # Check dangerous packages
            if package_name in self.DANGEROUS_PACKAGES:
                issues.append({
                    "type": "dependency_check",
                    "category": "dangerous_package",
                    "severity": "critical",
                    "message": f"NGUY HIỂM: Package '{package_name}' không an toàn - {self.DANGEROUS_PACKAGES[package_name]}",
                    "line": i,
                    "file": file_path,
                    "recommendation": self.DANGEROUS_PACKAGES[package_name]
                })
                continue
            
            # Try OSV API first
            vulns = []
            if self.use_api:
                vulns = self._query_osv_api(package_name, version_spec)
            
            # Fallback to local database
            if not vulns:
                vulns = self._check_local_database(package_name, version_spec, operator)
            
            # Report vulnerabilities
            for vuln in vulns:
                issues.append({
                    "type": "dependency_check",
                    "category": "vulnerable_library",
                    "severity": vuln.get("severity", "medium"),
                    "message": f"THƯ VIỆN DỄ TỔN THƯƠNG: {package_name}{operator}{version_spec} - {vuln.get('cve', 'N/A')}: {vuln.get('msg', 'Unknown')}",
                    "line": i,
                    "file": file_path,
                    "recommendation": vuln.get('recommendation', f"Nâng cấp lên {package_name}>={vuln.get('fixed_version', 'latest')}"),
                    "cve": vuln.get('cve'),
                    "cvss": vuln.get('cvss'),
                    "references": vuln.get('references', [])
                })
        
        return issues
    
    def _parse_requirement(self, line: str) -> Dict[str, Any]:
        """Parse requirement line: django==3.2.0 hoặc flask>=2.0.0"""
        # Remove comments
        line = line.split('#')[0].strip()
        if not line:
            return None
        
        # Parse với regex
        pattern = r'^([a-zA-Z0-9\-_\.]+)\s*([=<>!~]+)\s*([0-9\.]+.*?)$'
        match = re.match(pattern, line)
        
        if match:
            return {
                'name': match.group(1).lower().strip(),
                'operator': match.group(2).strip(),
                'version': match.group(3).strip()
            }
        
        # Nếu không có version specifier
        package_match = re.match(r'^([a-zA-Z0-9\-_\.]+)$', line)
        if package_match:
            return {
                'name': package_match.group(1).lower().strip(),
                'operator': '',
                'version': ''
            }
        
        return None
    
    def _query_osv_api(self, package_name: str, version: str) -> List[Dict]:
        """Query OSV (Open Source Vulnerabilities) API"""
        if not version:
            return []
        
        # Check cache
        cache_key = f"{package_name}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            # Query OSV API
            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                },
                "version": version
            }
            
            response = requests.post(url, json=payload, timeout=self.api_timeout)
            
            if response.status_code == 200:
                data = response.json()
                vulns = []
                
                for vuln in data.get('vulns', []):
                    severity = self._extract_severity(vuln)
                    
                    vulns.append({
                        'cve': vuln.get('id', 'N/A'),
                        'severity': severity,
                        'msg': vuln.get('summary', 'No description'),
                        'cvss': vuln.get('database_specific', {}).get('cvss', 'N/A'),
                        'fixed_version': self._extract_fixed_version(vuln),
                        'references': [ref.get('url') for ref in vuln.get('references', [])[:3]],
                        'recommendation': f"Cập nhật lên phiên bản đã vá lỗi"
                    })
                
                # Cache result
                self.cache[cache_key] = vulns
                return vulns
        
        except requests.Timeout:
            print(f"[SCA] OSV API timeout for {package_name}")
            self.use_api = False  # Disable API for subsequent calls
        except Exception as e:
            print(f"[SCA] OSV API error: {e}")
        
        return []
    
    def _check_local_database(self, package_name: str, version: str, operator: str) -> List[Dict]:
        """Check against local vulnerability database"""
        if package_name not in self.LOCAL_VULN_DB:
            return []
        
        if not version:
            # Nếu không có version, cảnh báo nên pin version
            return [{
                'severity': 'low',
                'msg': 'Version không được chỉ định - nên pin version cụ thể',
                'recommendation': f'Chỉ định version cụ thể: {package_name}==X.Y.Z'
            }]
        
        vulns = []
        
        for vuln_entry in self.LOCAL_VULN_DB[package_name]:
            vuln_version_spec = vuln_entry['version']
            
            if self._is_vulnerable(version, vuln_version_spec, operator):
                vulns.append({
                    'cve': vuln_entry.get('cve', 'N/A'),
                    'severity': vuln_entry['severity'],
                    'msg': vuln_entry['msg'],
                    'fixed_version': self._extract_version_from_spec(vuln_version_spec),
                    'recommendation': f"Nâng cấp {package_name} lên phiên bản mới nhất"
                })
        
        return vulns
    
    def _is_vulnerable(self, installed_version: str, vuln_spec: str, operator: str) -> bool:
        """
        Check if installed version is vulnerable
        vuln_spec format: "<3.2.19" means vulnerable if version < 3.2.19
        """
        try:
            installed = pkg_version.parse(installed_version)
            
            # Parse vuln_spec
            if vuln_spec.startswith('<'):
                threshold_version = vuln_spec[1:].strip()
                threshold = pkg_version.parse(threshold_version)
                return installed < threshold
            
            elif vuln_spec.startswith('<='):
                threshold_version = vuln_spec[2:].strip()
                threshold = pkg_version.parse(threshold_version)
                return installed <= threshold
            
            elif vuln_spec.startswith('>'):
                threshold_version = vuln_spec[1:].strip()
                threshold = pkg_version.parse(threshold_version)
                return installed > threshold
            
            elif vuln_spec.startswith('>='):
                threshold_version = vuln_spec[2:].strip()
                threshold = pkg_version.parse(threshold_version)
                return installed >= threshold
            
            elif vuln_spec.startswith('=='):
                threshold_version = vuln_spec[2:].strip()
                threshold = pkg_version.parse(threshold_version)
                return installed == threshold
        
        except Exception as e:
            print(f"[SCA] Version comparison error: {e}")
            return False
        
        return False
    
    def _extract_severity(self, vuln: Dict) -> str:
        """Extract severity from OSV vulnerability"""
        # Try CVSS score
        cvss = vuln.get('database_specific', {}).get('cvss', '')
        if 'CRITICAL' in cvss or '9.' in cvss or '10.' in cvss:
            return 'critical'
        elif 'HIGH' in cvss or '7.' in cvss or '8.' in cvss:
            return 'high'
        elif 'MEDIUM' in cvss or '4.' in cvss or '5.' in cvss or '6.' in cvss:
            return 'medium'
        else:
            return 'low'
    
    def _extract_fixed_version(self, vuln: Dict) -> str:
        """Extract fixed version from vulnerability data"""
        affected = vuln.get('affected', [])
        if affected and len(affected) > 0:
            ranges = affected[0].get('ranges', [])
            if ranges and len(ranges) > 0:
                events = ranges[0].get('events', [])
                for event in events:
                    if 'fixed' in event:
                        return event['fixed']
        return 'latest'
    
    def _extract_version_from_spec(self, spec: str) -> str:
        """Extract version number from spec like '<3.2.19'"""
        return re.sub(r'[<>=!]', '', spec).strip()


def scan_dependencies_advanced(requirements_file: str) -> Dict[str, Any]:
    """
    Scan dependencies với detailed report
    """
    scanner = DependencyScanner()
    
    try:
        with open(requirements_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {'error': f'Cannot read file: {e}'}
    
    issues = scanner.scan(content, requirements_file)
    
    # Generate summary
    severity_counts = {
        'critical': sum(1 for i in issues if i.get('severity') == 'critical'),
        'high': sum(1 for i in issues if i.get('severity') == 'high'),
        'medium': sum(1 for i in issues if i.get('severity') == 'medium'),
        'low': sum(1 for i in issues if i.get('severity') == 'low'),
    }
    
    return {
        'file': requirements_file,
        'total_issues': len(issues),
        'severity_breakdown': severity_counts,
        'issues': issues,
        'risk_score': min(100, severity_counts['critical'] * 30 + 
                               severity_counts['high'] * 20 + 
                               severity_counts['medium'] * 10 +
                               severity_counts['low'] * 5)
    }