# analyzer/advanced_security.py - ADVANCED SECURITY RULES
"""
Phát hiện các lỗ hổng bảo mật nâng cao:
- Race Conditions
- Memory Leaks
- Authentication Flaws
- CSRF & Session Issues
- File Upload Vulnerabilities
- XXE, SSTI, Logic Bugs
"""

import ast
import re
from typing import List, Dict, Any
from collections import defaultdict

class AdvancedSecurityAnalyzer(ast.NodeVisitor):
    """Phân tích các lỗ hổng bảo mật nâng cao"""
    
    def __init__(self, tree: ast.AST, code: str, file_path: str):
        self.tree = tree
        self.code = code
        self.file_path = file_path
        self.lines = code.split('\n')
        self.issues = []
        
        # Tracking
        self.file_operations = []
        self.shared_resources = []
        self.auth_checks = []
        self.session_vars = []
        self.upload_handlers = []
        
        self.visit(self.tree)
    
    def analyze(self) -> List[Dict]:
        """Trả về tất cả security issues"""
        # Phân tích thêm các pattern phức tạp
        self._detect_race_conditions()
        self._detect_memory_leaks()
        self._detect_auth_issues()
        self._detect_file_upload_issues()
        
        return self.issues
    
    # ============ 1. RACE CONDITIONS ============
    
    def visit_With(self, node):
        """Phát hiện file operations không có lock"""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name = self._get_func_name(item.context_expr.func)
                
                # File operations
                if func_name in ['open', 'file']:
                    # Check xem có dùng lock không
                    has_lock = self._check_for_lock(node.lineno)
                    
                    if not has_lock:
                        self.file_operations.append({
                            'line': node.lineno,
                            'type': 'file_operation',
                            'func': func_name
                        })
                        
                        self.issues.append({
                            "type": "race_condition",
                            "category": "concurrency_issue",
                            "severity": "high",
                            "message": "File operation không có lock - race condition risk",
                            "line": node.lineno,
                            "file": self.file_path,
                            "recommendation": "Dùng threading.Lock() hoặc filelock để tránh race condition"
                        })
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """Phát hiện shared resource không đồng bộ"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check global/class variables
                if target.id.isupper() or target.id.startswith('_shared'):
                    self.shared_resources.append({
                        'name': target.id,
                        'line': node.lineno
                    })
                    
                    # Check xem có dùng lock không
                    has_lock = self._check_for_lock(node.lineno)
                    
                    if not has_lock:
                        self.issues.append({
                            "type": "race_condition",
                            "category": "shared_resource",
                            "severity": "high",
                            "message": f"Shared variable '{target.id}' được modify không có lock",
                            "line": node.lineno,
                            "file": self.file_path,
                            "recommendation": "Sử dụng threading.Lock() để protect shared resources"
                        })
        
        self.generic_visit(node)
    
    def _check_for_lock(self, line_num: int) -> bool:
        """Kiểm tra có lock gần đó không"""
        start = max(0, line_num - 5)
        end = min(len(self.lines), line_num + 2)
        
        lock_keywords = ['lock', 'Lock()', 'acquire', 'threading.Lock', 'mutex']
        
        for i in range(start, end):
            if any(keyword in self.lines[i] for keyword in lock_keywords):
                return True
        
        return False
    
    def _detect_race_conditions(self):
        """Phân tích tổng hợp race conditions"""
        # Check multiple threads accessing same resource
        if len(self.shared_resources) > 0 and len(self.file_operations) > 0:
            self.issues.append({
                "type": "race_condition",
                "category": "concurrency_risk",
                "severity": "high",
                "message": f"Phát hiện {len(self.shared_resources)} shared resources và {len(self.file_operations)} file ops - high race condition risk",
                "line": 1,
                "file": self.file_path,
                "recommendation": "Review toàn bộ code để đảm bảo thread-safety"
            })
    
    # ============ 2. MEMORY LEAKS ============
    
    def _detect_memory_leaks(self):
        """Phát hiện memory leaks"""
        # Check for circular references
        for node in ast.walk(self.tree):
            # Unclosed files
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                
                if func_name == 'open':
                    # Check xem có dùng with statement không
                    parent = self._get_parent_node(node)
                    if not isinstance(parent, ast.With):
                        self.issues.append({
                            "type": "memory_leak",
                            "category": "resource_leak",
                            "severity": "medium",
                            "message": "File được open() nhưng không dùng 'with' statement - có thể leak",
                            "line": node.lineno,
                            "file": self.file_path,
                            "recommendation": "Dùng 'with open() as f:' để tự động close file"
                        })
            
            # Large data structures
            if isinstance(node, ast.List) or isinstance(node, ast.Dict):
                # Estimate size
                if isinstance(node, ast.List) and len(node.elts) > 1000:
                    self.issues.append({
                        "type": "memory_leak",
                        "category": "large_data_structure",
                        "severity": "low",
                        "message": f"List rất lớn ({len(node.elts)} elements) - có thể gây memory issue",
                        "line": node.lineno,
                        "file": self.file_path,
                        "recommendation": "Xem xét dùng generator hoặc iterator để tiết kiệm memory"
                    })
    
    def _get_parent_node(self, node):
        """Lấy parent node (simplified)"""
        # This is a simplified version
        return None
    
    # ============ 3. AUTHENTICATION & AUTHORIZATION ============
    
    def visit_FunctionDef(self, node):
        """Phát hiện missing authentication"""
        # Check Flask/Django routes
        decorators = [d.id if isinstance(d, ast.Name) else self._get_func_name(d) 
                     for d in node.decorator_list]
        
        is_route = any(dec in ['route', 'app.route', 'api.route'] for dec in decorators)
        
        if is_route:
            # Check xem có authentication decorator không
            has_auth = any('login_required' in str(dec) or 'auth' in str(dec) 
                          for dec in decorators)
            
            if not has_auth and not node.name.startswith('_'):
                # Check sensitive operations in function
                has_sensitive_op = self._has_sensitive_operation(node)
                
                if has_sensitive_op:
                    self.issues.append({
                        "type": "authentication",
                        "category": "missing_auth",
                        "severity": "critical",
                        "message": f"Route '{node.name}' thực hiện sensitive operations nhưng không có authentication",
                        "line": node.lineno,
                        "file": self.file_path,
                        "recommendation": "Thêm @login_required hoặc authentication decorator"
                    })
        
        self.generic_visit(node)
    
    def _has_sensitive_operation(self, node) -> bool:
        """Check xem function có sensitive operations không"""
        sensitive_keywords = ['delete', 'drop', 'update', 'insert', 'admin', 'password', 'secret']
        
        # Check trong tên function
        if any(keyword in node.name.lower() for keyword in sensitive_keywords):
            return True
        
        # Check trong body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child.func)
                if any(keyword in func_name.lower() for keyword in sensitive_keywords):
                    return True
        
        return False
    
    def _detect_auth_issues(self):
        """Phát hiện các vấn đề authentication khác"""
        # Check hardcoded credentials
        for i, line in enumerate(self.lines, 1):
            # Weak password patterns
            weak_patterns = [
                (r'password\s*=\s*["\']123', "Weak password '123...'"),
                (r'password\s*=\s*["\']admin', "Weak password 'admin'"),
                (r'password\s*=\s*["\']pass', "Weak password 'pass...'"),
                (r'SECRET_KEY\s*=\s*["\'].{1,8}["\']', "SECRET_KEY quá ngắn"),
            ]
            
            for pattern, message in weak_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append({
                        "type": "authentication",
                        "category": "weak_credentials",
                        "severity": "critical",
                        "message": message,
                        "line": i,
                        "file": self.file_path,
                        "recommendation": "Dùng strong password và lưu trong environment variables"
                    })
    
    # ============ 4. CSRF & SESSION MANAGEMENT ============
    
    def visit_Call(self, node):
        """Phát hiện CSRF và session issues"""
        func_name = self._get_func_name(node.func)
        
        # Flask/Django form handling without CSRF
        if any(keyword in func_name for keyword in ['form', 'request.form', 'POST']):
            # Check xem có CSRF protection không
            has_csrf = self._check_csrf_protection(node.lineno)
            
            if not has_csrf:
                self.issues.append({
                    "type": "csrf",
                    "category": "missing_csrf",
                    "severity": "high",
                    "message": "Form handling không có CSRF protection",
                    "line": node.lineno,
                    "file": self.file_path,
                    "recommendation": "Thêm CSRF token vào form và validate"
                })
        
        # Session fixation
        if 'session' in func_name:
            # Check regenerate session ID after login
            if any(keyword in func_name for keyword in ['login', 'authenticate']):
                has_regenerate = self._check_session_regenerate(node.lineno)
                
                if not has_regenerate:
                    self.issues.append({
                        "type": "session_management",
                        "category": "session_fixation",
                        "severity": "high",
                        "message": "Login không regenerate session ID - session fixation risk",
                        "line": node.lineno,
                        "file": self.file_path,
                        "recommendation": "Regenerate session ID sau khi login: session.regenerate()"
                    })
        
        self.generic_visit(node)
    
    def _check_csrf_protection(self, line_num: int) -> bool:
        """Check có CSRF protection không"""
        start = max(0, line_num - 10)
        end = min(len(self.lines), line_num + 5)
        
        csrf_keywords = ['csrf_token', 'CSRFProtect', '@csrf_exempt', 'csrf']
        
        for i in range(start, end):
            if any(keyword in self.lines[i] for keyword in csrf_keywords):
                return True
        
        return False
    
    def _check_session_regenerate(self, line_num: int) -> bool:
        """Check có regenerate session không"""
        start = line_num
        end = min(len(self.lines), line_num + 10)
        
        for i in range(start, end):
            if 'regenerate' in self.lines[i] or 'new_session' in self.lines[i]:
                return True
        
        return False
    
    # ============ 5. FILE UPLOAD VULNERABILITIES ============
    
    def _detect_file_upload_issues(self):
        """Phát hiện file upload vulnerabilities"""
        for i, line in enumerate(self.lines, 1):
            # File upload detection
            if any(keyword in line for keyword in ['request.files', 'upload', 'FileField']):
                # Check validation
                has_validation = self._check_file_validation(i)
                
                if not has_validation:
                    self.issues.append({
                        "type": "file_upload",
                        "category": "unrestricted_upload",
                        "severity": "critical",
                        "message": "File upload không validate extension/type - có thể upload malicious files",
                        "line": i,
                        "file": self.file_path,
                        "recommendation": "Validate file extension, MIME type, size và scan virus"
                    })
                
                # Check path traversal in filename
                if 'filename' in line and 'secure_filename' not in line:
                    self.issues.append({
                        "type": "file_upload",
                        "category": "path_traversal",
                        "severity": "high",
                        "message": "Filename không được sanitize - path traversal risk",
                        "line": i,
                        "file": self.file_path,
                        "recommendation": "Dùng werkzeug.utils.secure_filename() để sanitize filename"
                    })
    
    def _check_file_validation(self, line_num: int) -> bool:
        """Check có validate file không"""
        start = line_num
        end = min(len(self.lines), line_num + 10)
        
        validation_keywords = [
            'allowed_extensions', 'ALLOWED_EXTENSIONS', 'mimetype',
            'content_type', 'file_type', 'extension'
        ]
        
        for i in range(start, end):
            if any(keyword in self.lines[i] for keyword in validation_keywords):
                return True
        
        return False
    
    # ============ HELPER METHODS ============
    
    def _get_func_name(self, node) -> str:
        """Lấy tên function"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""


class XXEAnalyzer:
    """Phát hiện XML External Entity (XXE) vulnerabilities"""
    
    def __init__(self, code: str, file_path: str):
        self.code = code
        self.file_path = file_path
        self.lines = code.split('\n')
    
    def analyze(self) -> List[Dict]:
        issues = []
        
        for i, line in enumerate(self.lines, 1):
            # XML parsing không an toàn
            if any(keyword in line for keyword in ['xml.etree', 'minidom', 'lxml']):
                # Check xem có disable external entities không
                has_protection = self._check_xxe_protection(i)
                
                if not has_protection:
                    issues.append({
                        "type": "xxe",
                        "category": "xml_external_entity",
                        "severity": "high",
                        "message": "XML parsing có thể bị XXE attack - external entities không được disable",
                        "line": i,
                        "file": self.file_path,
                        "recommendation": "Disable external entities: parser.resolveEntities = False"
                    })
        
        return issues
    
    def _check_xxe_protection(self, line_num: int) -> bool:
        """Check có protection chống XXE không"""
        start = max(0, line_num - 5)
        end = min(len(self.lines), line_num + 10)
        
        protection_keywords = [
            'resolveEntities = False',
            'no_network=True',
            'XMLParser(resolve_entities=False)',
            'defusedxml'
        ]
        
        for i in range(start, end):
            if any(keyword in self.lines[i] for keyword in protection_keywords):
                return True
        
        return False


class SSTIAnalyzer:
    """Phát hiện Server-Side Template Injection"""
    
    def __init__(self, code: str, file_path: str):
        self.code = code
        self.file_path = file_path
        self.lines = code.split('\n')
    
    def analyze(self) -> List[Dict]:
        issues = []
        
        for i, line in enumerate(self.lines, 1):
            # Jinja2/Template rendering với user input
            dangerous_patterns = [
                (r'render_template_string\([^)]*\+', "render_template_string với string concatenation"),
                (r'Template\([^)]*request\.', "Template constructor với user input"),
                (r'\.render\([^)]*request\.', "Template render với user input"),
            ]
            
            for pattern, message in dangerous_patterns:
                if re.search(pattern, line):
                    issues.append({
                        "type": "ssti",
                        "category": "template_injection",
                        "severity": "critical",
                        "message": f"SSTI risk: {message}",
                        "line": i,
                        "file": self.file_path,
                        "recommendation": "Không bao giờ render template với user input. Dùng pre-defined templates"
                    })
        
        return issues


class LogicBugAnalyzer(ast.NodeVisitor):
    """Phát hiện logic bugs"""
    
    def __init__(self, tree: ast.AST, file_path: str):
        self.tree = tree
        self.file_path = file_path
        self.issues = []
        self.visit(self.tree)
    
    def analyze(self) -> List[Dict]:
        return self.issues
    
    def visit_If(self, node):
        """Phát hiện logic errors trong conditions"""
        # Check for always True/False conditions
        if isinstance(node.test, ast.Constant):
            if node.test.value in [True, False]:
                self.issues.append({
                    "type": "logic_bug",
                    "category": "constant_condition",
                    "severity": "high",
                    "message": f"If condition luôn luôn {node.test.value} - dead code",
                    "line": node.lineno,
                    "file": self.file_path,
                    "recommendation": "Xóa hoặc sửa condition logic"
                })
        
        # Check for duplicate conditions
        if isinstance(node.test, ast.BoolOp):
            values = node.test.values
            if len(values) != len(set(ast.dump(v) for v in values)):
                self.issues.append({
                    "type": "logic_bug",
                    "category": "duplicate_condition",
                    "severity": "medium",
                    "message": "Condition có phần trùng lặp",
                    "line": node.lineno,
                    "file": self.file_path,
                    "recommendation": "Loại bỏ conditions trùng lặp"
                })
        
        self.generic_visit(node)
    
    def visit_Compare(self, node):
        """Phát hiện comparison bugs"""
        # Check x == x
        if isinstance(node.left, ast.Name):
            for comp in node.comparators:
                if isinstance(comp, ast.Name) and comp.id == node.left.id:
                    self.issues.append({
                        "type": "logic_bug",
                        "category": "self_comparison",
                        "severity": "high",
                        "message": f"So sánh biến với chính nó: {node.left.id} == {node.left.id}",
                        "line": node.lineno,
                        "file": self.file_path,
                        "recommendation": "Có thể là typo - kiểm tra lại logic"
                    })
        
        self.generic_visit(node)


def analyze_advanced_security(file_path: str, code: str) -> List[Dict]:
    """
    Main function để chạy tất cả advanced security analysis
    """
    all_issues = []
    
    try:
        tree = ast.parse(code, filename=file_path)
        
        # Advanced Security
        adv_security = AdvancedSecurityAnalyzer(tree, code, file_path)
        all_issues.extend(adv_security.analyze())
        
        # XXE
        xxe = XXEAnalyzer(code, file_path)
        all_issues.extend(xxe.analyze())
        
        # SSTI
        ssti = SSTIAnalyzer(code, file_path)
        all_issues.extend(ssti.analyze())
        
        # Logic Bugs
        logic = LogicBugAnalyzer(tree, file_path)
        all_issues.extend(logic.analyze())
        
    except SyntaxError:
        pass
    except Exception as e:
        print(f"Error in advanced security analysis: {e}")
    
    return all_issues