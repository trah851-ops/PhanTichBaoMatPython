# analyzer/taint.py - IMPROVED VERSION with Sanitizer Detection
import ast
from typing import Set, Dict, List, Any
from collections import defaultdict

class TaintAnalyzer(ast.NodeVisitor):
    """
    Improved Taint Analyzer với:
    - Sanitizer detection
    - Context-sensitive analysis
    - Inter-procedural tracking (basic)
    - Reduced false positives
    """
    
    def __init__(self, tree, sources, sinks, file_path):
        self.sources = sources
        self.sinks = sinks
        self.file_path = file_path
        
        # Taint tracking
        self.tainted_vars = set()
        self.sanitized_vars = set()  # Variables that have been sanitized
        self.safe_vars = set()  # Variables that are safe by nature
        
        # Sanitizers - functions that clean/validate input
        self.sanitizers = {
            # HTML/XSS sanitizers
            'html.escape', 'bleach.clean', 'bleach.linkify', 'markupsafe.escape',
            'jinja2.escape', 'django.utils.html.escape', 'flask.escape',
            
            # SQL sanitizers (parameterized queries are handled separately)
            'psycopg2.sql.SQL', 'psycopg2.sql.Identifier', 'psycopg2.sql.Literal',
            'sqlalchemy.text', 'django.db.models.Q',
            
            # Path sanitizers
            'os.path.abspath', 'os.path.normpath', 'pathlib.Path',
            'werkzeug.utils.secure_filename',
            
            # Command sanitizers
            'shlex.quote', 'shlex.split',
            
            # General validators
            'int', 'float', 'str', 'bool',  # Type conversions
            'isinstance', 'type',
            're.escape', 'urllib.parse.quote', 'urllib.parse.quote_plus',
            'base64.b64encode',
            
            # Validation functions
            'validate', 'sanitize', 'clean', 'filter', 'escape',
            'check', 'verify', 'whitelist',
        }
        
        # Safe patterns that indicate validation
        self.safe_patterns = {
            'startswith', 'endswith', 'isdigit', 'isalpha', 'isalnum',
            'max', 'min', 'len',
        }
        
        # Track variable definitions
        self.var_definitions = defaultdict(list)  # var -> [line_numbers]
        
        # Track function parameters
        self.function_params = {}  # func_name -> [param_names]
        self.current_function = None
        
        self.issues = []
        self.visit(tree)

    def visit_FunctionDef(self, node):
        """Track function definitions and parameters"""
        self.current_function = node.name
        
        # Store parameters
        param_names = [arg.arg for arg in node.args.args]
        self.function_params[node.name] = param_names
        
        # If function name suggests it's a validator/sanitizer, mark params as safe
        if any(keyword in node.name.lower() for keyword in ['validate', 'sanitize', 'clean', 'check']):
            for param in param_names:
                self.safe_vars.add(param)
        
        self.generic_visit(node)
        self.current_function = None

    def visit_Assign(self, node):
        """Track assignments and taint propagation"""
        is_tainted = False
        is_sanitized = False
        
        # Get target variable names
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
                self.var_definitions[target.id].append(node.lineno)
        
        # Check if value is from a taint source
        if isinstance(node.value, ast.Call):
            func_name = self._get_func_name(node.value.func)
            
            # Check if it's a source
            if self._is_source(func_name):
                is_tainted = True
            
            # Check if it's a sanitizer
            elif self._is_sanitizer(func_name):
                is_sanitized = True
                
                # Check if sanitizer is applied to tainted variable
                for arg in node.value.args:
                    if isinstance(arg, ast.Name):
                        if arg.id in self.tainted_vars:
                            # Mark target as sanitized
                            for target in targets:
                                self.sanitized_vars.add(target)
                                if target in self.tainted_vars:
                                    self.tainted_vars.remove(target)
            
            # Type conversion functions (safe)
            elif func_name in ['int', 'float', 'bool', 'str'] and len(node.value.args) > 0:
                # Type conversion sanitizes most injection attacks
                is_sanitized = True
                for target in targets:
                    self.safe_vars.add(target)
        
        # Check if value is from tainted variable
        elif isinstance(node.value, ast.Name):
            if node.value.id in self.tainted_vars and node.value.id not in self.sanitized_vars:
                is_tainted = True
            elif node.value.id in self.sanitized_vars:
                is_sanitized = True
        
        # Check if value is from tainted operation (concatenation, formatting)
        elif isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
            if self._contains_tainted_var(node.value):
                # Check if there's sanitization in the operation
                if self._contains_sanitizer(node.value):
                    is_sanitized = True
                else:
                    is_tainted = True
        
        # Constant values are safe
        elif isinstance(node.value, ast.Constant):
            for target in targets:
                self.safe_vars.add(target)
        
        # Update taint status
        if is_tainted and not is_sanitized:
            for target in targets:
                self.tainted_vars.add(target)
                # Remove from safe/sanitized if was there
                self.safe_vars.discard(target)
                self.sanitized_vars.discard(target)
        
        elif is_sanitized:
            for target in targets:
                self.sanitized_vars.add(target)
                self.tainted_vars.discard(target)

        self.generic_visit(node)

    def visit_Call(self, node):
        """Check if tainted data flows into dangerous sinks"""
        func_name = self._get_func_name(node.func)
        
        # Skip if this is a sanitizer call
        if self._is_sanitizer(func_name):
            self.generic_visit(node)
            return
        
        # Check if this is a dangerous sink
        if any(sink in func_name for sink in self.sinks):
            # Special case: Parameterized queries are safe
            if self._is_parameterized_query(node, func_name):
                self.generic_visit(node)
                return
            
            # Check each argument
            for arg_idx, arg in enumerate(node.args):
                vulnerability = self._check_argument_safety(arg, func_name, node.lineno, arg_idx)
                if vulnerability:
                    self.issues.append(vulnerability)

        self.generic_visit(node)

    def _check_argument_safety(self, arg, sink_func: str, line: int, arg_idx: int) -> Dict:
        """Check if an argument to a sink is safe"""
        
        # 1. Direct tainted variable
        if isinstance(arg, ast.Name):
            if arg.id in self.tainted_vars and arg.id not in self.sanitized_vars:
                return {
                    "type": "taint_analysis",
                    "category": "injection_risk",
                    "severity": self._get_severity(sink_func),
                    "message": f"DÒNG DỮ LIỆU NGUY HIỂM: Biến '{arg.id}' (chưa sanitize) đi vào hàm nguy hiểm '{sink_func}'",
                    "line": line,
                    "file": self.file_path,
                    "recommendation": self._get_recommendation(sink_func, arg.id),
                    "confidence": "high"
                }
            
            # Safe variables
            elif arg.id in self.safe_vars or arg.id in self.sanitized_vars:
                return None
        
        # 2. F-string with tainted variables
        elif isinstance(arg, ast.JoinedStr):
            tainted_parts = []
            has_sanitization = False
            
            for value in arg.values:
                if isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name):
                        if value.value.id in self.tainted_vars:
                            tainted_parts.append(value.value.id)
                        elif value.value.id in self.sanitized_vars:
                            has_sanitization = True
            
            if tainted_parts and not has_sanitization:
                return {
                    "type": "taint_analysis",
                    "category": "injection_risk",
                    "severity": self._get_severity(sink_func),
                    "message": f"DÒNG DỮ LIỆU NGUY HIỂM: F-string chứa biến tainted {tainted_parts} đi vào '{sink_func}'",
                    "line": line,
                    "file": self.file_path,
                    "recommendation": self._get_recommendation(sink_func, str(tainted_parts)),
                    "confidence": "high"
                }
        
        # 3. Binary operation with tainted variables
        elif isinstance(arg, ast.BinOp):
            if self._contains_tainted_var(arg) and not self._contains_sanitizer(arg):
                tainted_vars = self._extract_tainted_vars(arg)
                return {
                    "type": "taint_analysis",
                    "category": "injection_risk",
                    "severity": self._get_severity(sink_func),
                    "message": f"DÒNG DỮ LIỆU NGUY HIỂM: Phép toán chứa biến tainted {tainted_vars} đi vào '{sink_func}'",
                    "line": line,
                    "file": self.file_path,
                    "recommendation": self._get_recommendation(sink_func, str(tainted_vars)),
                    "confidence": "medium"
                }
        
        # 4. Method call on tainted variable
        elif isinstance(arg, ast.Call):
            # Check if it's a safe transformation
            if self._is_sanitizer(self._get_func_name(arg.func)):
                return None
        
        return None

    def _is_parameterized_query(self, node: ast.Call, func_name: str) -> bool:
        """
        Check if SQL query is parameterized (safe)
        Example: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        """
        if 'execute' not in func_name:
            return False
        
        # Parameterized query has 2+ arguments: (query, params)
        if len(node.args) >= 2:
            # First arg is query string, second is parameters
            return True
        
        # Check for named parameters style
        if len(node.keywords) > 0:
            return True
        
        return False

    def _is_source(self, call_name: str) -> bool:
        """Check if function is a taint source"""
        return any(src in call_name for src in self.sources)

    def _is_sanitizer(self, func_name: str) -> bool:
        """Check if function is a sanitizer"""
        # Check exact match
        if func_name in self.sanitizers:
            return True
        
        # Check partial match (e.g., "sanitize_input" contains "sanitize")
        func_lower = func_name.lower()
        for sanitizer in self.sanitizers:
            if sanitizer in func_lower:
                return True
        
        return False

    def _contains_sanitizer(self, node) -> bool:
        """Check if expression contains a sanitizer call"""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child.func)
                if self._is_sanitizer(func_name):
                    return True
        return False

    def _check_taint_recursive(self, node) -> bool:
        """Recursively check if node contains tainted variable"""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars and node.id not in self.sanitized_vars
        
        if isinstance(node, ast.BinOp):
            return self._check_taint_recursive(node.left) or self._check_taint_recursive(node.right)
        
        return False

    def _contains_tainted_var(self, node) -> bool:
        """Check if node contains any tainted variable"""
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in self.tainted_vars and child.id not in self.sanitized_vars:
                    return True
        return False

    def _extract_tainted_vars(self, node) -> List[str]:
        """Extract all tainted variable names from node"""
        tainted = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in self.tainted_vars and child.id not in self.sanitized_vars:
                    tainted.append(child.id)
        return tainted

    def _get_func_name(self, func) -> str:
        """Get full function name"""
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return f"{self._get_func_name(func.value)}.{func.attr}"
        return ""

    def _get_severity(self, sink_func: str) -> str:
        """Determine severity based on sink type"""
        critical_sinks = ['eval', 'exec', 'compile', '__import__', 'os.system', 'pickle.loads']
        high_sinks = ['subprocess', 'os.popen', 'open', 'yaml.load']
        
        for critical in critical_sinks:
            if critical in sink_func:
                return 'critical'
        
        for high in high_sinks:
            if high in sink_func:
                return 'high'
        
        return 'medium'

    def _get_recommendation(self, sink_func: str, var_name: str) -> str:
        """Get specific recommendation based on sink type"""
        recommendations = {
            'execute': f"Sử dụng parameterized query: cursor.execute('SELECT * WHERE id=?', ({var_name},))",
            'system': f"Tránh os.system(). Dùng subprocess với shell=False và list arguments",
            'eval': f"KHÔNG BAO GIỜ dùng eval() với user input. Dùng ast.literal_eval() hoặc json.loads()",
            'exec': f"KHÔNG BAO GIỜ dùng exec() với user input",
            'open': f"Validate path với os.path.abspath() và kiểm tra prefix: if not path.startswith(SAFE_DIR): raise Error",
            'subprocess': f"Dùng subprocess.run() với shell=False và truyền command dạng list: ['ls', '-la']",
            'pickle': f"KHÔNG dùng pickle với untrusted data. Dùng JSON thay thế",
            'yaml.load': f"Dùng yaml.safe_load() thay vì yaml.load()",
        }
        
        for key, rec in recommendations.items():
            if key in sink_func:
                return rec
        
        return f"Sanitize/validate biến '{var_name}' trước khi sử dụng"

    def analyze(self) -> List[Dict]:
        """Return all taint analysis issues"""
        return self.issues