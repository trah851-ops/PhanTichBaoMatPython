# analyzer/ast_rules.py - IMPROVED with Reduced False Positives
import ast
import re

class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityIssue:
    def __init__(self, severity, category, message, line, recommendation="", code_context="", confidence="high"):
        self.severity = severity
        self.category = category
        self.message = message
        self.line = line
        self.recommendation = recommendation
        self.code_context = code_context
        self.confidence = confidence  # high, medium, low

class ASTLinter(ast.NodeVisitor):
    def __init__(self, tree: ast.AST, code: str, file_path: str = ""):
        self.tree = tree
        self.code = code
        self.file_path = file_path
        self.issues = []
        self.lines = code.split('\n')
        
        # Track context to reduce false positives
        self.in_test_file = 'test' in file_path.lower()
        self.constants = set()  # Track constant values
        self.safe_functions = set()  # Functions that validate/sanitize
    
    def lint(self):
        self.visit(self.tree)
        return [self._to_dict(i) for i in self.issues]

    def _add(self, sev, cat, msg, line, rec="", context_lines=2, confidence="high"):
        code_context = self._get_code_context(line, context_lines)
        self.issues.append(SecurityIssue(sev, cat, msg, line, rec, code_context, confidence))

    def _get_code_context(self, line_num, context_lines=2):
        start = max(0, line_num - context_lines - 1)
        end = min(len(self.lines), line_num + context_lines)
        
        context = []
        for i in range(start, end):
            line_content = self.lines[i].rstrip()
            is_error_line = (i == line_num - 1)
            context.append(f"{i+1}: {line_content}")
        return "\n".join(context)

    def visit_FunctionDef(self, node):
        """Check function definitions"""
        # Track safe functions
        if any(keyword in node.name.lower() for keyword in ['validate', 'sanitize', 'clean', 'check', 'verify']):
            self.safe_functions.add(node.name)
        
        # Check unreachable code
        has_return = False
        for idx, child in enumerate(node.body):
            if has_return and idx < len(node.body) - 1:  # Not the last statement
                # Skip docstrings
                if isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant):
                    continue
                
                self._add(Severity.MEDIUM, "unreachable_code", 
                          "Code sau return/raise sẽ không bao giờ chạy", 
                          child.lineno, "Xóa code thừa hoặc sửa logic",
                          confidence="high")
            
            if isinstance(child, (ast.Return, ast.Raise)):
                has_return = True
        
        # Check docstring
        if not ast.get_docstring(node) and not node.name.startswith('_'):
            if not self.in_test_file:  # Don't enforce in test files
                self._add(Severity.INFO, "missing_docstring", 
                         f"Thiếu docstring cho hàm '{node.name}'", 
                         node.lineno, "Thêm docstring mô tả chức năng hàm",
                         confidence="high")
        
        # Check function complexity (too many parameters)
        if len(node.args.args) > 7:
            self._add(Severity.MEDIUM, "too_many_parameters",
                     f"Hàm '{node.name}' có {len(node.args.args)} parameters (>7)",
                     node.lineno, "Nhóm parameters vào dict hoặc dataclass",
                     confidence="high")
        
        self.generic_visit(node)

    def visit_Assign(self, node):
        """Check assignments"""
        builtins = dir(__builtins__)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Shadowing builtin (exclude common safe ones)
                safe_builtins = ['_', 'id', 'type', 'len', 'file', 'input']
                if target.id in builtins and target.id not in safe_builtins:
                    self._add(Severity.MEDIUM, "shadowing_builtin", 
                              f"Biến '{target.id}' trùng với hàm built-in của Python", 
                              node.lineno, f"Đổi tên biến (vd: my_{target.id})",
                              confidence="high")
                
                # Hardcoded credentials - IMPROVED detection
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    value = node.value.value
                    var_lower = target.id.lower()
                    
                    # Check if variable name suggests it's a secret
                    secret_indicators = ['pass', 'pwd', 'secret', 'key', 'token', 'auth', 'credential', 'api_key']
                    is_secret_name = any(ind in var_lower for ind in secret_indicators)
                    
                    if is_secret_name and len(value) > 3:
                        # Exclude test/example values
                        test_values = ['test', 'example', 'demo', 'xxx', 'dummy', 'placeholder']
                        if not any(tv in value.lower() for tv in test_values):
                            # Check if it's not a path or URL
                            if not value.startswith(('/', 'http', './', '../')):
                                self._add(Severity.CRITICAL, "hardcoded_secret", 
                                         f"Phát hiện credential cứng trong biến '{target.id}'", 
                                         node.lineno, 
                                         "Dùng os.getenv() hoặc secret manager. VD: PASSWORD = os.getenv('PASSWORD')",
                                         confidence="high")
                    
                    # Check for API keys/tokens pattern
                    api_patterns = [
                        (r'^sk_live_[a-zA-Z0-9]{24,}', 'Stripe Secret Key'),
                        (r'^pk_live_[a-zA-Z0-9]{24,}', 'Stripe Publishable Key'),
                        (r'^AKIA[0-9A-Z]{16}', 'AWS Access Key'),
                        (r'^ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
                        (r'^xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}', 'Slack Bot Token'),
                        (r'^AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
                    ]
                    
                    for pattern, key_type in api_patterns:
                        if re.match(pattern, value):
                            self._add(Severity.CRITICAL, "hardcoded_api_key", 
                                     f"Phát hiện {key_type} cứng trong code", 
                                     node.lineno, 
                                     "LƯU NGAY vào .env file và dùng os.getenv(). Revoke key này!",
                                     confidence="high")
                            break

        self.generic_visit(node)

    def visit_Compare(self, node):
        """Check comparisons"""
        # Singleton comparison
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comparator, ast.Constant):
                if comparator.value in [None, True, False]:
                    self._add(Severity.LOW, "singleton_comparison", 
                              "So sánh với None/True/False nên dùng 'is' hoặc 'is not'", 
                              node.lineno, "Sửa: 'if x is None:' thay vì 'if x == None:'",
                              confidence="high")
        
        # Hardcoded password comparison - IMPROVED
        if isinstance(node.left, ast.Name):
            var_lower = node.left.id.lower()
            sensitive_names = ['pass', 'pwd', 'secret', 'key', 'password', 'token', 'credential']
            
            if any(x in var_lower for x in sensitive_names):
                for comp in node.comparators:
                    if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                        # Exclude test values
                        if comp.value not in ['test', 'example', '']:
                            self._add(Severity.CRITICAL, "hardcoded_comparison", 
                                     "So sánh mật khẩu trực tiếp với chuỗi tĩnh - NGUY HIỂM", 
                                     node.lineno, 
                                     "Dùng bcrypt.checkpw() hoặc argon2.verify(): if bcrypt.checkpw(password, hashed)",
                                     confidence="high")
        
        self.generic_visit(node)

    def visit_BinOp(self, node):
        """Check binary operations"""
        # Division by zero
        if isinstance(node.op, ast.Div):
            if isinstance(node.right, ast.Constant) and node.right.value == 0:
                self._add(Severity.HIGH, "zero_division", 
                         "Chia cho 0 - ZeroDivisionError", 
                         node.lineno, "Kiểm tra: if divisor != 0: result = x / divisor",
                         confidence="high")
        
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        """Check exception handling"""
        # Bare except
        if node.type is None:
            # Allow in very specific cases
            if not self._has_raise_or_log(node):
                self._add(Severity.MEDIUM, "bare_except", 
                         "Dùng 'except:' trống có thể che giấu lỗi nghiêm trọng", 
                         node.lineno, 
                         "Bắt exception cụ thể: except ValueError: hoặc except Exception as e:",
                         confidence="medium")
        
        self.generic_visit(node)

    def _has_raise_or_log(self, node) -> bool:
        """Check if except block has raise or logging"""
        for child in ast.walk(node):
            if isinstance(child, ast.Raise):
                return True
            if isinstance(child, ast.Call):
                func_name = self._get_func_name(child.func)
                if 'log' in func_name.lower() or 'print' in func_name.lower():
                    return True
        return False
    
    def visit_Call(self, node):
        """Check function calls - IMPROVED"""
        func_name = self._get_func_name(node.func)
        
        # Print usage (only warn in non-test files)
        if func_name == "print" and not self.in_test_file:
            self._add(Severity.LOW, "print_usage", 
                     "Dùng print() thay vì logging trong production", 
                     node.lineno, "import logging; logging.info('message')",
                     confidence="low")
        
        # Dangerous functions - IMPROVED context checking
        dangerous_funcs = {
            'eval': ('critical', 'Code injection - KHÔNG BAO GIỜ dùng eval() với user input'),
            'exec': ('critical', 'Code injection - KHÔNG BAO GIỜ dùng exec() với user input'),
            'compile': ('high', 'Code injection risk với untrusted input'),
            'pickle.loads': ('critical', 'Deserialization attack - dùng JSON thay thế'),
            'yaml.load': ('high', 'Deserialization attack - dùng yaml.safe_load()'),
            'marshal.loads': ('critical', 'Unsafe deserialization'),
        }
        
        for danger_func, (severity, msg) in dangerous_funcs.items():
            if danger_func in func_name:
                # Check if used with constant (safe) or variable (dangerous)
                has_variable_arg = False
                for arg in node.args:
                    if not isinstance(arg, ast.Constant):
                        has_variable_arg = True
                        break
                
                if has_variable_arg:
                    self._add(getattr(Severity, severity.upper()), "dangerous_function", 
                             f"Hàm nguy hiểm: {func_name} - {msg}", 
                             node.lineno, 
                             self._get_safe_alternative(danger_func),
                             confidence="high")
        
        # OS command injection - IMPROVED
        os_funcs = ['os.system', 'os.popen', 'subprocess.call', 'subprocess.run', 'subprocess.Popen']
        for os_func in os_funcs:
            if os_func in func_name:
                # Check if shell=True (dangerous)
                has_shell_true = any(
                    isinstance(kw.value, ast.Constant) and kw.value.value == True 
                    for kw in node.keywords if kw.arg == 'shell'
                )
                
                # Check if command is constructed (dangerous)
                has_dynamic_command = False
                for arg in node.args:
                    if isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Name)):
                        has_dynamic_command = True
                        break
                
                if has_shell_true or has_dynamic_command:
                    self._add(Severity.CRITICAL, "command_injection_risk", 
                             f"Command injection risk với {func_name}", 
                             node.lineno, 
                             "Dùng subprocess.run(['ls', '-la'], shell=False) - list arguments",
                             confidence="high")
        
        self.generic_visit(node)

    def visit_With(self, node):
        """Check file operations - IMPROVED"""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name = self._get_func_name(item.context_expr.func)
                
                if func_name == 'open':
                    # Check for path traversal - IMPROVED
                    for arg in item.context_expr.args:
                        # Only warn if path is constructed dynamically
                        if isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Name)):
                            # Check if there's validation nearby
                            if not self._has_path_validation(node.lineno):
                                self._add(Severity.HIGH, "path_traversal_risk", 
                                         "Path traversal risk - path được xây dựng động", 
                                         node.lineno, 
                                         "Validate: path = os.path.abspath(path); if not path.startswith(SAFE_DIR): raise ValueError",
                                         confidence="medium")
        
        self.generic_visit(node)

    def _has_path_validation(self, line_num: int) -> bool:
        """Check if there's path validation nearby"""
        start = max(0, line_num - 5)
        end = min(len(self.lines), line_num + 2)
        
        validation_keywords = ['abspath', 'normpath', 'startswith', 'secure_filename', 'Path']
        
        for i in range(start, end):
            if any(kw in self.lines[i] for kw in validation_keywords):
                return True
        
        return False

    def _get_safe_alternative(self, danger_func: str) -> str:
        """Get safe alternative for dangerous function"""
        alternatives = {
            'eval': "Dùng ast.literal_eval() cho data, hoặc json.loads() cho JSON",
            'exec': "Refactor code để tránh dynamic execution",
            'pickle.loads': "Dùng json.loads() thay thế",
            'yaml.load': "Dùng yaml.safe_load() thay thế",
            'compile': "Tránh compile untrusted code",
        }
        return alternatives.get(danger_func, "Tránh dùng với untrusted input")

    def _get_func_name(self, node):
        """Get full function name"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_func_name(node.value) + '.' + node.attr
        return ""

    def _to_dict(self, issue):
        return {
            "type": "ast_lint", 
            "category": issue.category, 
            "severity": issue.severity,
            "message": issue.message, 
            "line": issue.line, 
            "file": self.file_path,
            "recommendation": issue.recommendation,
            "code": issue.code_context,
            "confidence": issue.confidence
        }