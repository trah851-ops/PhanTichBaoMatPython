# analyzer/ast_rules.py
# AST Linting Engine - Phát hiện lỗi logic, code smell và vấn đề chất lượng code
# Tác giả: [Tên bạn] - PyScan Pro
import ast
from typing import List, Set, Any
from collections import defaultdict

# ------------------------------------------------------------------
# Định nghĩa Issue và Severity (để dùng chung toàn dự án)
# ------------------------------------------------------------------
class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class SecurityIssue:
    def __init__(self, severity: str, category: str, message: str, line: int,
                 column: int = 0, code_snippet: str = "", recommendation: str = "", cwe_id: str = ""):
        self.severity = severity
        self.category = category
        self.message = message
        self.line = line
        self.column = column
        self.code_snippet = code_snippet
        self.recommendation = recommendation
        self.cwe_id = cwe_id

# ------------------------------------------------------------------
# Helper: Thêm thuộc tính parent cho tất cả node (để check with open)
# ------------------------------------------------------------------
class NodeParentTracker(ast.NodeVisitor):
    def visit(self, node: ast.AST):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore
            self.visit(child)

# ------------------------------------------------------------------
# AST Linter chính - SIÊU MẠNH, SIÊU CHUẨN
# ------------------------------------------------------------------
class ASTLinter:
    MAX_FUNCTION_LENGTH = 50
    MAX_COMPLEXITY = 12
    MAX_PARAMETERS = 6

    def __init__(self, tree: ast.AST, code: str, file_path: str = ""):
        self.tree = tree
        self.code = code
        self.file_path = file_path
        self.lines = code.splitlines()
        self.issues: List[SecurityIssue] = []

        # Thêm parent để check context (with open, try-except,...)
        NodeParentTracker().visit(tree)

        # Tracking
        self.imported_names: Set[str] = set()
        self.used_names: Set[str] = set()
        self.defined_vars: Set[str] = set()

    def lint(self) -> List[dict]:
        """Chạy toàn bộ kiểm tra và trả về list issue dạng dict (dễ dùng cho web/CLI)"""
        self._collect_info()
        self._run_all_checks()
        return [self._to_dict(issue) for issue in self.issues]

    def _collect_info(self):
        for node in ast.walk(self.tree):
            # Thu thập import
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    name = alias.asname or alias.name.split('.')[-1]
                    self.imported_names.add(name)
            # Thu thập biến + hàm được dùng
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Load):
                    self.used_names.add(node.id)
                elif isinstance(node.ctx, ast.Store):
                    self.defined_vars.add(node.id)

    def _run_all_checks(self):
        self._check_unused_imports()
        self._check_unused_variables()
        self._check_bare_except()
        self._check_mutable_defaults()
        self._check_function_complexity()
        self._check_missing_docstrings()
        self._check_open_without_context()
        self._check_assert_in_production()
        self._check_print_statements()
        self._check_global_usage()

    # =================================================================
    # Các rule kiểm tra
    # =================================================================

    def _check_mutable_defaults(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                for default in node.args.defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        self.issues.append(SecurityIssue(
                            severity=Severity.HIGH,
                            category="mutable_default",
                            message=f"LỖ HỔNG BẢO MẬT: Mutable default argument trong hàm '{node.name}'",
                            line=node.lineno,
                            recommendation="Dùng None làm default và khởi tạo bên trong hàm"
                        ))

    def _check_bare_except(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                self.issues.append(SecurityIssue(
                    severity=Severity.MEDIUM,
                    category="bare_except",
                    message="Dùng except trống – bắt tất cả lỗi, kể cả SystemExit",
                    line=node.lineno,
                    recommendation="Chỉ bắt exception cụ thể: except ValueError:"
                ))

    def _check_unused_imports(self):
        unused = self.imported_names - self.used_names
        for name in unused:
            if not name.startswith('_'):
                self.issues.append(SecurityIssue(
                    severity=Severity.LOW,
                    category="unused_import",
                    message=f"Import không sử dụng: {name}",
                    line=1,
                    recommendation="Xóa import thừa"
                ))

    def _check_unused_variables(self):
        unused = self.defined_vars - self.used_names
        for name in unused:
            if not name.startswith('_'):
                self.issues.append(SecurityIssue(
                    severity=Severity.LOW,
                    category="unused_variable",
                    message=f"Biến không sử dụng: {name}",
                    line=1,
                    recommendation="Xóa hoặc sử dụng biến"
                ))

    def _check_function_complexity(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            # Độ dài hàm
            if hasattr(node, 'end_lineno'):
                length = node.end_lineno - node.lineno + 1
                if length > self.MAX_FUNCTION_LENGTH:
                    self.issues.append(SecurityIssue(
                        severity=Severity.MEDIUM,
                        category="long_function",
                        message=f"Hàm '{node.name}' quá dài ({length} dòng)",
                        line=node.lineno,
                        recommendation="Chia nhỏ thành nhiều hàm"
                    ))

    def _check_missing_docstrings(self):
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith('_'):
                has_doc = (node.body and isinstance(node.body[0], ast.Expr) and
                          isinstance(node.body[0].value, ast.Constant) and
                          isinstance(node.body[0].value.value, str))
                if not has_doc:
                    self.issues.append(SecurityIssue(
                        severity=Severity.INFO,
                        category="missing_docstring",
                        message=f"Thiếu docstring cho {node.__class__.__name__.lower()} '{node.name}'",
                        line=node.lineno,
                        recommendation="Thêm \"\"\"Mô tả chức năng\"\"\""
                    ))

    def _check_open_without_context(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                current = node
                while hasattr(current, "parent"):
                    current = current.parent
                    if isinstance(current, ast.With):
                        break
                else:
                    self.issues.append(SecurityIssue(
                        severity=Severity.MEDIUM,
                        category="open_no_context",
                        message="open() không dùng with – có thể quên đóng file",
                        line=node.lineno,
                        recommendation="Dùng: with open(...) as f:"
                    ))

    def _check_assert_in_production(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assert):
                self.issues.append(SecurityIssue(
                    severity=Severity.LOW,
                    category="assert_used",
                    message="Dùng assert – sẽ bị tắt khi chạy python -O",
                    line=node.lineno,
                    recommendation="Thay bằng if + raise"
                ))

    def _check_print_statements(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                self.issues.append(SecurityIssue(
                    severity=Severity.LOW,
                    category="print_stmt",
                    message="Dùng print() – nên dùng logging trong production",
                    line=node.lineno
                ))

    def _check_global_usage(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Global):
                self.issues.append(SecurityIssue(
                    severity=Severity.MEDIUM,
                    category="global_usage",
                    message=f"Dùng global: {', '.join(node.names)}",
                    line=node.lineno,
                    recommendation="Tránh global, dùng parameter hoặc class"
                ))

    # =================================================================
    # Chuyển issue sang dict để web/CLI dùng
    # =================================================================
    def _to_dict(self, issue: SecurityIssue) -> dict:
        return {
            "type": "ast_lint",
            "category": issue.category,
            "message": issue.message,
            "severity": issue.severity,
            "line": issue.line,
            "file": self.file_path,
            "recommendation": issue.recommendation
        }