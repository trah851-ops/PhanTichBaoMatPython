# analyzer/taint.py - FIXED VERSION
import ast

class TaintAnalyzer(ast.NodeVisitor):
    """Phân tích luồng dữ liệu tainted (từ input nguy hiểm đến sink)"""
    
    def __init__(self, tree, sources, sinks, file_path):
        self.sources = sources
        self.sinks = sinks
        self.tainted_vars = set()
        self.issues = []
        self.file_path = file_path
        self.visit(tree)

    def visit_Call(self, node):
        """Kiểm tra function call"""
        func_name = self._get_func_name(node.func)
        
        # Check nếu là taint source (input, request.form, etc.)
        if any(src in func_name for src in self.sources):
            # Mark biến nhận giá trị từ source là tainted
            parent = getattr(node, 'parent', None)
            if parent and isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        # Check nếu là sink nguy hiểm (eval, os.system, etc.)
        if any(sink in func_name for sink in self.sinks):
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    self.issues.append({
                        "type": "taint_flow",
                        "category": "data_flow",
                        "message": f"NGUY HIỂM: Dữ liệu tainted → {func_name}()",
                        "line": node.lineno,
                        "file": self.file_path,
                        "severity": "critical",
                        "recommendation": f"Validate/sanitize input trước khi dùng {func_name}"
                    })
        
        self.generic_visit(node)

    def visit_Assign(self, node):
        """Track assignment để lan truyền taint"""
        # Nếu gán từ biến tainted → biến mới cũng tainted
        if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        
        self.generic_visit(node)

    def _get_func_name(self, func):
        """Lấy tên function từ AST node"""
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            # os.system → "os.system"
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""

    def analyze(self):
        """Trả về danh sách issues"""
        return self.issues