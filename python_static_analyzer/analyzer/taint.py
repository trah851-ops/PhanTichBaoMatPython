# analyzer/taint.py
import ast
class SimpleTaintEngine:
    def __init__(self):
        self.tainted = {}
        self.expr_taint = {}

    def taint_name(self, name, lineno, sources=None):
        if not sources:
            sources = set(["taint"])
        else:
            sources = set(sources)
        self.tainted.setdefault(name, set()).update(sources)

    def mark_expr_tainted(self, expr_node, source="unknown"):
        self.expr_taint[id(expr_node)] = set([source])

    def eval_expr(self, node):
        if node is None:
            return set()
        if isinstance(node, ast.Constant):
            return set()
        if isinstance(node, ast.Name):
            return set(self.tainted.get(node.id, set()))
        if isinstance(node, ast.Attribute):
            name = self.attr_to_name(node)
            if name:
                return set(self.tainted.get(name, set()))
            return set()
        if isinstance(node, ast.Call):
            t = self.expr_taint.get(id(node))
            if t:
                return set(t)
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "input":
                return set(["input()"])
            if isinstance(fn, ast.Attribute) and getattr(fn, "attr", "") in ("getenv", "get"):
                return set(["os.getenv"])
            labels = set()
            for a in node.args:
                labels |= self.eval_expr(a)
            for k in getattr(node, "keywords", []):
                labels |= self.eval_expr(k.value)
            return labels
        if isinstance(node, ast.BinOp):
            return self.eval_expr(node.left) | self.eval_expr(node.right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            labels = set()
            for e in node.elts:
                labels |= self.eval_expr(e)
            return labels
        if isinstance(node, ast.Subscript):
            return self.eval_expr(node.value) | self.eval_expr(node.slice)
        return set()

    def attr_to_name(self, node):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.insert(0, cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.insert(0, cur.id)
            return ".".join(parts)
        return None
