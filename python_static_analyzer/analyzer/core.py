# analyzer/core.py
"""Core static analyzer (pure Python): AST-based checks + simple taint tracking.
Entry point: analyze_file(path) or analyze_code(source, filename)
Returns: {"issues": [...], "summary": {...}}
"""
import ast, re
from collections import defaultdict
from .taint import SimpleTaintEngine
from .rules import load_rules_from_file

class Issue:
    def __init__(self, type_, lineno, msg, severity="medium", rule_id=None, extra=None):
        self.type = type_
        self.lineno = lineno or 0
        self.msg = msg
        self.severity = severity
        self.rule_id = rule_id
        self.extra = extra or {}

    def to_dict(self):
        return {
            "type": self.type,
            "lineno": self.lineno,
            "msg": self.msg,
            "severity": self.severity,
            "rule_id": self.rule_id,
            **({"extra": self.extra} if self.extra else {})
        }

class Analyzer(ast.NodeVisitor):
    def __init__(self, filename="<string>", rules=None):
        self.issues = []
        self.filename = filename
        self.imports = {}
        self.used_names = set()
        self.defined_names = set()
        self.assigns = []
        self.rules = rules or []
        self.taint = SimpleTaintEngine()
        self.current_func = None

    def add_issue(self, type_, node, msg, severity="medium", rule_id=None, extra=None):
        lineno = getattr(node, "lineno", None) or (extra.get("lineno") if extra else 0) or 0
        self.issues.append(Issue(type_, lineno, msg, severity, rule_id, extra))

    def visit_Import(self, node):
        for alias in node.names:
            asname = alias.asname or alias.name.split('.')[0]
            self.imports[asname] = (alias.name, node.lineno)
            self.defined_names.add(asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if any(a.name == "*" for a in node.names):
            self.add_issue("Style/Quy ước", node, f"from {node.module} import * (reduces clarity)", "low")
        for alias in node.names:
            asname = alias.asname or alias.name
            self.imports[asname] = (f"{node.module}.{alias.name}" if node.module else alias.name, node.lineno)
            self.defined_names.add(asname)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.add_issue("Lỗi Logic", node, f"Function '{node.name}' has mutable default argument.", "high")
        self.defined_names.add(node.name)
        prev = self.current_func
        self.current_func = node
        self.generic_visit(node)
        self.current_func = prev

    def visit_ExceptHandler(self, node):
        if node.type is None:
            self.add_issue("Lỗi Logic", node, "Bare except: statement; catch specific exceptions instead.", "medium")
        self.generic_visit(node)

    def visit_Assign(self, node):
        for t in node.targets:
            self.assigns.append((t, node.value, node.lineno))
        value_taints = self.taint.eval_expr(node.value)
        for t in node.targets:
            if isinstance(t, ast.Name):
                if value_taints:
                    self.taint.taint_name(t.id, node.lineno, sources=value_taints)
            elif isinstance(t, ast.Attribute):
                name = self.taint.attr_to_name(t)
                if name and value_taints:
                    self.taint.taint_name(name, node.lineno, sources=value_taints)
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = self._get_call_fullname(node.func)
        if func_name:
            if re.search(r"(^|\\.)(eval|exec)$", func_name):
                self.add_issue("Bảo mật", node, f"Call to '{func_name}' may lead to code execution.", "high")
            if func_name.endswith("os.system") or func_name.endswith("system"):
                self.add_issue("Bảo mật", node, "Use of os.system; check inputs to avoid command injection.", "high")
            if "subprocess" in func_name or "Popen" in func_name:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.add_issue("Bảo mật", node, f"subprocess called with shell=True at line {node.lineno}", "high")
            arg_taints = set()
            for a in node.args:
                arg_taints.update(self.taint.eval_expr(a))
            for kw in node.keywords:
                arg_taints.update(self.taint.eval_expr(kw.value))
            for sink in ("eval", "exec", "os.system", "subprocess.run", "subprocess.Popen"):
                if func_name.endswith(sink):
                    if arg_taints:
                        self.add_issue("Bảo mật", node, f"Tainted data flows into sink '{func_name}'. Sources: {sorted(arg_taints)}", "high")
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            self.taint.mark_expr_tainted(node, source="input()")
        if isinstance(node.func, ast.Attribute):
            if getattr(node.func, "attr", "") in ("getenv",):
                self.taint.mark_expr_tainted(node, source="os.getenv")
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        if isinstance(node.ctx, ast.Store):
            self.defined_names.add(node.id)
        self.generic_visit(node)

    def analyze_additional(self, tree, source_text):
        for alias, (module, lineno) in self.imports.items():
            if alias not in self.used_names:
                self.add_issue("Style/Quy ước", ast.AST(), f"Import '{alias}' (from {module}) appears unused.", "low", extra={"lineno": lineno})
        suspicious_keys = ("password","passwd","secret","token","apikey","api_key","key")
        for target, value, lineno in self.assigns:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if name and any(k in name.lower() for k in suspicious_keys):
                if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                    self.add_issue("Bảo mật", ast.AST(), f"Possible hard-coded secret in '{name}'.", "high", extra={"lineno": lineno})
        for r in (self.rules or []):
            try:
                pat = r.get("pattern")
                if not pat:
                    continue
                for m in re.finditer(pat, source_text, flags=re.MULTILINE):
                    lineno = source_text[:m.start()].count("\\n") + 1
                    self.add_issue(r.get("type", "Rule"), ast.AST(), r.get("message", "Rule triggered"), r.get("severity","medium"), rule_id=r.get("id"))
            except re.error:
                continue

    def _get_call_fullname(self, node):
        parts = []
        cur = node
        while True:
            if isinstance(cur, ast.Name):
                parts.insert(0, cur.id)
                break
            elif isinstance(cur, ast.Attribute):
                parts.insert(0, cur.attr)
                cur = cur.value
                continue
            else:
                return None
        return ".".join(parts)

def analyze_code(source_text, filename="<string>", rules_path=None):
    try:
        tree = ast.parse(source_text, filename=filename)
    except SyntaxError as e:
        return {"issues":[Issue("Lỗi Cú pháp", e.lineno or 0, f"SyntaxError: {e.msg}").to_dict()], "summary":{"total":1}}

    rules = load_rules_from_file(rules_path) if rules_path else []
    analyzer = Analyzer(filename=filename, rules=rules)
    analyzer.visit(tree)
    analyzer.analyze_additional(tree, source_text)
    issues = [i.to_dict() for i in analyzer.issues]
    issues.sort(key=lambda x: (x.get("lineno", 0), x.get("severity","")))
    summary = defaultdict(int)
    for it in issues:
        summary[it.get("type", "Thông báo")] += 1
    summary["total"] = len(issues)
    return {"issues": issues, "summary": dict(summary)}

def analyze_file(path, rules_path=None):
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    return analyze_code(src, filename=path, rules_path=rules_path)
