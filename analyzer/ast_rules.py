# analyzer/ast_rules.py
import ast
from typing import List, Dict

# Helper to create an issue dict consistent with core.py format
def _issue(filename, lineno, typ, msg, severity="medium"):
    return {"file": filename, "lineno": lineno or 0, "type": typ, "severity": severity, "msg": msg}


def run_checks(tree: ast.AST, filename: str) -> List[Dict]:
    """
    Run a suite of AST-based checks and return a list of issue dicts.
    """
    issues = []

    # 1) Mutable default arguments
    for node in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        defaults = node.args.defaults or []
        for idx, d in enumerate(defaults):
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                lineno = getattr(node, "lineno", None)
                issues.append(_issue(filename, lineno, "Logic",
                                     f"Mutable default parameter detected in function '{node.name}'.",
                                     "high"))

    # 2) Bare except
    for node in [n for n in ast.walk(tree) if isinstance(n, ast.Try)]:
        for handler in node.handlers:
            if handler.type is None:
                lineno = getattr(handler, "lineno", None)
                issues.append(_issue(filename, lineno, "Style",
                                     "Bare except detected — should catch specific exception.",
                                     "medium"))

    # 3) Wildcard import
    for node in [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]:
        for alias in node.names:
            if alias.name == "*" or alias.asname == "*":
                lineno = getattr(node, "lineno", None)
                issues.append(_issue(filename, lineno, "Style",
                                     f"Wildcard import from module '{node.module}' detected.",
                                     "low"))

    # 4) Unused imports (simple)
    # Collect imports
    imports = {}  # name -> lineno
    for node in [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                imports[name] = getattr(node, "lineno", None)
        else:
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = getattr(node, "lineno", None)

    # Collect used names
    used = set()
    for n in [n for n in ast.walk(tree) if isinstance(n, ast.Name)]:
        # consider usage (Load context)
        if isinstance(n.ctx, ast.Load):
            used.add(n.id)

    for name, lineno in imports.items():
        if name not in used:
            issues.append(_issue(filename, lineno, "Maintainability",
                                 f"Imported name '{name}' appears unused.",
                                 "low"))

    # 5) Unused local variables (per function) — simple heuristic
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        assigned = set()
        used_local = set()
        for n in ast.walk(func):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        assigned.add(t.id)
            if isinstance(n, ast.Name):
                if isinstance(n.ctx, ast.Load):
                    used_local.add(n.id)
        # variables assigned but never loaded
        unused = assigned - used_local
        for v in unused:
            # skip common names (self)
            if v == "self":
                continue
            lineno = getattr(func, "lineno", None)
            issues.append(_issue(filename, lineno, "Maintainability",
                                 f"Variable '{v}' assigned but not used in function '{func.name}'.",
                                 "low"))

    # 6) Function with many returns
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        returns = [n for n in ast.walk(func) if isinstance(n, ast.Return)]
        if len(returns) > 1:
            lineno = getattr(func, "lineno", None)
            issues.append(_issue(filename, lineno, "Logic",
                                 f"Hàm '{func.name}' có nhiều return — xem xét hợp nhất logic.",
                                 "low"))

    # 7) Nested if depth
    def max_if_depth(node, depth=0):
        maxd = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If):
                maxd = max(maxd, max_if_depth(child, depth + 1))
            else:
                maxd = max(maxd, max_if_depth(child, depth))
        return maxd

    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        depth = max_if_depth(func, 0)
        if depth >= 3:
            lineno = getattr(func, "lineno", None)
            issues.append(_issue(filename, lineno, "Maintainability",
                                 f"Hàm '{func.name}' có nested-if depth = {depth}.",
                                 "medium"))

    # 8) Function too long (use end_lineno if available)
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        start = getattr(func, "lineno", None)
        end = getattr(func, "end_lineno", None)
        if start and end and (end - start) > 50:
            issues.append(_issue(filename, start, "Maintainability",
                                 f"Function '{func.name}' too long ({end - start} lines). Consider refactoring.",
                                 "low"))

    # 9) open() usage not under with (detect calls to open and check parent context)
    # Strategy: collect open calls and mark ones inside With nodes as safe
    open_calls = []  # (lineno, node)
    for node in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            open_calls.append(node)

    # find all calls under With nodes
    safe_nodes = set()
    for w in [n for n in ast.walk(tree) if isinstance(n, ast.With)]:
        for n in ast.walk(w):
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open":
                safe_nodes.add(n)

    for call in open_calls:
        if call not in safe_nodes:
            lineno = getattr(call, "lineno", None)
            issues.append(_issue(filename, lineno, "Security",
                                 "open() used outside context manager (with).",
                                 "medium"))

    # 10) print() usage (AST) — complementing regex
    for node in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            lineno = getattr(node, "lineno", None)
            issues.append(_issue(filename, lineno, "Style",
                                 "Phát hiện print() — debug code.",
                                 "low"))

    return issues
