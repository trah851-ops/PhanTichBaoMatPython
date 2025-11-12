# analyzer/core.py
import os
import ast
import re
import json
import io
import tokenize
import builtins
from analyzer import ast_rules
from analyzer.rules import load_rules_from_file
from analyzer.taint import AdvancedTaintEngine


class Analyzer(ast.NodeVisitor):
    def __init__(self, filename, source, rules):
        self.filename = filename
        self.source = source.split("\n")
        self.rules = rules
        self.issues = []
        self.taint = AdvancedTaintEngine()

    def add_issue(self, lineno, issue_type, msg, severity="medium"):
        self.issues.append({
            "file": self.filename,
            "lineno": lineno,
            "type": issue_type,
            "severity": severity,
            "msg": msg
        })

    # --------------------------
    # AST RULES (LINT + SECURITY)
    # --------------------------

    def visit_Assign(self, node):
        # propagate taint (marks variables)
        try:
            self.taint.process_assign(node)
        except Exception:
            # fail-safe: don't crash scanner
            pass

        # detect shadow builtins (only correct if variable is not a module import)
        for target in node.targets:
            if isinstance(target, ast.Name):
                # ignore names starting with underscore
                if target.id in dir(builtins) and not target.id.startswith("_"):
                    self.add_issue(node.lineno, "Shadowing Builtin",
                                   f"Tên `{target.id}` đang che built-in.", "medium")

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # record returns inside function for taint tracking
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                try:
                    self.taint.process_return(child, func_name=node.name)
                except Exception:
                    pass
        # continue visiting body (so inner assignments/calls are processed)
        self.generic_visit(node)

    def visit_Call(self, node):
        func = self._get_call_name(node)

        # detect dangerous calls
        if func in ("eval", "exec"):
            self.add_issue(node.lineno, "Dangerous Call",
                           f"Dùng `{func}()` là nguy hiểm.", "high")

        # subprocess.run with shell=True -> HIGH
        if func in ("subprocess.run", "subprocess.Popen", "subprocess.call"):
            # check kwargs for shell=True
            for kw in getattr(node, "keywords", []):
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.add_issue(node.lineno, "Command Injection",
                                       f"{func} được gọi với shell=True — có nguy cơ shell injection.", "high")
            # also check if any arg is tainted (including function return taint)
            try:
                src = self.taint.get_taint_label(node)
                src |= self.taint.get_call_return_labels(node)
            except Exception:
                src = set()
            if src:
                self.add_issue(node.lineno, "Command Injection",
                               f"Tham số có thể bị taint: {', '.join(sorted(src))}", "high")

        # os.system or os.popen or subprocess.* with tainted args
        if func in ("os.system", "os.popen"):
            try:
                src = self.taint.get_taint_label(node)
                src |= self.taint.get_call_return_labels(node)
            except Exception:
                src = set()
            if src:
                self.add_issue(node.lineno, "Command Injection",
                               f"Tham số có thể bị taint: {', '.join(sorted(src))}", "high")

        # detect insecure yaml.load without explicit safe loader (basic)
        if func in ("yaml.load",):
            # if keywords include Loader and set to SafeLoader/FullLoader treat as less severe
            loader_is_safe = False
            for kw in getattr(node, "keywords", []):
                if kw.arg == "Loader":
                    # conservative: consider FullLoader and SafeLoader as acceptable
                    if isinstance(kw.value, ast.Attribute):
                        attr = self._attr_to_str(kw.value)
                        if attr.endswith("FullLoader") or attr.endswith("SafeLoader"):
                            loader_is_safe = True
                    if isinstance(kw.value, ast.Name):
                        if kw.value.id in ("FullLoader", "SafeLoader"):
                            loader_is_safe = True
            if not loader_is_safe:
                self.add_issue(node.lineno, "Insecure YAML",
                               "yaml.load được gọi mà không chỉ định Loader an toàn.", "medium")

        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == "pickle":
                self.add_issue(node.lineno, "Insecure Library",
                               "pickle có thể gây RCE.", "medium")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == "pickle":
            self.add_issue(node.lineno, "Insecure Library",
                           "pickle có thể gây RCE.", "medium")
        self.generic_visit(node)

    # --------------------------
    # UTIL
    # --------------------------

    def _get_call_name(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._attr_to_str(node.func)
        return None

    def _attr_to_str(self, node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))


# --------------------------
# REGEX ENGINE (improved)
# --------------------------

def collect_string_comment_spans(source):
    spans = []
    src_bytes = source.encode("utf-8")
    f = io.BytesIO(src_bytes)
    try:
        for tok in tokenize.tokenize(f.readline):
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                srow, scol = tok.start
                erow, ecol = tok.end
                lines = source.splitlines(keepends=True)
                start = sum(len(lines[i]) for i in range(srow - 1)) + scol
                end = sum(len(lines[i]) for i in range(erow - 1)) + ecol
                spans.append((start, end))
    except tokenize.TokenError:
        pass
    return spans


def in_spans(pos, spans):
    return any(start <= pos < end for start, end in spans)


def run_regex_rules(source, rules, filename):
    issues = []
    spans = collect_string_comment_spans(source)

    for rule in rules:
        pattern_str = rule.get("pattern")
        if not pattern_str:
            continue

        try:
            pattern = re.compile(pattern_str, re.MULTILINE)
        except Exception as e:
            issues.append({
                "file": filename,
                "lineno": 0,
                "type": "Invalid Regex",
                "severity": "low",
                "msg": f"Regex lỗi: {e}"
            })
            continue

        for m in pattern.finditer(source):
            if in_spans(m.start(), spans):
                continue

            lineno = source[:m.start()].count("\n") + 1
            issues.append({
                "file": filename,
                "lineno": lineno,
                "type": rule.get("type", "Regex Rule"),
                "severity": rule.get("severity", "medium"),
                "msg": rule.get("message", "")
            })

    return issues


# --------------------------
# MAIN ANALYSIS LOGIC
# --------------------------

def analyze_code(source, filename="<inline>", rules_path=None):
    issues = []
    rules = load_rules_from_file(rules_path)
    syntax_error = None

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        syntax_error = e
        issues.append({
            "file": filename,
            "lineno": e.lineno,
            "type": "SyntaxError",
            "severity": "high",
            "msg": str(e)
        })
        tree = None

    if tree:
        analyzer = Analyzer(filename, source, rules)
        analyzer.visit(tree)
        issues.extend(analyzer.issues)

        # ✅ Run Advanced AST Rules
        try:
            extra_ast = ast_rules.run_checks(tree, filename)
            issues.extend(extra_ast)
        except Exception:
            pass

    # always run regex rules
    issues.extend(run_regex_rules(source, rules, filename))

    # remove duplicates
    dedup = []
    seen = set()
    for i in issues:
        key = (i["file"], i["lineno"], i["type"], i["msg"])
        if key not in seen:
            seen.add(key)
            dedup.append(i)

    return {
        "issues": dedup,
        "summary": {
            "total": len(dedup),
            "syntax_error": bool(syntax_error)
        }
    }


def analyze_file(filepath, rules_path=None):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        return {"issues": [{"file": filepath, "lineno": 0, "type": "IOError", "severity": "high", "msg": str(e)}]}

    return analyze_code(source, filename=filepath, rules_path=rules_path)


def analyze_path(path, rules_path=None):
    all_issues = []
    if os.path.isfile(path):
        res = analyze_file(path, rules_path)
        all_issues.extend(res["issues"])
    else:
        for root, dirs, files in os.walk(path):
            if "__pycache__" in root or "venv" in root or ".git" in root:
                continue
            for f in files:
                if f.endswith(".py"):
                    res = analyze_file(os.path.join(root, f), rules_path)
                    all_issues.extend(res["issues"])

    # dedupe across whole project
    final = []
    seen = set()
    for i in all_issues:
        key = (i["file"], i["lineno"], i["type"], i["msg"])
        if key not in seen:
            seen.add(key)
            final.append(i)

    return {"issues": final, "summary": {"total": len(final)}}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python core.py <path> [rules.json]")
        exit(1)

    path = sys.argv[1]
    rules = sys.argv[2] if len(sys.argv) > 2 else "custom_rules.json"
    result = analyze_path(path, rules)
    print(json.dumps(result, indent=2, ensure_ascii=False))
