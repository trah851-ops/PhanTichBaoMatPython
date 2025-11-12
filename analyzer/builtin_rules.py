import ast
from .rules_base import BaseRule

class RuleShadowBuiltin(BaseRule):
    id = "shadow-builtin"
    type = "Style"
    severity = "medium"

    def check_assign(self, node, engine):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in dir(__builtins__):
                engine.add_issue(node.lineno, self.type, self.severity,
                                 f"Shadowing builtin name `{t.id}`")

class RuleEvalExec(BaseRule):
    id = "dangerous-eval"
    type = "Security"
    severity = "high"

    def check_call(self, node, engine):
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            engine.add_issue(node.lineno, self.type, self.severity,
                             f"Dangerous call `{node.func.id}()`")

class RuleDangerousOS(BaseRule):
    id = "command-injection"
    type = "Security"
    severity = "high"

    def check_call(self, node, engine):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system":
                engine.add_issue(node.lineno, self.type, self.severity,
                                 "Possible command injection")

class RuleInsecurePickle(BaseRule):
    id = "pickle-rce"
    type = "Security"
    severity = "medium"

    def check_import(self, node, engine):
        for n in node.names:
            if n.name == "pickle":
                engine.add_issue(node.lineno, self.type, self.severity,
                                 "pickle can lead to RCE")

class RuleHardcodedPassword(BaseRule):
    id = "hardcoded-password"
    type = "Security"
    severity = "medium"

    def check_assign(self, node, engine):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            if "password" in node.targets[0].id.lower():
                engine.add_issue(node.lineno, self.type, self.severity,
                                 "Hardcoded password")
