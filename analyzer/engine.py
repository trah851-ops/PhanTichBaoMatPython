import ast

class Engine(ast.NodeVisitor):
    def __init__(self, filename, source, rules, taint_engine):
        self.filename = filename
        self.source = source.split("\n")
        self.rules = rules
        self.issues = []
        self.taint = taint_engine

    def add_issue(self, lineno, issue_type, severity, message):
        self.issues.append({
            "file": self.filename,
            "line": lineno,
            "type": issue_type,
            "severity": severity,
            "message": message
        })

    def visit_Assign(self, node):
        self.taint.track_assign(node)
        for rule in self.rules:
            if hasattr(rule, "check_assign"):
                rule.check_assign(node, self)
        self.generic_visit(node)

    def visit_Call(self, node):
        self.taint.track_call(node)
        for rule in self.rules:
            if hasattr(rule, "check_call"):
                rule.check_call(node, self)
        self.generic_visit(node)

    def visit_Import(self, node):
        for rule in self.rules:
            if hasattr(rule, "check_import"):
                rule.check_import(node, self)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for rule in self.rules:
            if hasattr(rule, "check_import_from"):
                rule.check_import_from(node, self)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.taint.track_function(node)
        for rule in self.rules:
            if hasattr(rule, "check_function"):
                rule.check_function(node, self)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        for rule in self.rules:
            if hasattr(rule, "check_class"):
                rule.check_class(node, self)
        self.generic_visit(node)

