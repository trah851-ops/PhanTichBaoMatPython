# analyzer/taint.py
import ast

class AdvancedTaintEngine:
    """
    Advanced (but still lightweight) taint engine:
    - mark variables tainted
    - propagate through Assign, BinOp (concat), JoinedStr (f-string), Subscript (arr[0]), List/Tuple
    - record taint labels returned by functions (process_return)
    - provide labels for Call nodes via get_call_return_labels
    """

    def __init__(self):
        # varname -> set(labels)
        self.tainted_vars = {}
        # func_name -> set(labels) for returned values
        self.func_returns = {}

    # ---- helpers for marking/queries ----
    def mark(self, name, label="taint"):
        if not name:
            return
        self.tainted_vars.setdefault(name, set()).add(label)

    def is_tainted(self, name):
        return bool(self.tainted_vars.get(name))

    def get_var_labels(self, name):
        return set(self.tainted_vars.get(name, set()))

    # ---- compute taint labels for an AST node ----
    def get_taint_label(self, node):
        """
        Return a set of labels (possibly empty) indicating taint sources for this node.
        """
        if node is None:
            return set()

        # Name: variable lookup
        if isinstance(node, ast.Name):
            return set(self.get_var_labels(node.id))

        # Constant: safe
        if isinstance(node, ast.Constant):
            return set()

        # Formatted string f"...{x}..."
        if isinstance(node, ast.JoinedStr):
            labels = set()
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    labels |= self.get_taint_label(val.value)
                elif isinstance(val, ast.Constant):
                    pass
            return labels

        # BinOp (e.g. "rm -rf " + user) -> check both sides
        if isinstance(node, ast.BinOp):
            left = self.get_taint_label(node.left)
            right = self.get_taint_label(node.right)
            return left | right

        # Call: tainted if args are tainted OR call returns taint (if function known)
        if isinstance(node, ast.Call):
            labels = set()
            # direct taint sources (expandable)
            if isinstance(node.func, ast.Name) and node.func.id in ("input",):
                labels.add("input()")

            # common patterns: request.args.get, flask request — if attribute chain endswith 'args' treat as taint
            if isinstance(node.func, ast.Attribute):
                attr_chain = self._attr_to_str(node.func)
                if attr_chain.endswith(".args") or attr_chain.endswith(".GET") or ".get_param" in attr_chain:
                    labels.add(attr_chain)

            # include args/keywords
            for a in node.args:
                labels |= self.get_taint_label(a)
            for kw in getattr(node, "keywords", []):
                labels |= self.get_taint_label(kw.value)

            # include known function returns if function is local-known
            labels |= self.get_call_return_labels(node)
            return labels

        # Attribute: a.b -> check base a
        if isinstance(node, ast.Attribute):
            return self.get_taint_label(node.value)

        # List/Tuple/Set: check elements
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            labels = set()
            for e in node.elts:
                labels |= self.get_taint_label(e)
            return labels

        # Subscript: arr[0] -> check arr and slice
        if isinstance(node, ast.Subscript):
            labels = set()
            labels |= self.get_taint_label(node.value)
            # some ASTs put slice in different nodes
            slice_node = getattr(node, "slice", None)
            if slice_node is not None:
                labels |= self.get_taint_label(slice_node)
            return labels

        # Index wrapper (py<3.9) may exist
        if isinstance(node, ast.Index):
            return self.get_taint_label(node.value)

        # Fallback: unknown node types -> empty
        return set()

    def _attr_to_str(self, node):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    # ---- assignment processing ----
    def process_assign(self, node: ast.Assign):
        """
        Called from analyzer for assignments.
        - collects labels from right-hand side and marks each simple target name.
        """
        if node is None:
            return

        labels = self.get_taint_label(node.value)

        # If RHS is a call and that call returns taint via recorded function returns, they are included above.
        for target in node.targets:
            if isinstance(target, ast.Name):
                if labels:
                    for l in labels:
                        self.mark(target.id, l)
            elif isinstance(target, (ast.Tuple, ast.List)):
                # destructuring: assign same labels to names
                for elt in target.elts:
                    if isinstance(elt, ast.Name) and labels:
                        for l in labels:
                            self.mark(elt.id, l)
            # else: ignore complex targets for now

    # ---- return processing for functions ----
    def process_return(self, node: ast.Return, func_name: str = None):
        """
        Record taint labels for returns inside a function.
        Later when we see a call to that function (by name), get_call_return_labels will expose labels.
        """
        if node is None or func_name is None:
            return
        labels = self.get_taint_label(node.value)
        if labels:
            self.func_returns.setdefault(func_name, set()).update(labels)

    def function_return_labels(self, func_name: str):
        return set(self.func_returns.get(func_name, set()))

    # ---- call return resolution ----
    def get_call_return_labels(self, node: ast.Call):
        """
        If a Call is a simple name call (foo()), and foo has recorded return taint labels,
        return those labels. This allows tracking taint through functions when functions are defined in same module.
        """
        if isinstance(node.func, ast.Name):
            return self.function_return_labels(node.func.id)
        # For attribute-based calls (obj.method()), we don't track returns for now.
        return set()
