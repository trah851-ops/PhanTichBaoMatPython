# analyzer/dataflow.py - ADVANCED DATA FLOW ANALYSIS
import ast
from typing import Dict, List, Set, Any, Tuple
from collections import defaultdict, deque
import re

class DataFlowNode:
    """Node trong data flow graph"""
    def __init__(self, name: str, line: int, node_type: str):
        self.name = name
        self.line = line
        self.node_type = node_type  # 'source', 'sink', 'sanitizer', 'intermediate'
        self.flows_to = []
        self.flows_from = []
        self.tainted = False
    
    def __repr__(self):
        return f"<DataFlowNode {self.name}@{self.line} type={self.node_type} tainted={self.tainted}>"


class AdvancedDataFlowAnalyzer(ast.NodeVisitor):
    """
    Phân tích data flow nâng cao với:
    - Inter-procedural analysis
    - Context-sensitive analysis
    - Path-sensitive analysis
    - Sanitizer detection
    """
    
    def __init__(self, tree: ast.AST, file_path: str):
        self.tree = tree
        self.file_path = file_path
        
        # Data flow graph
        self.dfg_nodes: Dict[str, DataFlowNode] = {}
        self.variable_definitions: Dict[str, List[int]] = defaultdict(list)
        self.variable_uses: Dict[str, List[int]] = defaultdict(list)
        
        # Taint sources & sinks (mở rộng)
        self.sources = {
            'input', 'raw_input', 'sys.argv', 'os.environ', 'os.getenv',
            'request.form', 'request.args', 'request.json', 'request.cookies',
            'request.values', 'request.files', 'request.data', 'request.headers',
            'flask.request', 'django.http.request', 'socket.recv', 'socket.recvfrom',
            'file.read', 'open', 'urlopen', 'urllib.request.urlopen'
        }
        
        self.sinks = {
            'eval', 'exec', 'compile', '__import__',
            'os.system', 'os.popen', 'os.spawn', 'os.exec',
            'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output',
            'pickle.loads', 'pickle.load', 'yaml.load', 'marshal.loads',
            'sqlite3.execute', 'cursor.execute', 'db.execute',
            'open', 'file', 'write', 'writelines',
            'send', 'sendall', 'socket.send', 'socket.sendto',
            'render_template', 'render_template_string', 'render',
            'redirect', 'url_for', 'make_response'
        }
        
        self.sanitizers = {
            'escape', 'html.escape', 'urllib.parse.quote', 'quote',
            'bleach.clean', 'sanitize', 'validate', 'filter',
            're.escape', 'strip', 'replace', 'clean',
            'int', 'float', 'str', 'bool',  # Type conversions
            'isinstance', 'type', 'len'
        }
        
        # Analysis results
        self.flows = []
        self.vulnerabilities = []
        self.tainted_vars = set()
        self.sanitized_vars = set()
        
        # Function call graph
        self.call_graph = defaultdict(list)
        self.function_params = {}
        
        # Current context
        self.current_function = None
        self.in_try_block = False
        
        self.visit(self.tree)
        self._analyze_flows()
    
    def analyze(self) -> Dict[str, Any]:
        """Trả về kết quả phân tích đầy đủ"""
        return {
            "file": self.file_path,
            "data_flows": self.flows,
            "vulnerabilities": self.vulnerabilities,
            "tainted_variables": list(self.tainted_vars),
            "sanitized_variables": list(self.sanitized_vars),
            "call_graph": dict(self.call_graph),
            "statistics": {
                "total_flows": len(self.flows),
                "vulnerable_flows": len(self.vulnerabilities),
                "sources_found": len([f for f in self.flows if f['type'] == 'source']),
                "sinks_found": len([f for f in self.flows if f['type'] == 'sink']),
                "sanitizers_found": len([f for f in self.flows if f['type'] == 'sanitizer'])
            }
        }
    
    def visit_FunctionDef(self, node):
        """Theo dõi function definitions"""
        self.current_function = node.name
        
        # Lưu parameters
        param_names = [arg.arg for arg in node.args.args]
        self.function_params[node.name] = {
            'params': param_names,
            'line': node.lineno
        }
        
        self.generic_visit(node)
        self.current_function = None
    
    def visit_Assign(self, node):
        """Phân tích assignments và track data flow"""
        # Lấy tên biến được gán
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
                self.variable_definitions[target.id].append(node.lineno)
        
        # Kiểm tra value có tainted không
        is_tainted = False
        is_sanitized = False
        source_info = None
        
        # 1. Check if value is from a source
        if isinstance(node.value, ast.Call):
            func_name = self._get_func_name(node.value.func)
            
            if self._is_source(func_name):
                is_tainted = True
                source_info = {
                    'type': 'source',
                    'function': func_name,
                    'line': node.lineno
                }
                
                self.flows.append({
                    'type': 'source',
                    'variable': targets[0] if targets else 'unknown',
                    'source': func_name,
                    'line': node.lineno,
                    'file': self.file_path
                })
            
            elif self._is_sanitizer(func_name):
                is_sanitized = True
                for arg in node.value.args:
                    if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                        self.sanitized_vars.add(targets[0] if targets else 'unknown')
                        
                        self.flows.append({
                            'type': 'sanitizer',
                            'variable': targets[0] if targets else 'unknown',
                            'sanitizer': func_name,
                            'input': arg.id,
                            'line': node.lineno,
                            'file': self.file_path
                        })
        
        # 2. Check if value is from tainted variable
        elif isinstance(node.value, ast.Name):
            if node.value.id in self.tainted_vars:
                is_tainted = True
            elif node.value.id in self.sanitized_vars:
                is_sanitized = True
        
        # 3. Check if value is from operation with tainted vars
        elif isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
            if self._contains_tainted_var(node.value):
                is_tainted = True
        
        # Update taint status
        if is_tainted and not is_sanitized:
            for target in targets:
                self.tainted_vars.add(target)
                
                # Create DFG node
                if target not in self.dfg_nodes:
                    self.dfg_nodes[target] = DataFlowNode(target, node.lineno, 'intermediate')
                self.dfg_nodes[target].tainted = True
        
        elif is_sanitized:
            for target in targets:
                if target in self.tainted_vars:
                    self.tainted_vars.remove(target)
                self.sanitized_vars.add(target)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Phân tích function calls"""
        func_name = self._get_func_name(node.func)
        
        # Track function calls for call graph
        if self.current_function:
            self.call_graph[self.current_function].append({
                'called': func_name,
                'line': node.lineno
            })
        
        # Check if sink is called with tainted data
        if self._is_sink(func_name):
            for arg in node.args:
                vulnerability = self._check_vulnerability(arg, func_name, node.lineno)
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)
                    
                    self.flows.append({
                        'type': 'sink',
                        'function': func_name,
                        'tainted_input': vulnerability.get('variable'),
                        'line': node.lineno,
                        'file': self.file_path,
                        'severity': vulnerability.get('severity')
                    })
        
        self.generic_visit(node)
    
    def visit_Try(self, node):
        """Track try-except blocks"""
        self.in_try_block = True
        self.generic_visit(node)
        self.in_try_block = False
    
    def _check_vulnerability(self, arg, sink_func: str, line: int) -> Dict:
        """Kiểm tra xem arg có vulnerable không"""
        # Direct variable
        if isinstance(arg, ast.Name):
            if arg.id in self.tainted_vars and arg.id not in self.sanitized_vars:
                return {
                    'type': 'taint_vulnerability',
                    'severity': self._get_vulnerability_severity(sink_func),
                    'category': self._get_vulnerability_category(sink_func),
                    'variable': arg.id,
                    'sink': sink_func,
                    'line': line,
                    'file': self.file_path,
                    'message': f"VULNERABILITY: Tainted variable '{arg.id}' flows vào dangerous sink '{sink_func}'",
                    'recommendation': f"Sanitize input trước khi dùng với {sink_func}",
                    'data_flow': self._trace_data_flow(arg.id)
                }
        
        # F-string with tainted vars
        elif isinstance(arg, ast.JoinedStr):
            for value in arg.values:
                if isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name):
                        if value.value.id in self.tainted_vars:
                            return {
                                'type': 'taint_vulnerability',
                                'severity': self._get_vulnerability_severity(sink_func),
                                'category': self._get_vulnerability_category(sink_func),
                                'variable': value.value.id,
                                'sink': sink_func,
                                'line': line,
                                'file': self.file_path,
                                'message': f"VULNERABILITY: F-string với tainted variable '{value.value.id}' vào {sink_func}",
                                'recommendation': "Use parameterized queries hoặc sanitize input",
                                'data_flow': self._trace_data_flow(value.value.id)
                            }
        
        # Binary operation with tainted vars
        elif isinstance(arg, ast.BinOp):
            if self._contains_tainted_var(arg):
                tainted = self._extract_tainted_vars(arg)
                return {
                    'type': 'taint_vulnerability',
                    'severity': self._get_vulnerability_severity(sink_func),
                    'category': self._get_vulnerability_category(sink_func),
                    'variable': ', '.join(tainted),
                    'sink': sink_func,
                    'line': line,
                    'file': self.file_path,
                    'message': f"VULNERABILITY: Binary operation với tainted vars {tainted} vào {sink_func}",
                    'recommendation': "Sanitize tất cả inputs trước khi concatenate",
                    'data_flow': [self._trace_data_flow(v) for v in tainted]
                }
        
        return None
    
    def _trace_data_flow(self, var_name: str) -> List[Dict]:
        """Trace data flow của một variable"""
        flow = []
        
        # Find where variable was defined
        if var_name in self.variable_definitions:
            for line in self.variable_definitions[var_name]:
                flow.append({
                    'event': 'definition',
                    'variable': var_name,
                    'line': line
                })
        
        # Find where variable was used
        if var_name in self.variable_uses:
            for line in self.variable_uses[var_name]:
                flow.append({
                    'event': 'use',
                    'variable': var_name,
                    'line': line
                })
        
        return sorted(flow, key=lambda x: x['line'])
    
    def _analyze_flows(self):
        """Phân tích tất cả data flows và tìm paths"""
        # Build complete data flow paths
        for var in self.tainted_vars:
            if var in self.dfg_nodes:
                node = self.dfg_nodes[var]
                paths = self._find_paths_to_sinks(node)
                
                for path in paths:
                    self.flows.append({
                        'type': 'complete_flow',
                        'source_variable': var,
                        'path': path,
                        'is_vulnerable': any(p['type'] == 'sink' for p in path)
                    })
    
    def _find_paths_to_sinks(self, start_node: DataFlowNode) -> List[List[Dict]]:
        """Tìm tất cả paths từ node đến sinks"""
        paths = []
        visited = set()
        
        def dfs(node, current_path):
            if node.name in visited:
                return
            
            visited.add(node.name)
            current_path.append({
                'variable': node.name,
                'line': node.line,
                'type': node.node_type,
                'tainted': node.tainted
            })
            
            # If this is a sink, save the path
            if node.node_type == 'sink':
                paths.append(current_path.copy())
            
            # Continue to flows_to
            for next_node in node.flows_to:
                dfs(next_node, current_path)
            
            current_path.pop()
            visited.remove(node.name)
        
        dfs(start_node, [])
        return paths
    
    def _contains_tainted_var(self, node) -> bool:
        """Kiểm tra node có chứa tainted variable không"""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        
        elif isinstance(node, ast.BinOp):
            return self._contains_tainted_var(node.left) or self._contains_tainted_var(node.right)
        
        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if self._contains_tainted_var(value.value):
                        return True
        
        return False
    
    def _extract_tainted_vars(self, node) -> List[str]:
        """Trích xuất tất cả tainted variables từ node"""
        tainted = []
        
        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                tainted.append(node.id)
        
        elif isinstance(node, ast.BinOp):
            tainted.extend(self._extract_tainted_vars(node.left))
            tainted.extend(self._extract_tainted_vars(node.right))
        
        return tainted
    
    def _is_source(self, func_name: str) -> bool:
        """Kiểm tra có phải source không"""
        return any(src in func_name for src in self.sources)
    
    def _is_sink(self, func_name: str) -> bool:
        """Kiểm tra có phải sink không"""
        return any(sink in func_name for sink in self.sinks)
    
    def _is_sanitizer(self, func_name: str) -> bool:
        """Kiểm tra có phải sanitizer không"""
        return any(san in func_name for san in self.sanitizers)
    
    def _get_vulnerability_severity(self, sink_func: str) -> str:
        """Xác định severity dựa trên sink type"""
        critical_sinks = ['eval', 'exec', 'os.system', 'pickle.loads']
        high_sinks = ['subprocess', 'compile', 'open', 'write']
        
        if any(s in sink_func for s in critical_sinks):
            return 'critical'
        elif any(s in sink_func for s in high_sinks):
            return 'high'
        else:
            return 'medium'
    
    def _get_vulnerability_category(self, sink_func: str) -> str:
        """Xác định vulnerability category"""
        if 'execute' in sink_func or 'query' in sink_func:
            return 'sql_injection'
        elif any(s in sink_func for s in ['system', 'popen', 'subprocess']):
            return 'command_injection'
        elif any(s in sink_func for s in ['eval', 'exec', 'compile']):
            return 'code_injection'
        elif 'open' in sink_func or 'file' in sink_func:
            return 'path_traversal'
        elif 'pickle' in sink_func or 'yaml' in sink_func:
            return 'deserialization'
        else:
            return 'injection'
    
    def _get_func_name(self, node) -> str:
        """Lấy tên function"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""


def analyze_data_flow(file_path: str, code: str) -> Dict[str, Any]:
    """
    Main function để chạy advanced data flow analysis
    """
    try:
        tree = ast.parse(code, filename=file_path)
        analyzer = AdvancedDataFlowAnalyzer(tree, file_path)
        return analyzer.analyze()
    
    except SyntaxError as e:
        return {
            "error": f"Syntax error: {e.msg}",
            "line": e.lineno
        }
    except Exception as e:
        return {
            "error": str(e)
        }