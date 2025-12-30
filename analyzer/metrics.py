# analyzer/metrics.py - ADVANCED CODE QUALITY METRICS
import ast
import re
from typing import Dict, List, Any
from collections import defaultdict
import math

class CodeComplexityAnalyzer(ast.NodeVisitor):
    """
    Phân tích độ phức tạp code theo nhiều metrics:
    - Cyclomatic Complexity
    - Cognitive Complexity
    - Halstead Metrics
    - Maintainability Index
    """
    
    def __init__(self, tree: ast.AST, code: str, file_path: str):
        self.tree = tree
        self.code = code
        self.file_path = file_path
        self.lines = code.split('\n')
        
        # Metrics
        self.cyclomatic = 1  # Bắt đầu từ 1
        self.cognitive = 0
        self.nesting_level = 0
        self.max_nesting = 0
        
        # Halstead metrics
        self.operators = []
        self.operands = []
        
        # Function metrics
        self.functions = {}
        self.current_function = None
        
        # Code smells
        self.smells = []
        
        self.visit(self.tree)
    
    def analyze(self) -> Dict[str, Any]:
        """Chạy tất cả các phân tích"""
        return {
            "file": self.file_path,
            "complexity": {
                "cyclomatic": self.cyclomatic,
                "cognitive": self.cognitive,
                "max_nesting": self.max_nesting,
                "halstead": self._calculate_halstead(),
                "maintainability_index": self._calculate_maintainability_index()
            },
            "functions": self.functions,
            "code_smells": self.smells,
            "loc": {
                "total": len(self.lines),
                "code": self._count_code_lines(),
                "comments": self._count_comment_lines(),
                "blank": self._count_blank_lines()
            },
            "recommendations": self._generate_recommendations()
        }
    
    def visit_FunctionDef(self, node):
        """Phân tích từng function"""
        self.current_function = node.name
        
        func_complexity = self._calculate_function_complexity(node)
        func_loc = len(node.body)
        
        self.functions[node.name] = {
            "line": node.lineno,
            "complexity": func_complexity,
            "loc": func_loc,
            "parameters": len(node.args.args),
            "returns": self._count_returns(node),
            "docstring": ast.get_docstring(node) is not None
        }
        
        # Check for code smells
        if func_complexity > 10:
            self.smells.append({
                "type": "high_complexity",
                "severity": "high",
                "function": node.name,
                "line": node.lineno,
                "message": f"Function '{node.name}' có độ phức tạp cao ({func_complexity})",
                "recommendation": "Refactor thành các function nhỏ hơn"
            })
        
        if func_loc > 50:
            self.smells.append({
                "type": "long_function",
                "severity": "medium",
                "function": node.name,
                "line": node.lineno,
                "message": f"Function '{node.name}' quá dài ({func_loc} lines)",
                "recommendation": "Chia nhỏ function thành các sub-functions"
            })
        
        if len(node.args.args) > 5:
            self.smells.append({
                "type": "too_many_parameters",
                "severity": "medium",
                "function": node.name,
                "line": node.lineno,
                "message": f"Function '{node.name}' có quá nhiều parameters ({len(node.args.args)})",
                "recommendation": "Nhóm parameters vào object/dict"
            })
        
        self.generic_visit(node)
        self.current_function = None
    
    def visit_If(self, node):
        """Tăng complexity cho if statements"""
        self.cyclomatic += 1
        self.cognitive += 1 + self.nesting_level
        
        self.nesting_level += 1
        self.max_nesting = max(self.max_nesting, self.nesting_level)
        
        self.generic_visit(node)
        
        self.nesting_level -= 1
    
    def visit_For(self, node):
        """Tăng complexity cho loops"""
        self.cyclomatic += 1
        self.cognitive += 1 + self.nesting_level
        
        self.nesting_level += 1
        self.max_nesting = max(self.max_nesting, self.nesting_level)
        
        self.generic_visit(node)
        
        self.nesting_level -= 1
    
    def visit_While(self, node):
        """Tăng complexity cho while loops"""
        self.cyclomatic += 1
        self.cognitive += 1 + self.nesting_level
        
        self.nesting_level += 1
        self.max_nesting = max(self.max_nesting, self.nesting_level)
        
        self.generic_visit(node)
        
        self.nesting_level -= 1
    
    def visit_ExceptHandler(self, node):
        """Tăng complexity cho exception handlers"""
        self.cyclomatic += 1
        self.generic_visit(node)
    
    def visit_BoolOp(self, node):
        """Tăng complexity cho boolean operators"""
        self.cyclomatic += len(node.values) - 1
        self.generic_visit(node)
    
    def _calculate_function_complexity(self, node) -> int:
        """Tính cyclomatic complexity của một function"""
        complexity = 1
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        
        return complexity
    
    def _count_returns(self, node) -> int:
        """Đếm số return statements"""
        count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                count += 1
        return count
    
    def _calculate_halstead(self) -> Dict[str, float]:
        """Tính Halstead Metrics"""
        # Đếm operators và operands từ code
        operators_set = set()
        operands_set = set()
        
        operator_pattern = r'[\+\-\*\/\%\=\<\>\!\&\|\^]+'
        operand_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        
        for line in self.lines:
            operators_set.update(re.findall(operator_pattern, line))
            operands_set.update(re.findall(operand_pattern, line))
        
        n1 = len(operators_set)  # Unique operators
        n2 = len(operands_set)   # Unique operands
        N1 = sum(self.code.count(op) for op in operators_set)  # Total operators
        N2 = sum(self.code.count(op) for op in operands_set)   # Total operands
        
        if n1 == 0 or n2 == 0:
            return {"vocabulary": 0, "length": 0, "volume": 0, "difficulty": 0, "effort": 0}
        
        vocabulary = n1 + n2
        length = N1 + N2
        volume = length * math.log2(vocabulary) if vocabulary > 0 else 0
        difficulty = (n1 / 2) * (N2 / n2) if n2 > 0 else 0
        effort = volume * difficulty
        
        return {
            "vocabulary": vocabulary,
            "length": length,
            "volume": round(volume, 2),
            "difficulty": round(difficulty, 2),
            "effort": round(effort, 2)
        }
    
    def _calculate_maintainability_index(self) -> float:
        """
        Tính Maintainability Index
        MI = 171 - 5.2 * ln(V) - 0.23 * G - 16.2 * ln(LOC)
        V = Halstead Volume
        G = Cyclomatic Complexity
        LOC = Lines of Code
        """
        halstead = self._calculate_halstead()
        volume = halstead.get("volume", 0)
        loc = self._count_code_lines()
        
        if volume <= 0 or loc <= 0:
            return 100.0
        
        try:
            mi = 171 - 5.2 * math.log(volume) - 0.23 * self.cyclomatic - 16.2 * math.log(loc)
            mi = max(0, min(100, mi))  # Clamp giữa 0-100
            return round(mi, 2)
        except:
            return 100.0
    
    def _count_code_lines(self) -> int:
        """Đếm số dòng code thực sự (không tính comment và blank)"""
        count = 0
        in_multiline_comment = False
        
        for line in self.lines:
            stripped = line.strip()
            
            # Check multiline comments
            if '"""' in stripped or "'''" in stripped:
                in_multiline_comment = not in_multiline_comment
                continue
            
            if in_multiline_comment:
                continue
            
            # Skip empty lines and comments
            if stripped and not stripped.startswith('#'):
                count += 1
        
        return count
    
    def _count_comment_lines(self) -> int:
        """Đếm số dòng comment"""
        count = 0
        in_multiline = False
        
        for line in self.lines:
            stripped = line.strip()
            
            if '"""' in stripped or "'''" in stripped:
                in_multiline = not in_multiline
                count += 1
                continue
            
            if in_multiline or stripped.startswith('#'):
                count += 1
        
        return count
    
    def _count_blank_lines(self) -> int:
        """Đếm số dòng trống"""
        return sum(1 for line in self.lines if not line.strip())
    
    def _generate_recommendations(self) -> List[str]:
        """Tạo recommendations dựa trên metrics"""
        recommendations = []
        
        if self.cyclomatic > 20:
            recommendations.append("🔴 CRITICAL: Cyclomatic complexity quá cao. Refactor code ngay!")
        elif self.cyclomatic > 10:
            recommendations.append("⚠️  WARNING: Cyclomatic complexity cao. Nên refactor.")
        
        if self.cognitive > 15:
            recommendations.append("🔴 CRITICAL: Cognitive complexity quá cao. Code khó hiểu!")
        
        if self.max_nesting > 4:
            recommendations.append("⚠️  WARNING: Nesting level quá sâu. Flatten code structure.")
        
        mi = self._calculate_maintainability_index()
        if mi < 20:
            recommendations.append("🔴 CRITICAL: Maintainability Index rất thấp. Code khó maintain!")
        elif mi < 50:
            recommendations.append("⚠️  WARNING: Maintainability Index thấp.")
        
        if len(self.functions) > 20:
            recommendations.append("ℹ️  INFO: File có nhiều functions. Cân nhắc split thành modules.")
        
        return recommendations


class DuplicationDetector:
    """Phát hiện code trùng lặp"""
    
    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
    
    def find_duplicates(self, min_lines: int = 3) -> List[Dict]:
        """Tìm các đoạn code trùng lặp"""
        duplicates = []
        
        # Simple hash-based detection
        line_hashes = {}
        
        for i, line in enumerate(self.lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            
            if stripped not in line_hashes:
                line_hashes[stripped] = []
            line_hashes[stripped].append(i + 1)
        
        # Find duplicates
        for line_text, line_numbers in line_hashes.items():
            if len(line_numbers) >= 2 and len(line_text) > 20:
                duplicates.append({
                    "type": "duplicate_line",
                    "severity": "low",
                    "lines": line_numbers,
                    "text": line_text[:50] + "..." if len(line_text) > 50 else line_text,
                    "count": len(line_numbers)
                })
        
        return duplicates


class PerformanceAnalyzer(ast.NodeVisitor):
    """Phân tích performance issues"""
    
    def __init__(self, tree: ast.AST, file_path: str):
        self.tree = tree
        self.file_path = file_path
        self.issues = []
        self.visit(self.tree)
    
    def analyze(self) -> List[Dict]:
        """Trả về performance issues"""
        return self.issues
    
    def visit_For(self, node):
        """Phát hiện nested loops"""
        # Check for nested loops
        for child in ast.walk(node):
            if child != node and isinstance(child, (ast.For, ast.While)):
                self.issues.append({
                    "type": "performance",
                    "category": "nested_loop",
                    "severity": "medium",
                    "line": node.lineno,
                    "file": self.file_path,
                    "message": "Nested loop phát hiện - có thể gây performance issue",
                    "recommendation": "Xem xét tối ưu thuật toán hoặc dùng list comprehension"
                })
                break
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Phát hiện các function calls có thể chậm"""
        func_name = self._get_func_name(node.func)
        
        # Check for expensive operations
        expensive_ops = {
            'sleep': "Sử dụng sleep() - blocking operation",
            'time.sleep': "Sử dụng time.sleep() - blocking operation",
            'requests.get': "Synchronous HTTP request - nên dùng async",
            'requests.post': "Synchronous HTTP request - nên dùng async",
        }
        
        for op, message in expensive_ops.items():
            if op in func_name:
                self.issues.append({
                    "type": "performance",
                    "category": "blocking_call",
                    "severity": "medium",
                    "line": node.lineno,
                    "file": self.file_path,
                    "message": message,
                    "recommendation": "Cân nhắc dùng async/await hoặc threading"
                })
        
        self.generic_visit(node)
    
    def _get_func_name(self, node) -> str:
        """Lấy tên function"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_func_name(node.value) + '.' + node.attr
        return ""


def analyze_code_metrics(file_path: str, code: str) -> Dict[str, Any]:
    """
    Hàm main để chạy tất cả metric analysis
    """
    try:
        tree = ast.parse(code, filename=file_path)
        
        # Run all analyzers
        complexity_analyzer = CodeComplexityAnalyzer(tree, code, file_path)
        complexity_results = complexity_analyzer.analyze()
        
        duplication_detector = DuplicationDetector(code)
        duplicates = duplication_detector.find_duplicates()
        
        performance_analyzer = PerformanceAnalyzer(tree, file_path)
        performance_issues = performance_analyzer.analyze()
        
        return {
            "metrics": complexity_results,
            "duplicates": duplicates,
            "performance": performance_issues,
            "summary": {
                "quality_score": _calculate_quality_score(complexity_results),
                "risk_level": _assess_risk_level(complexity_results)
            }
        }
    
    except SyntaxError as e:
        return {
            "error": f"Syntax error: {e.msg}",
            "line": e.lineno
        }
    except Exception as e:
        return {
            "error": str(e)
        }


def _calculate_quality_score(metrics: Dict) -> float:
    """
    Tính quality score từ 0-100
    Cao = tốt, thấp = xấu
    """
    score = 100.0
    
    complexity = metrics.get("complexity", {})
    
    # Cyclomatic complexity penalty
    cyclomatic = complexity.get("cyclomatic", 0)
    if cyclomatic > 20:
        score -= 30
    elif cyclomatic > 10:
        score -= 15
    
    # Cognitive complexity penalty
    cognitive = complexity.get("cognitive", 0)
    if cognitive > 15:
        score -= 20
    elif cognitive > 10:
        score -= 10
    
    # Maintainability bonus
    mi = complexity.get("maintainability_index", 100)
    score = score * (mi / 100)
    
    # Code smells penalty
    smells = len(metrics.get("code_smells", []))
    score -= smells * 5
    
    return max(0, min(100, round(score, 2)))


def _assess_risk_level(metrics: Dict) -> str:
    """Đánh giá risk level của code"""
    complexity = metrics.get("complexity", {})
    cyclomatic = complexity.get("cyclomatic", 0)
    mi = complexity.get("maintainability_index", 100)
    smells = len(metrics.get("code_smells", []))
    
    if cyclomatic > 20 or mi < 20 or smells > 10:
        return "🔴 HIGH RISK"
    elif cyclomatic > 10 or mi < 50 or smells > 5:
        return "⚠️  MEDIUM RISK"
    else:
        return "✅ LOW RISK" 