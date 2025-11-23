# analyzer/__init__.py
from .core import Analyzer
from .ast_rules import ASTLinter
from .taint import TaintAnalyzer

try:
    from .fuzzing import FuzzEngine, run_fuzz_on_analyzer, is_fuzzing_available
except ImportError:
    is_fuzzing_available = lambda: False
    run_fuzz_on_analyzer = None

try:
    from .rules import BUILTIN_RULES, get_rule
except ImportError:
    pass

__version__ = "2.0.0"
__all__ = ["Analyzer", "ASTLinter", "TaintAnalyzer"]