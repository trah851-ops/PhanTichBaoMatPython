# analyzer/__init__.py - V3.0.0 COMPLETE PACKAGE
"""
PyScan Pro - Advanced Python Security & Code Quality Analyzer

Features:
- AST-based static analysis
- Taint tracking & data flow analysis
- Code complexity metrics
- Fuzzing engine
- Dependency scanning
- Multi-format support (Python, Config, Docker, Shell, HTML, JS)
- CI/CD integration
"""

__version__ = "3.0.0"
__author__ = "PyScan Pro Team"

# Core analyzer
from .core import Analyzer

# Fuzzing
from .fuzzing import (
    fuzz_user_code, 
    fuzz_uploaded_file, 
    is_fuzzing_available,
    CodeFuzzer,
    ProjectFuzzer
)

# Advanced modules
try:
    from .metrics import (
        CodeComplexityAnalyzer,
        DuplicationDetector,
        PerformanceAnalyzer,
        analyze_code_metrics
    )
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

try:
    from .dataflow import (
        AdvancedDataFlowAnalyzer,
        analyze_data_flow
    )
    DATAFLOW_AVAILABLE = True
except ImportError:
    DATAFLOW_AVAILABLE = False

# Taint analysis
from .taint import TaintAnalyzer

# SCA
from .sca import DependencyScanner

# AST rules
from .ast_rules import ASTLinter, Severity

__all__ = [
    # Core
    "Analyzer",
    "__version__",
    
    # Fuzzing
    "fuzz_user_code",
    "fuzz_uploaded_file", 
    "is_fuzzing_available",
    "CodeFuzzer",
    "ProjectFuzzer",
    
    # Taint
    "TaintAnalyzer",
    
    # SCA
    "DependencyScanner",
    
    # AST
    "ASTLinter",
    "Severity",
    
    # Feature flags
    "METRICS_AVAILABLE",
    "DATAFLOW_AVAILABLE"
]

# Conditionally add advanced features
if METRICS_AVAILABLE:
    __all__.extend([
        "CodeComplexityAnalyzer",
        "DuplicationDetector",
        "PerformanceAnalyzer",
        "analyze_code_metrics"
    ])

if DATAFLOW_AVAILABLE:
    __all__.extend([
        "AdvancedDataFlowAnalyzer",
        "analyze_data_flow"
    ])


def get_version():
    """Get PyScan Pro version"""
    return __version__


def get_features():
    """Get available features"""
    return {
        "version": __version__,
        "core_analysis": True,
        "fuzzing": is_fuzzing_available(),
        "metrics": METRICS_AVAILABLE,
        "dataflow": DATAFLOW_AVAILABLE,
        "taint_analysis": True,
        "sca": True,
        "multi_format": True,
        "external_tools": True
    }


def print_banner():
    """Print PyScan Pro banner"""
    banner = f"""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗   ║
║   ██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║   ║
║   ██████╔╝ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║   ║
║   ██╔═══╝   ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║   ║
║   ██║        ██║   ███████║╚██████╗██║  ██║██║ ╚████║   ║
║   ╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ║
║                                                           ║
║              Advanced Security & Quality Analyzer         ║
║                     Version {__version__}                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    features = get_features()
    print("\n🎯 Available Features:")
    
    feature_icons = {
        "core_analysis": "✅ Core Analysis",
        "fuzzing": "🔥 Fuzzing Engine",
        "metrics": "📊 Code Metrics",
        "dataflow": "🔄 Data Flow Analysis",
        "taint_analysis": "🦠 Taint Tracking",
        "sca": "📦 Dependency Scanning",
        "multi_format": "📁 Multi-Format Support",
        "external_tools": "🔧 External Tools Integration"
    }
    
    for key, label in feature_icons.items():
        status = "✅" if features.get(key) else "❌"
        print(f"  {status} {label}")
    
    print("\n" + "="*63)


# Auto-print banner when imported in interactive mode
import sys
if hasattr(sys, 'ps1'):  # Interactive mode
    print_banner()