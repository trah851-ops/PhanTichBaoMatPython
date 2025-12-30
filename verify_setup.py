#!/usr/bin/env python3
"""
verify_setup.py - Cross-platform Setup Verification
Works on Windows, Linux, macOS
"""

import os
import sys
from pathlib import Path
import json

# Colors for terminal (works on Windows 10+)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_colored(text, color):
    """Print colored text"""
    print(f"{color}{text}{Colors.RESET}")

def print_header(text):
    """Print section header"""
    print("\n" + "=" * 60)
    print_colored(f"  {text}", Colors.BOLD + Colors.BLUE)
    print("=" * 60)

def check_file(filepath):
    """Check if file exists"""
    path = Path(filepath)
    exists = path.exists()
    
    status = f"{Colors.GREEN}✓{Colors.RESET}" if exists else f"{Colors.RED}✗{Colors.RESET}"
    print(f"{status} {filepath}")
    
    return exists

def check_file_content(filepath, keywords):
    """Check if file contains specific keywords"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        found = all(keyword in content for keyword in keywords)
        
        if found:
            print(f"  {Colors.GREEN}→ Contains required keywords{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}⚠ Missing some keywords{Colors.RESET}")
        
        return found
    except Exception as e:
        print(f"  {Colors.RED}! Error reading file: {e}{Colors.RESET}")
        return False

def main():
    print_header("🔍 PyScan Pro Setup Verification")
    
    # Check if in correct directory
    if not Path("web_app.py").exists():
        print_colored("\n❌ Error: Not in project root directory!", Colors.RED)
        print("   Please run from directory containing web_app.py")
        sys.exit(1)
    
    print_colored("\n✓ Running from project directory", Colors.GREEN)
    
    # 1. Check critical files
    print_header("1️⃣ Critical Files")
    
    critical_files = {
        "web_app.py": ["FUZZING_SERVICE_URL", "@app.route(\"/fuzz\""],
        "docker-compose.yml": ["pyscan-web", "fuzzing"],
        "Dockerfile.web": ["FROM python", "CMD"],
        "Dockerfile.fuzzing": ["atheris", "fuzzing_server.py"],
        "templates/index.html": ["Fuzzing", "runFuzzing"],
        "docker_fuzzing/atheris_real_fuzzer.py": ["RealAtherisFuzzer", "def fuzz_callback"],
        "docker_fuzzing/fuzzing_server.py": ["FuzzingJob", "@app.route"],
    }
    
    all_critical_ok = True
    for filepath, keywords in critical_files.items():
        if not check_file(filepath):
            all_critical_ok = False
            print(f"  {Colors.RED}→ MISSING - Create from artifacts!{Colors.RESET}")
        else:
            check_file_content(filepath, keywords)
    
    # 2. Check analyzer modules
    print_header("2️⃣ Analyzer Modules")
    
    analyzer_files = [
        "analyzer/__init__.py",
        "analyzer/core.py",
        "analyzer/ast_rules.py",
        "analyzer/taint.py",
        "analyzer/sca.py",
    ]
    
    analyzer_ok = all(check_file(f) for f in analyzer_files)
    
    # 3. Check optional files
    print_header("3️⃣ Optional Files")
    
    optional_files = [
        "analyzer/advanced_security.py",
        "analyzer/metrics.py",
        "analyzer/dataflow.py",
        "requirements.txt",
        "README.md",
    ]
    
    for filepath in optional_files:
        check_file(filepath)
    
    # 4. Check Docker
    print_header("4️⃣ Docker Check")
    
    try:
        import subprocess
        
        # Check docker
        result = subprocess.run(["docker", "--version"], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"{Colors.GREEN}✓{Colors.RESET} Docker: {result.stdout.strip()}")
            docker_ok = True
        else:
            print(f"{Colors.RED}✗{Colors.RESET} Docker not found")
            docker_ok = False
        
        # Check docker-compose
        result = subprocess.run(["docker-compose", "--version"], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"{Colors.GREEN}✓{Colors.RESET} Docker Compose: {result.stdout.strip()}")
            compose_ok = True
        else:
            print(f"{Colors.RED}✗{Colors.RESET} Docker Compose not found")
            compose_ok = False
    
    except Exception as e:
        print(f"{Colors.RED}✗{Colors.RESET} Error checking Docker: {e}")
        docker_ok = False
        compose_ok = False
    
    # 5. File size check
    print_header("5️⃣ File Size Verification")
    
    size_checks = {
        "docker_fuzzing/atheris_real_fuzzer.py": (10000, "Should be ~15KB - Main fuzzer"),
        "docker_fuzzing/fuzzing_server.py": (8000, "Should be ~12KB - API server"),
        "web_app.py": (5000, "Should be ~10KB - Web app"),
    }
    
    for filepath, (min_size, description) in size_checks.items():
        path = Path(filepath)
        if path.exists():
            size = path.stat().st_size
            if size >= min_size:
                print(f"{Colors.GREEN}✓{Colors.RESET} {filepath}: {size:,} bytes")
                print(f"  → {description}")
            else:
                print(f"{Colors.YELLOW}⚠{Colors.RESET} {filepath}: {size:,} bytes (might be incomplete)")
                print(f"  → {description}")
        else:
            print(f"{Colors.RED}✗{Colors.RESET} {filepath}: NOT FOUND")
    
    # Summary
    print_header("📊 Summary")
    
    checks = {
        "Critical Files": all_critical_ok,
        "Analyzer Modules": analyzer_ok,
        "Docker": docker_ok and compose_ok,
    }
    
    all_ok = all(checks.values())
    
    for check_name, status in checks.items():
        icon = f"{Colors.GREEN}✓{Colors.RESET}" if status else f"{Colors.RED}✗{Colors.RESET}"
        print(f"{icon} {check_name}")
    
    print("\n" + "=" * 60)
    
    if all_ok:
        print_colored("✅ ALL CHECKS PASSED!", Colors.GREEN)
        print("\n🚀 Ready to deploy!")
        print("\nNext steps:")
        print("  1. Build: docker-compose build")
        print("  2. Start: docker-compose up -d")
        print("  3. Test:  python verify_running.py")
    else:
        print_colored("❌ SOME CHECKS FAILED", Colors.RED)
        print("\n📝 Action items:")
        
        if not all_critical_ok:
            print(f"  {Colors.RED}→{Colors.RESET} Create missing critical files from artifacts")
        if not analyzer_ok:
            print(f"  {Colors.YELLOW}→{Colors.RESET} Add missing analyzer modules")
        if not (docker_ok and compose_ok):
            print(f"  {Colors.RED}→{Colors.RESET} Install Docker and Docker Compose")
        
        print("\n📚 See: QUICK_SETUP.md for detailed instructions")
    
    print("=" * 60)
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)