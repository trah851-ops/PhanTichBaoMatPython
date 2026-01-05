#!/usr/bin/env python3
"""
verify_running.py - Verify Running Services
Check if PyScan Pro services are operational
"""

import sys
import time
import json
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print("\n" + "=" * 60)
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print("=" * 60)

def check_url(url, timeout=5):
    """Check if URL is accessible"""
    try:
        req = Request(url)
        with urlopen(req, timeout=timeout) as response:
            return response.status == 200, response.read().decode('utf-8')
    except (URLError, HTTPError) as e:
        return False, str(e)

def main():
    print_header("🔍 PyScan Pro - Service Status Check")
    
    # Test 1: Web Service
    print("\n1️⃣ Testing Web Service...")
    web_ok, web_data = check_url("http://localhost:5000/")
    
    if web_ok:
        print(f"{Colors.GREEN}✅ Web Service: RUNNING{Colors.RESET}")
        print(f"   URL: http://localhost:5000")
    else:
        print(f"{Colors.RED}❌ Web Service: NOT RUNNING{Colors.RESET}")
        print(f"   Error: {web_data}")
    
    # Test 2: Fuzzing Service Health
    print("\n2️⃣ Testing Fuzzing Service...")
    fuzz_ok, fuzz_data = check_url("http://localhost:8001/health")
    
    if fuzz_ok:
        print(f"{Colors.GREEN}✅ Fuzzing Service: RUNNING{Colors.RESET}")
        print(f"   URL: http://localhost:8001")
        
        # Parse health data
        try:
            health = json.loads(fuzz_data)
            
            print(f"\n   📊 Service Info:")
            print(f"   → Version: {health.get('version', 'unknown')}")
            print(f"   → Mode: {health.get('mode', 'unknown')}")
            
            atheris_avail = health.get('atheris_available', False)
            if atheris_avail:
                print(f"   {Colors.GREEN}→ Atheris: AVAILABLE ✓{Colors.RESET}")
                print(f"      (Real coverage-guided fuzzing enabled)")
            else:
                print(f"   {Colors.YELLOW}→ Atheris: NOT AVAILABLE{Colors.RESET}")
                print(f"      (Using pattern matching fallback)")
            
            active_jobs = health.get('active_jobs', 0)
            print(f"   → Active Jobs: {active_jobs}")
        
        except json.JSONDecodeError:
            print(f"   {Colors.YELLOW}⚠ Could not parse health data{Colors.RESET}")
    else:
        print(f"{Colors.RED}❌ Fuzzing Service: NOT RUNNING{Colors.RESET}")
        print(f"   Error: {fuzz_data}")
    
    # Test 3: Quick Fuzzing Test
    if fuzz_ok:
        print("\n3️⃣ Running Quick Fuzzing Test...")
        
        test_code = """
import os
def vulnerable(x):
    os.system(x)
    eval(x)
"""
        
        try:
            # Send test fuzzing request
            data = json.dumps({
                "code": test_code,
                "config": {"runs": 50, "timeout": 10}
            }).encode('utf-8')
            
            req = Request(
                "http://localhost:8001/fuzz/start",
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            
            with urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                if result.get('success'):
                    job_id = result.get('job_id')
                    print(f"{Colors.GREEN}✓{Colors.RESET} Fuzzing job started: {job_id}")
                    
                    # Wait for completion
                    print("   Waiting for results", end="", flush=True)
                    
                    for _ in range(20):
                        time.sleep(1)
                        print(".", end="", flush=True)
                        
                        # Check status
                        status_ok, status_data = check_url(
                            f"http://localhost:8001/fuzz/status/{job_id}"
                        )
                        
                        if status_ok:
                            status = json.loads(status_data)
                            if status.get('status') == 'completed':
                                print(f" {Colors.GREEN}Done!{Colors.RESET}")
                                
                                # Get results
                                results_ok, results_data = check_url(
                                    f"http://localhost:8001/fuzz/results/{job_id}"
                                )
                                
                                if results_ok:
                                    results = json.loads(results_data)
                                    if results.get('success'):
                                        vulns = results.get('results', {}).get('vulnerabilities', [])
                                        stats = results.get('results', {}).get('statistics', {})
                                        
                                        print(f"\n   {Colors.GREEN}✓{Colors.RESET} Fuzzing completed!")
                                        print(f"   → Vulnerabilities found: {len(vulns)}")
                                        print(f"   → Risk score: {stats.get('risk_score', 0)}/100")
                                        
                                        if len(vulns) > 0:
                                            print(f"\n   {Colors.YELLOW}Sample vulnerabilities:{Colors.RESET}")
                                            for i, v in enumerate(vulns[:3], 1):
                                                print(f"   {i}. {v.get('type', 'unknown')} at line {v.get('line', 0)}")
                                    else:
                                        print(f"\n   {Colors.YELLOW}⚠ No results returned{Colors.RESET}")
                                
                                break
                    else:
                        print(f" {Colors.YELLOW}Timeout{Colors.RESET}")
                else:
                    print(f"{Colors.RED}✗{Colors.RESET} Failed to start fuzzing: {result.get('error')}")
        
        except Exception as e:
            print(f"\n   {Colors.RED}✗{Colors.RESET} Fuzzing test failed: {e}")
    else:
        print("\n3️⃣ Skipping fuzzing test (service not available)")
    
    # Summary
    print_header("📊 Overall Status")
    
    all_ok = web_ok and fuzz_ok
    
    if all_ok:
        print(f"\n{Colors.GREEN}✅ ALL SERVICES OPERATIONAL!{Colors.RESET}\n")
        print("🎉 PyScan Pro is ready to use!\n")
        print("🌐 Access web interface:")
        print(f"   → {Colors.BLUE}http://localhost:5000{Colors.RESET}\n")
        print("📖 Usage:")
        print("   1. Open web interface")
        print("   2. Go to 'Fuzzing' tab")
        print("   3. Paste vulnerable code")
        print("   4. Click 'Start Fuzzing'")
        print("   5. View results\n")
    else:
        print(f"\n{Colors.RED}❌ SOME SERVICES NOT RUNNING{Colors.RESET}\n")
        print("🔧 Troubleshooting:\n")
        
        if not web_ok:
            print(f"   {Colors.YELLOW}Web Service:{Colors.RESET}")
            print("   → Check if container is running: docker ps")
            print("   → Check logs: docker-compose logs pyscan-web")
            print("   → Restart: docker-compose restart pyscan-web\n")
        
        if not fuzz_ok:
            print(f"   {Colors.YELLOW}Fuzzing Service:{Colors.RESET}")
            print("   → Check if container is running: docker ps")
            print("   → Check logs: docker-compose logs fuzzing")
            print("   → Restart: docker-compose restart fuzzing\n")
        
        print("💡 Common fixes:")
        print("   → Rebuild: docker-compose build --no-cache")
        print("   → Restart all: docker-compose restart")
        print("   → Full reset: docker-compose down && docker-compose up -d\n")
    
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