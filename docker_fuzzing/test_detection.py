#!/usr/bin/env python3
"""
Quick test for vulnerability detection - LOCAL TEST
Run this to verify detection works WITHOUT Docker
"""

import sys
import os

print("=" * 70)
print("🔍 PyScan Detection Test - v1.0")
print("=" * 70)

# Test code with vulnerabilities
test_code = """
import os

def vulnerable_function(user_input):
    # Command injection
    os.system(f"echo {user_input}")
    
    # Code injection
    result = eval(user_input)
    
    return result

data = input("Enter: ")
vulnerable_function(data)
"""

print("\n📝 Test Code:")
print("-" * 70)
print(test_code)
print("-" * 70)

# Try importing the fuzzer
try:
    from atheris_real_fuzzer import SmartVulnerabilityDetector
    print("\n✅ Successfully imported SmartVulnerabilityDetector")
except ImportError as e:
    print(f"\n❌ Failed to import: {e}")
    print("Make sure atheris_real_fuzzer.py is in the same directory!")
    sys.exit(1)

# Run detection
print("\n🔍 Running vulnerability detection...")
detector = SmartVulnerabilityDetector()
results = detector.analyze_code_line_by_line(test_code)

# Display results
print("\n" + "=" * 70)
print("📊 DETECTION RESULTS")
print("=" * 70)

print(f"\n✅ Entry Points: {len(results['entry_points'])}")
for ep in results['entry_points']:
    print(f"  └─ Line {ep['line']}: {ep['type']}")

print(f"\n🚨 Vulnerabilities: {len(results['vulnerabilities'])}")
if results['vulnerabilities']:
    for vuln in results['vulnerabilities']:
        print(f"\n  ┌─ Line {vuln['line']}")
        print(f"  ├─ Type: {vuln['type']}")
        print(f"  ├─ Severity: {vuln['severity']}")
        print(f"  ├─ Message: {vuln['message']}")
        print(f"  └─ Code: {vuln['code']}")
else:
    print("  ❌ NO VULNERABILITIES DETECTED (THIS IS A BUG!)")

print(f"\n📈 Statistics:")
print(f"  ├─ Risk Score: {results['risk_score']}/100")
print(f"  ├─ Risk Level: {results['statistics'].get('risk_level', 'unknown')}")
print(f"  ├─ Critical: {results['statistics'].get('critical_count', 0)}")
print(f"  └─ High: {results['statistics'].get('high_count', 0)}")

print("\n" + "=" * 70)

# Verify expected results
expected_vulns = 2  # os.system + eval
if len(results['vulnerabilities']) >= expected_vulns:
    print("✅ TEST PASSED - Detection works correctly!")
else:
    print(f"❌ TEST FAILED - Expected {expected_vulns} vulnerabilities, found {len(results['vulnerabilities'])}")
    sys.exit(1)

print("=" * 70)