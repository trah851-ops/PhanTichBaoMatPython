#!/usr/bin/env python3
"""
Test Fuzzing Service Directly
Run: python test_fuzzing_direct.py
"""

import requests
import json
import time

FUZZING_URL = "http://localhost:8001"

def test_fuzzing():
    """Test fuzzing service end-to-end"""
    
    print("="*60)
    print("🔥 Testing Fuzzing Service Directly")
    print("="*60)
    
    # 1. Health check
    print("\n1️⃣ Health Check...")
    try:
        resp = requests.get(f"{FUZZING_URL}/health", timeout=5)
        health = resp.json()
        print(f"✅ Status: {health['status']}")
        print(f"   Atheris: {health['atheris_available']}")
        print(f"   Mode: {health['mode']}")
        print(f"   Active jobs: {health['active_jobs']}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return
    
    # 2. Start fuzzing
    print("\n2️⃣ Starting Fuzzing Job...")
    
    test_code = """
import os

def vulnerable_function(user_input):
    # Command injection
    os.system(f"echo {user_input}")
    
    # Code injection  
    result = eval(user_input)
    
    return result

user_data = input("Enter: ")
vulnerable_function(user_data)
"""
    
    payload = {
        "code": test_code,
        "config": {
            "runs": 100,
            "timeout": 30
        }
    }
    
    try:
        resp = requests.post(
            f"{FUZZING_URL}/fuzz/start",
            json=payload,
            timeout=10
        )
        
        if resp.status_code != 200:
            print(f"❌ Failed to start: {resp.status_code}")
            print(resp.text)
            return
        
        result = resp.json()
        
        if not result.get('success'):
            print(f"❌ Start failed: {result}")
            return
        
        job_id = result['job_id']
        print(f"✅ Job started: {job_id}")
        print(f"   Mode: {result.get('mode')}")
        
    except Exception as e:
        print(f"❌ Start error: {e}")
        return
    
    # 3. Poll status
    print("\n3️⃣ Polling Status...")
    max_polls = 60
    
    for i in range(max_polls):
        time.sleep(1)
        
        try:
            resp = requests.get(
                f"{FUZZING_URL}/fuzz/status/{job_id}",
                timeout=5
            )
            
            if resp.status_code != 200:
                print(f"❌ Status check failed: {resp.status_code}")
                break
            
            status_data = resp.json()
            status = status_data.get('status')
            progress = status_data.get('progress', 0)
            
            print(f"   [{i+1}/{max_polls}] Status: {status}, Progress: {progress}%")
            
            if status == 'completed':
                print("✅ Job completed!")
                break
            
            elif status in ['failed', 'stopped']:
                print(f"❌ Job {status}")
                break
        
        except Exception as e:
            print(f"⚠️ Poll error: {e}")
            continue
    
    else:
        print(f"⏱️ Timeout after {max_polls}s")
        return
    
    # 4. Get results
    print("\n4️⃣ Getting Results...")
    
    try:
        resp = requests.get(
            f"{FUZZING_URL}/fuzz/results/{job_id}",
            timeout=10
        )
        
        if resp.status_code != 200:
            print(f"❌ Failed to get results: {resp.status_code}")
            print(resp.text)
            return
        
        results_data = resp.json()
        
        print("\n" + "="*60)
        print("📊 FUZZING RESULTS")
        print("="*60)
        
        # Pretty print full response
        print("\n🔍 Full Response:")
        print(json.dumps(results_data, indent=2))
        
        if not results_data.get('success'):
            print("\n❌ No results available")
            print(f"Response: {results_data}")
            return
        
        # Parse results
        results = results_data.get('results', {})
        
        print(f"\n📈 Statistics:")
        stats = results.get('statistics', {})
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        # Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        print(f"\n🛡️ Vulnerabilities: {len(vulns)}")
        
        if vulns:
            for i, vuln in enumerate(vulns[:5], 1):
                print(f"\n   {i}. Line {vuln.get('line', '?')}: {vuln.get('type', 'unknown')}")
                print(f"      Severity: {vuln.get('severity', 'unknown')}")
                print(f"      Function: {vuln.get('function', 'N/A')}")
                print(f"      Message: {vuln.get('message', 'N/A')}")
        
        # Entry points
        entry_points = results.get('entry_points', [])
        print(f"\n🔓 Entry Points: {len(entry_points)}")
        
        if entry_points:
            for i, ep in enumerate(entry_points[:3], 1):
                print(f"   {i}. {ep.get('type', 'unknown')}: {ep.get('function', 'N/A')} (line {ep.get('line', '?')})")
        
        # Risk score
        risk_score = results.get('statistics', {}).get('risk_score', 0)
        print(f"\n⚠️ Risk Score: {risk_score}/100")
        
        if risk_score >= 70:
            print("   🔴 HIGH RISK!")
        elif risk_score >= 40:
            print("   🟡 MEDIUM RISK")
        else:
            print("   🟢 LOW RISK")
        
        print("\n" + "="*60)
        print("✅ Test completed successfully!")
        print("="*60)
        
    except Exception as e:
        print(f"❌ Results error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        test_fuzzing()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()