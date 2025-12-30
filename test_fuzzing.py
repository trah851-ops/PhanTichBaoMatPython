#!/usr/bin/env python3
"""
Test script để debug fuzzing
Chạy: python test_fuzzing.py
"""

import requests
import time
import json

FUZZING_SERVICE_URL = "http://localhost:8001"

test_code = """
import os

def vulnerable_function(user_input):
    # Vulnerable to command injection
    os.system(f"echo {user_input}")
    
    # Vulnerable to eval
    result = eval(user_input)
    
    return result

user_data = input("Enter command: ")
vulnerable_function(user_data)
"""

def test_health():
    """Test 1: Health check"""
    print("=" * 60)
    print("TEST 1: Health Check")
    print("=" * 60)
    
    try:
        response = requests.get(f"{FUZZING_SERVICE_URL}/health", timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ Health check PASSED")
            return True
        else:
            print("❌ Health check FAILED")
            return False
    
    except Exception as e:
        print(f"❌ Cannot connect to fuzzing service: {e}")
        print("\n💡 Make sure fuzzing service is running:")
        print("   docker-compose up -d fuzzing")
        print("   OR")
        print("   cd docker_fuzzing && python fuzzing_server.py")
        return False


def test_start_fuzzing():
    """Test 2: Start fuzzing job"""
    print("\n" + "=" * 60)
    print("TEST 2: Start Fuzzing Job")
    print("=" * 60)
    
    try:
        response = requests.post(
            f"{FUZZING_SERVICE_URL}/fuzz/start",
            json={
                "code": test_code,
                "runs": 100,
                "max_len": 4096,
                "timeout": 60
            },
            timeout=10
        )
        
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        if response.status_code == 200 and data.get('success'):
            print("✅ Job started successfully")
            return data.get('job_id')
        else:
            print("❌ Failed to start job")
            return None
    
    except Exception as e:
        print(f"❌ Error starting job: {e}")
        return None


def test_poll_status(job_id: str):
    """Test 3: Poll job status"""
    print("\n" + "=" * 60)
    print("TEST 3: Poll Job Status")
    print("=" * 60)
    
    max_polls = 60
    poll_count = 0
    
    while poll_count < max_polls:
        try:
            response = requests.get(
                f"{FUZZING_SERVICE_URL}/fuzz/status/{job_id}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"[Poll {poll_count + 1}] Status: {data.get('status')}, Progress: {data.get('progress')}")
                
                if data.get('status') == 'completed':
                    print("✅ Job completed")
                    return True
                
                elif data.get('status') in ['failed', 'stopped']:
                    print(f"❌ Job {data.get('status')}")
                    return False
            
            time.sleep(1)
            poll_count += 1
        
        except Exception as e:
            print(f"❌ Error polling status: {e}")
            return False
    
    print("❌ Timeout waiting for job completion")
    return False


def test_get_results(job_id: str):
    """Test 4: Get results"""
    print("\n" + "=" * 60)
    print("TEST 4: Get Results")
    print("=" * 60)
    
    try:
        response = requests.get(
            f"{FUZZING_SERVICE_URL}/fuzz/results/{job_id}",
            timeout=10
        )
        
        print(f"Status: {response.status_code}")
        data = response.json()
        
        if response.status_code == 200 and data.get('success'):
            results = data.get('results', {})
            
            print("\n📊 FUZZING RESULTS:")
            print(f"  Status: {results.get('status')}")
            print(f"  Total Crashes: {results.get('total_crashes', 0)}")
            
            vulns = results.get('vulnerabilities', [])
            print(f"  Vulnerabilities: {len(vulns)}")
            
            if vulns:
                print("\n🐛 Vulnerabilities Found:")
                for i, vuln in enumerate(vulns[:5], 1):  # Show first 5
                    print(f"    {i}. Line {vuln.get('line')}: {vuln.get('type')} ({vuln.get('severity')})")
                    print(f"       {vuln.get('message')}")
            
            stats = results.get('statistics', {})
            print(f"\n📈 Statistics:")
            print(f"  Runs: {stats.get('runs', 0)}")
            print(f"  Elapsed Time: {stats.get('elapsed_time', 0)}s")
            
            print("\n✅ Results retrieved successfully")
            return True
        else:
            print("❌ Failed to get results")
            print(f"Response: {json.dumps(data, indent=2)}")
            return False
    
    except Exception as e:
        print(f"❌ Error getting results: {e}")
        return False


def main():
    """Main test runner"""
    print("\n" + "=" * 60)
    print("🔥 PYSCAN FUZZING SERVICE TEST")
    print("=" * 60)
    
    # Test 1: Health
    if not test_health():
        print("\n❌ TEST FAILED: Cannot connect to fuzzing service")
        return
    
    # Test 2: Start job
    job_id = test_start_fuzzing()
    if not job_id:
        print("\n❌ TEST FAILED: Cannot start fuzzing job")
        return
    
    # Test 3: Poll status
    if not test_poll_status(job_id):
        print("\n❌ TEST FAILED: Job did not complete")
        return
    
    # Test 4: Get results
    if not test_get_results(job_id):
        print("\n❌ TEST FAILED: Cannot get results")
        return
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    main()