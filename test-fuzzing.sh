#!/bin/bash
# test-fuzzing.sh - Test Atheris Fuzzing Integration
# Renamed to avoid Windows filename issues

echo "========================================"
echo "🔥 Testing Atheris Fuzzing Integration"
echo "========================================"

# Create test vulnerable code
cat > /tmp/test-vuln.py << 'EOF'
import os
import pickle

def vulnerable_function(data: bytes):
    """Vulnerable function for testing"""
    if len(data) < 2:
        return
    
    # Trigger ZeroDivisionError
    if data[0] == 0x41 and data[1] == 0x42:  # 'A' 'B'
        x = 10 // 0  # Crash!
    
    # Command injection
    user_input = data.decode('utf-8', errors='ignore')
    if 'system' in user_input:
        os.system(f"echo {user_input}")
    
    # Code injection
    if 'eval' in user_input:
        eval(user_input)
    
    # Deserialization
    if 'pickle' in user_input:
        pickle.loads(b'fake')

def main():
    test_input = input("Enter test: ")
    vulnerable_function(test_input.encode())

if __name__ == "__main__":
    main()
EOF

echo ""
echo "📄 Test file created: /tmp/test-vuln.py"
echo ""

# Test 1: Check Atheris
echo "1️⃣ Checking Atheris installation..."
python3 -c "import atheris; print('✅ Atheris version:', atheris.__version__)" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✅ Atheris is installed!"
    ATHERIS_OK=1
else
    echo "❌ Atheris NOT installed"
    echo "   Installing..."
    pip install atheris
    ATHERIS_OK=$?
fi

echo ""

# Test 2: Check services
echo "2️⃣ Checking services..."

# Web service
if curl -s http://localhost:5000/ > /dev/null 2>&1; then
    echo "✅ Web service: http://localhost:5000"
    WEB_OK=1
else
    echo "❌ Web service not running"
    WEB_OK=0
fi

# Fuzzing service
if curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "✅ Fuzzing service: http://localhost:8001"
    
    # Check Atheris status
    STATUS=$(curl -s http://localhost:8001/health)
    ATHERIS_AVAIL=$(echo $STATUS | grep -o '"atheris_available":[^,}]*' | cut -d: -f2)
    
    if [ "$ATHERIS_AVAIL" = "true" ]; then
        echo "✅ Atheris: AVAILABLE"
    else
        echo "⚠️  Atheris: NOT AVAILABLE (pattern matching mode)"
    fi
    
    FUZZ_OK=1
else
    echo "❌ Fuzzing service not running"
    FUZZ_OK=0
fi

echo ""

# Test 3: Quick fuzzing test via API
if [ $FUZZ_OK -eq 1 ]; then
    echo "3️⃣ Running quick fuzzing test..."
    
    TEST_CODE='import os
def vuln(x):
    os.system(x)
    eval(x)'
    
    RESPONSE=$(curl -s -X POST http://localhost:8001/fuzz/start \
        -H "Content-Type: application/json" \
        -d "{\"code\": $(echo "$TEST_CODE" | python3 -c 'import sys, json; print(json.dumps(sys.stdin.read()))'), \"config\": {\"runs\": 100}}")
    
    JOB_ID=$(echo "$RESPONSE" | python3 -c 'import sys, json; print(json.loads(sys.stdin.read()).get("job_id", ""))' 2>/dev/null)
    
    if [ -n "$JOB_ID" ]; then
        echo "✅ Job started: $JOB_ID"
        echo "   Waiting for completion..."
        
        for i in {1..20}; do
            sleep 1
            STATUS=$(curl -s http://localhost:8001/fuzz/status/$JOB_ID)
            STATE=$(echo "$STATUS" | python3 -c 'import sys, json; print(json.loads(sys.stdin.read()).get("status", ""))' 2>/dev/null)
            
            echo -n "."
            
            if [ "$STATE" = "completed" ]; then
                echo ""
                echo "✅ Fuzzing completed!"
                
                RESULTS=$(curl -s http://localhost:8001/fuzz/results/$JOB_ID)
                VULNS=$(echo "$RESULTS" | python3 -c 'import sys, json; r=json.loads(sys.stdin.read()); print(len(r.get("results",{}).get("vulnerabilities",[])))' 2>/dev/null)
                
                echo "   Found $VULNS vulnerabilities"
                break
            fi
        done
    else
        echo "❌ Failed to start fuzzing job"
    fi
else
    echo "3️⃣ Skipping fuzzing test (service not available)"
fi

echo ""
echo "========================================"
echo "📊 Test Summary"
echo "========================================"

[ $WEB_OK -eq 1 ] && echo "✅ Web Service" || echo "❌ Web Service"
[ $FUZZ_OK -eq 1 ] && echo "✅ Fuzzing Service" || echo "❌ Fuzzing Service"
[ $ATHERIS_OK -eq 1 ] && echo "✅ Atheris" || echo "❌ Atheris"

echo ""

if [ $WEB_OK -eq 1 ] && [ $FUZZ_OK -eq 1 ]; then
    echo "✅ All systems operational!"
    echo ""
    echo "🌐 Access web UI: http://localhost:5000"
    echo "🔥 Test fuzzing tab and start fuzzing!"
else
    echo "⚠️  Some services not running"
    echo ""
    echo "To start services:"
    echo "  docker-compose up -d"
fi

echo ""
echo "Done! 🎉"