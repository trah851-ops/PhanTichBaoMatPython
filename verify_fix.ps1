# verify_fix.ps1 - Verify detection works in Docker

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  PyScan - Verify Detection Fix                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check if fuzzing service is running
Write-Host "🔍 Test 1: Checking fuzzing service..." -ForegroundColor Yellow

try {
    $health = Invoke-RestMethod -Uri "http://localhost:8001/health" -TimeoutSec 5
    
    Write-Host "  ✅ Service is running" -ForegroundColor Green
    Write-Host "  Version: $($health.version)" -ForegroundColor Gray
    Write-Host "  Detection mode: $($health.detection_mode)" -ForegroundColor Gray
    Write-Host "  Atheris: $($health.atheris_available)" -ForegroundColor Gray
    
    if ($health.detection_mode -ne "static_analysis_primary") {
        Write-Host "  ⚠️  Warning: Detection mode is not 'static_analysis_primary'" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ❌ Service not reachable!" -ForegroundColor Red
    Write-Host "  Make sure Docker is running: docker-compose up fuzzing" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Test 2: Send test code to fuzzing service
Write-Host "🔍 Test 2: Testing vulnerability detection..." -ForegroundColor Yellow

$testCode = @"
import os

def vulnerable_function(user_input):
    os.system(f"echo {user_input}")
    result = eval(user_input)
    return result
"@

Write-Host "  Sending test code..." -ForegroundColor Gray

try {
    # Create multipart form data
    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    
    $bodyLines = @(
        "--$boundary",
        "Content-Disposition: form-data; name=`"code`"",
        "",
        $testCode,
        "--$boundary",
        "Content-Disposition: form-data; name=`"runs`"",
        "",
        "100",
        "--$boundary--"
    ) -join $LF
    
    $headers = @{
        "Content-Type" = "multipart/form-data; boundary=$boundary"
    }
    
    # Start fuzzing job
    $startResponse = Invoke-RestMethod -Uri "http://localhost:8001/fuzz/start" -Method Post -Body $bodyLines -Headers $headers -TimeoutSec 10
    
    $jobId = $startResponse.job_id
    Write-Host "  ✅ Job started: $jobId" -ForegroundColor Green
    
    # Wait for completion
    Write-Host "  ⏳ Waiting for analysis..." -ForegroundColor Gray
    
    $maxWait = 30  # 30 seconds
    $waited = 0
    $completed = $false
    
    while ($waited -lt $maxWait) {
        Start-Sleep -Seconds 2
        $waited += 2
        
        try {
            $status = Invoke-RestMethod -Uri "http://localhost:8001/fuzz/status/$jobId" -TimeoutSec 5
            
            if ($status.status -eq "completed") {
                $completed = $true
                break
            }
            
            Write-Host "  ⏳ Progress: $($status.progress)%" -ForegroundColor Gray
        } catch {
            Write-Host "  ⚠️  Status check failed, retrying..." -ForegroundColor Yellow
        }
    }
    
    if (-not $completed) {
        Write-Host "  ⚠️  Timeout waiting for results" -ForegroundColor Yellow
        Write-Host "  Check logs: docker-compose logs fuzzing" -ForegroundColor Yellow
        exit 1
    }
    
    # Get results
    $results = Invoke-RestMethod -Uri "http://localhost:8001/fuzz/results/$jobId" -TimeoutSec 5
    
    Write-Host ""
    Write-Host "📊 RESULTS:" -ForegroundColor Cyan
    Write-Host "  Vulnerabilities: $($results.results.statistics.total_vulnerabilities)" -ForegroundColor White
    Write-Host "  Risk Score: $($results.results.statistics.risk_score)/100" -ForegroundColor White
    Write-Host "  Risk Level: $($results.results.statistics.risk_level)" -ForegroundColor White
    Write-Host ""
    
    # Check if detection works
    if ($results.results.statistics.total_vulnerabilities -ge 2) {
        Write-Host "✅ DETECTION WORKS!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Vulnerabilities found:" -ForegroundColor Green
        foreach ($vuln in $results.results.vulnerabilities) {
            Write-Host "  🚨 Line $($vuln.line): $($vuln.type) ($($vuln.severity))" -ForegroundColor Yellow
            Write-Host "     $($vuln.message)" -ForegroundColor Gray
        }
    } else {
        Write-Host "❌ DETECTION FAILED!" -ForegroundColor Red
        Write-Host "Expected: 2+ vulnerabilities" -ForegroundColor Red
        Write-Host "Found: $($results.results.statistics.total_vulnerabilities)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Debug info:" -ForegroundColor Yellow
        Write-Host "  Mode: $($results.results.statistics.mode)" -ForegroundColor Gray
        Write-Host "  Check logs: docker-compose logs fuzzing" -ForegroundColor Gray
        exit 1
    }
    
} catch {
    Write-Host "  ❌ Test failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ ALL TESTS PASSED!                                      ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""