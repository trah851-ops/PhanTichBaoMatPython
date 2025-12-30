# quick_fix.ps1 - One-click fix for detection issue
# Run this after replacing the 3 files

param(
    [switch]$SkipTest = $false,
    [switch]$SkipRebuild = $false
)

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  PyScan - Quick Fix for Detection Issue                   ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check required files
Write-Host "📋 Checking files..." -ForegroundColor Yellow
$requiredFiles = @(
    "atheris_real_fuzzer.py",
    "fuzzing_server.py",
    "test_detection.py"
)

$missing = @()
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "  ✅ $file" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $file (MISSING)" -ForegroundColor Red
        $missing += $file
    }
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "❌ Missing files! Please add these files first:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "   - $_" }
    exit 1
}

Write-Host ""

# Step 1: Test locally
if (-not $SkipTest) {
    Write-Host "🔍 Step 1: Testing detection locally..." -ForegroundColor Cyan
    Write-Host ""
    
    python test_detection.py
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "❌ Local test FAILED!" -ForegroundColor Red
        Write-Host "Detection is not working. Please check the error above." -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "✅ Local test PASSED!" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "⏭️  Skipping local test..." -ForegroundColor Yellow
    Write-Host ""
}

# Step 2: Rebuild Docker
if (-not $SkipRebuild) {
    Write-Host "🔨 Step 2: Rebuilding Docker..." -ForegroundColor Cyan
    Write-Host ""
    
    # Stop containers
    Write-Host "  Stopping containers..." -ForegroundColor Yellow
    docker-compose down 2>$null
    
    # Remove old image
    Write-Host "  Removing old image..." -ForegroundColor Yellow
    docker rmi pyscan_fuzzing 2>$null
    docker rmi python_static_analyzer-fuzzing 2>$null
    
    # Clean cache
    Write-Host "  Cleaning cache..." -ForegroundColor Yellow
    docker builder prune -f 2>$null
    
    # Rebuild
    Write-Host ""
    Write-Host "  Building fuzzing service..." -ForegroundColor Green
    docker-compose build --no-cache fuzzing
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "❌ Docker build FAILED!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "✅ Docker build successful!" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "⏭️  Skipping Docker rebuild..." -ForegroundColor Yellow
    Write-Host ""
}

# Summary
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ FIX COMPLETED!                                         ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Start services:" -ForegroundColor White
Write-Host "     docker-compose up" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Open browser:" -ForegroundColor White
Write-Host "     http://localhost:5000" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Test with this code:" -ForegroundColor White
Write-Host "     import os" -ForegroundColor Gray
Write-Host "     def test(x):" -ForegroundColor Gray
Write-Host "         os.system(f'echo {x}')" -ForegroundColor Gray
Write-Host "         eval(x)" -ForegroundColor Gray
Write-Host ""
Write-Host "Expected result:" -ForegroundColor Cyan
Write-Host "  ✅ Vulnerabilities: 2" -ForegroundColor Green
Write-Host "  ✅ Risk Score: 60/100" -ForegroundColor Green
Write-Host ""