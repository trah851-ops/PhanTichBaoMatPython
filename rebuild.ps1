# rebuild.ps1 - Clean build script for PyScan Fuzzing (Windows)

Write-Host "🔧 PyScan Fuzzing - Clean Rebuild" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# Stop and remove existing containers
Write-Host "🛑 Stopping existing containers..." -ForegroundColor Yellow
docker-compose down 2>$null

# Remove existing images
Write-Host "🗑️  Removing old images..." -ForegroundColor Yellow
docker rmi pyscan_fuzzing 2>$null
docker rmi python_static_analyzer-fuzzing 2>$null
docker rmi python_static_analyzer_fuzzing 2>$null

# Clean Docker build cache
Write-Host "🧹 Cleaning Docker cache..." -ForegroundColor Yellow
docker builder prune -f

Write-Host ""
Write-Host "🔨 Building fuzzing service (no cache)..." -ForegroundColor Green
Write-Host ""

# Rebuild with no cache
docker-compose build --no-cache fuzzing

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Build successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  docker-compose up fuzzing     # Test fuzzing service"
    Write-Host "  docker-compose up             # Start all services"
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "❌ Build failed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check the error above. Common issues:" -ForegroundColor Yellow
    Write-Host "  1. Make sure requirements.txt is clean (no atheris-no-libfuzzer)"
    Write-Host "  2. Make sure Docker has internet access"
    Write-Host "  3. Try running: docker system prune -a"
    Write-Host ""
}