Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  PolicyGuard - Running Automated Test Suite" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

python -m pytest $args
