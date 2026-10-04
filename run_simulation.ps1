Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  PolicyGuard - Running Violation Simulator Demo" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

python demo/simulate_violation.py --save $args
