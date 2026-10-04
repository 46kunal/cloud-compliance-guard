Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  PolicyGuard - Starting Local Web Dashboard" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Initializing database schema and seed data..." -ForegroundColor Yellow
python db/schema.py
python db/seed_data.py

Write-Host "`n[2/2] Launching Flask Dashboard on http://127.0.0.1:5000 ..." -ForegroundColor Green
python dashboard/app.py
