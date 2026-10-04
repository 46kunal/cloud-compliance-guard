@echo off
echo ===================================================
echo   PolicyGuard - Starting Local Web Dashboard
echo ===================================================

echo [1/2] Checking & initializing database...
python db/schema.py
python db/seed_data.py

echo [2/2] Launching Flask Server on http://127.0.0.1:5000 ...
python dashboard/app.py
