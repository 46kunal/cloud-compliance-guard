@echo off
echo ===================================================
echo   PolicyGuard - Running Automated Test Suite
echo ===================================================

python -m pytest %*
