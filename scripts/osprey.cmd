@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0osprey.ps1" %*
exit /b %errorlevel%
