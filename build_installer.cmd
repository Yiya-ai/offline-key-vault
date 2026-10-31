@echo off
setlocal
cd /d "%~dp0"
python -I -S build_portable.py
if errorlevel 1 exit /b 1
python -I -S build_installer.py
set "result=%errorlevel%"
pause
exit /b %result%
