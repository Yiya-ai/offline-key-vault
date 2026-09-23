@echo off
setlocal
cd /d "%~dp0"
python -I -S build_portable.py
set "result=%errorlevel%"
if not "%result%"=="0" echo Offline build failed. See the error above. No downloads are performed.
pause
exit /b %result%
