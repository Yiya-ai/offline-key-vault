@echo off
setlocal
cd /d "%~dp0"
python -I -S launch.py
if errorlevel 1 (
  echo Application could not start. Requires Python 3.12 and dependencies listed in requirements.txt locally.
  pause
)
