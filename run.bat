@echo off
REM Double-click to scan ips.txt, or drag any CSV/text file containing IPs onto this file.
cd /d "%~dp0"

REM First run after cloning: create local config files from the templates
if not exist vt_api_key.txt copy vt_api_key.example.txt vt_api_key.txt >nul
if not exist internal_ranges.txt copy internal_ranges.example.txt internal_ranges.txt >nul
if not exist ips.txt copy ips.example.txt ips.txt >nul
if not exist .venv (
    echo Setting up Python environment, first run only ...
    python -m venv .venv && ".venv\Scripts\pip" install -q -r requirements.txt
)

if "%~1"=="" (
    ".venv\Scripts\python.exe" vt_checker.py -i ips.txt
) else (
    ".venv\Scripts\python.exe" vt_checker.py -i "%~1"
)
pause
