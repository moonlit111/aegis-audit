@echo off
rem ASCII-only wrapper (batch parsing is codepage-sensitive; all Chinese lives in run_all.py)
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv\Scripts\python.exe not found.
  echo         Run from the 04-* folder, or read the setup doc in this folder.
  goto :end
)
".venv\Scripts\python.exe" -X utf8 run_all.py
:end
if /i not "%~1"=="nopause" pause
