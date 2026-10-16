@echo off
REM ===  CFD Migration Sanity  ===
REM Double-click this file to start the local server and open the app.
cd /d "%~dp0"
echo Starting CFD Migration Sanity...
python server.py
if errorlevel 1 (
  echo.
  echo Could not start with "python". Trying "py"...
  py server.py
)
echo.
echo Server stopped. Press any key to close.
pause >nul
