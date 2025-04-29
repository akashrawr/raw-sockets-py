@echo off
echo Starting server...
start cmd /k "python rawrserver.py"

timeout /t 2 >nul
echo Starting client...
start cmd /k "python rawrclient.py"
