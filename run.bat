@echo off
cd /d "%~dp0"
python -c "import numpy" 2>nul || python -m pip install --user numpy
python app.py
pause
