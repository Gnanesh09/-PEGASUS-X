@echo off
cd /d "%~dp0\.."
if not exist .venv (
  py -3 -m venv .venv
)
call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if not exist .env copy .env.example .env
echo.
echo PEGASUS-X starting at http://127.0.0.1:8001
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload
pause
