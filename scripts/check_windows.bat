@echo off
cd /d "%~dp0\.."
call .venv\Scripts\activate
python -c "import fastapi, langgraph; print('Core dependencies OK')"
pause
