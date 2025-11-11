@echo off
setlocal

set PYTHON_SCRIPT=app.py
set VENV_DIR=venv
set REQUIREMENTS=requirements.txt

if not exist "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv "%VENV_DIR%"
)

echo Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

echo Checking Python version...
python --version

echo Installing/upgrading pip...
python -m pip install --upgrade pip

if exist "%REQUIREMENTS%" (
    echo Installing dependencies from %REQUIREMENTS%...
    pip install -r "%REQUIREMENTS%"
) else (
    echo Warning: %REQUIREMENTS% not found!
)

echo Starting application...
python "%PYTHON_SCRIPT%"

pause