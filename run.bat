@echo off
rem Clipboard Guardian - one-click launcher (Windows)
rem Installs dependencies, makes sure the nimble model is pulled,
rem then starts the tray app without a console window.

setlocal
pushd "%~dp0"

echo [1/3] Checking Python...
python --version >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH. Install Python 3.9+ and try again.
    pause
    exit /b 1
)

echo [2/3] Installing dependencies...
python -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo Dependency install failed.
    pause
    exit /b 1
)

echo [3/3] Pulling the nimble model from Ollama (no-op if already present)...
where ollama >nul 2>nul
if errorlevel 1 (
    echo Ollama was not found. The tray app still starts, but the
    echo language-model layer stays off until Ollama is installed and
    echo "ollama pull nimble" succeeds.
) else (
    ollama pull nimble
)

start "" /min pythonw guardian.py
timeout /t 2 >nul
popd
endlocal
