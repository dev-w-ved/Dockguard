@echo off
setlocal

set "PYTHON=%PYTHON%"
if not defined PYTHON set "PYTHON=py -3"

%PYTHON% -m pip install -r requirements.txt
if errorlevel 1 exit /b %errorlevel%

if /I "%~1"=="server" (
    %PYTHON% -m uvicorn dockguard.web.app:app --host 127.0.0.1 --port 8080
    exit /b %errorlevel%
)

%PYTHON% -W error -m pytest -q
exit /b %errorlevel%
