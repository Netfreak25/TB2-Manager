@echo off
setlocal
python "%~dp0tools\test_memory_suite.py" %*
set "RESULT=%ERRORLEVEL%"
echo.
pause
exit /b %RESULT%
