@echo off
setlocal
set "SDK=%~1"
if not defined SDK set /p "SDK=Path to Official firmware 1.4.3 SDK: "
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build.ps1" -FirmwareRoot "%SDK%" -Target Official
if errorlevel 1 pause & exit /b 1
echo Official firmware build completed.
pause
