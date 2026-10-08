@echo off
setlocal
set "SDK=%~1"
if not defined SDK set /p "SDK=Path to Momentum mntm-012 SDK: "
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build.ps1" -FirmwareRoot "%SDK%" -Target Momentum
if errorlevel 1 pause & exit /b 1
echo Momentum build completed.
pause
