@echo off
setlocal
set "SDK=%~1"
if not defined SDK set /p "SDK=Path to Unleashed unlshd-092 SDK: "
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build.ps1" -FirmwareRoot "%SDK%" -Target Unleashed
if errorlevel 1 pause & exit /b 1
echo Unleashed build completed.
pause
