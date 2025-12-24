@echo off
setlocal

REM NeacSafe64 Driver Service Installer
REM Run as Administrator

set DRIVER_NAME=NeacSafe64
set DRIVER_PATH=%~dp0NeacSafe64.sys

echo ============================================
echo   NeacSafe64 Driver Service Installer
echo ============================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script requires Administrator privileges.
    echo [!] Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Check if driver file exists
if not exist "%DRIVER_PATH%" (
    echo [!] Driver file not found: %DRIVER_PATH%
    echo [!] Make sure NeacSafe64.sys is in the same directory as this script
    pause
    exit /b 1
)

echo [*] Driver path: %DRIVER_PATH%
echo.

REM Check if service already exists
sc query %DRIVER_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Service already exists, stopping and deleting...
    sc stop %DRIVER_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %DRIVER_NAME%
    timeout /t 1 /nobreak >nul
)

REM Create the service
echo [*] Creating service...
sc create %DRIVER_NAME% type= kernel start= demand binPath= "%DRIVER_PATH%" DisplayName= "NeacSafe64 Driver"

if %errorlevel% neq 0 (
    echo [!] Failed to create service (Error: %errorlevel%)
    pause
    exit /b 1
)

echo [+] Service created successfully!
echo.
echo [*] To start the driver:  sc start %DRIVER_NAME%
echo [*] To stop the driver:   sc stop %DRIVER_NAME%
echo [*] To remove the driver: sc delete %DRIVER_NAME%
echo.

REM Optionally start the service
set /p START_NOW="Start the driver now? (y/n): "
if /i "%START_NOW%"=="y" (
    echo [*] Starting driver...
    sc start %DRIVER_NAME%
    if %errorlevel% equ 0 (
        echo [+] Driver started successfully!
    ) else (
        echo [!] Failed to start driver (Error: %errorlevel%)
        echo [!] This may be due to DSE - the driver needs a valid signature
    )
)

echo.
pause
