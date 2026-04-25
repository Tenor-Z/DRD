@echo off
setlocal EnableDelayedExpansion

echo.
echo ======================================================
echo   DRD v2.0 - Windows Build Script
echo   Discover / Report / Document
echo ======================================================
echo.

echo [*] Checking for GCC compiler...
where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] GCC not found in PATH.
    echo.
    echo Please install MinGW-w64:
    echo   https://www.mingw-w64.org/downloads/
    echo.
    echo Or install via MSYS2:
    echo   https://www.msys2.org/
    echo   Then run: pacman -S mingw-w64-x86_64-gcc
    echo.
    echo After installing, add the bin folder to your PATH.
    echo.
    goto :end
)

echo [+] GCC found.
echo.

echo [*] GCC Version:
gcc --version | findstr /C:"gcc"
echo.

echo [*] Compiling DRD v2.0...
echo [*] Command: gcc -O2 -Wall -o drd.exe drd_intel.c -lws2_32 -liphlpapi
echo.
echo --- Compiler Output ---
echo.

gcc -O2 -Wall -Wno-unused-variable -o drd.exe drd_intel.c -lws2_32 -liphlpapi
set BUILD_RESULT=%ERRORLEVEL%

echo.
echo --- End Compiler Output ---
echo.

if %BUILD_RESULT% EQU 0 (
    echo [+] BUILD SUCCESSFUL
    echo [+] Executable: drd.exe
    echo.
    echo Quick test: drd.exe -h
    echo.
) else (
    echo [X] BUILD FAILED with error code: %BUILD_RESULT%
    echo.
    echo Common issues:
    echo   1. Missing header files - check MinGW installation
    echo   2. Missing libraries - ensure ws2_32 and iphlpapi are available
    echo   3. Syntax errors in source code
    echo.
    echo Try compiling manually to see full errors:
    echo   gcc -Wall -o drd-intel.exe drd_intel.c -lws2_32 -liphlpapi
    echo.
)

:end
echo.
echo Press any key to exit...
pause >nul
