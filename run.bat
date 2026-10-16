@echo off
REM ═══════════════════════════════════════════════════════════════
REM  ARAN — Autonomous Risk Analysis & Network Security Platform
REM  Windows startup script
REM ═══════════════════════════════════════════════════════════════

set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21.0.5.11-hotspot
set PATH=%JAVA_HOME%\bin;%PATH%

echo Starting ARAN...
echo.

REM Create required directories
if not exist "logs"    mkdir logs
if not exist "data"    mkdir data
if not exist "reports" mkdir reports

REM Compile if not compiled
if not exist "out\aran\ARANApplication.class" (
    echo Compiling Java sources...
    dir /s /b src\aran\*.java > sources.txt
    javac --release 21 -d out @sources.txt
    if errorlevel 1 (
        echo Compilation failed!
        pause
        exit /b 1
    )
    echo Compilation successful!
    echo.
)

REM Start in interactive CLI mode (default)
REM Use: java -cp out aran.ARANApplication --server   for headless server mode
java -cp out aran.ARANApplication

pause
