#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  ARAN — Autonomous Risk Analysis & Network Security Platform
#  Linux/Mac startup script
# ═══════════════════════════════════════════════════════════════

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Java
if ! command -v java &>/dev/null; then
    echo "ERROR: Java not found. Install Java 21."
    exit 1
fi

JAVA_VER=$(java -version 2>&1 | head -1 | grep -o '[0-9]*' | head -1)
if [ "$JAVA_VER" -lt 21 ] 2>/dev/null; then
    echo "WARNING: Java 21+ recommended. Found Java $JAVA_VER."
fi

# Create directories
mkdir -p logs data reports out

# Compile if needed
if [ ! -f "out/aran/ARANApplication.class" ]; then
    echo "Compiling Java sources..."
    find src/aran -name "*.java" > /tmp/aran_sources.txt
    java -jar /usr/share/java/ecj.jar --release 21 -d out @/tmp/aran_sources.txt 2>/dev/null || \
    javac --release 21 -d out @/tmp/aran_sources.txt
    echo "Compilation successful!"
    echo
fi

# Parse flags
MODE="interactive"
if [ "$1" = "--server" ]; then MODE="server"; fi

echo "Starting ARAN ($MODE mode)..."
echo "Dashboard: http://localhost:$(grep api.port config/application.properties | cut -d= -f2 | tr -d ' ' || echo 8080)/"
echo

if [ "$MODE" = "server" ]; then
    exec java -cp out aran.ARANApplication --server
else
    exec java -cp out aran.ARANApplication
fi
