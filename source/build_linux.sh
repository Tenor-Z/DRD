#!/bin/bash

echo ""
echo "======================================================"
echo "  DRD v2.0 - Linux/macOS Build Script"
echo "  Discover | Report | Document"
echo "======================================================"
echo ""

# Check if GCC is available
if ! command -v gcc &> /dev/null; then
    echo "[ERROR] GCC not found. Install with:"
    echo "  Ubuntu/Debian: sudo apt install gcc"
    echo "  macOS: xcode-select --install"
    exit 1
fi

echo "[*] Compiling DRD v2.0..."
gcc -O2 -Wall -o drd-intel drd_intel.c -lpthread

if [ $? -eq 0 ]; then
    chmod +x drd
    echo ""
    echo "[+] Compilation successful!"
    echo "[+] Executable: ./drd-intel"
    echo ""
    echo "======================================================"
    echo "  Quick Reference"
    echo "======================================================"
    echo ""
    echo "  Basic Scan:"
    echo "    ./drd example.com"
    echo ""
    echo "  Port Range:"
    echo "    ./drd 192.168.1.1 -p 1-65535"
    echo "    ./drd 192.168.1.1 -p 22,80,443"
    echo ""
    echo "  Top Ports:"
    echo "    ./drd 192.168.1.1 -top 100"
    echo ""
    echo "  Version Detection:"
    echo "    ./drd example.com -sV"
    echo ""
    echo "  Subnet Scan (CIDR):"
    echo "    ./drd 192.168.1.0/24 -top 20 -v"
    echo ""
    echo "  IPv6:"
    echo "    ./drd ::1 -6 -p 22,80,443"
    echo ""
    echo "  Full Scan with Report:"
    echo "    ./drd target.com -p 1-65535 -sV -u -o report.html"
    echo ""
    echo "  Verbose Levels:"
    echo "    -v   Show progress"
    echo "    -vv  Show closed ports"
    echo "    -vvv Debug output"
    echo ""
    echo "  For full help: ./drd -h"
    echo ""
else
    echo "[ERROR] Build failed. Check your GCC installation."
    exit 1
fi
