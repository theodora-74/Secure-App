#!/bin/bash
# ============================================================
# SecurePanel - Security Test Runner for Kali Linux
# Run this WHILE the server is running in another terminal
# ============================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  SecurePanel - STRIDE Security Test Suite${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Check if server is running
if ! curl -s -o /dev/null -w "" http://127.0.0.1:5000/ 2>/dev/null; then
    echo -e "${RED}[!] Server is not running!${NC}"
    echo -e "${RED}[!] Open another terminal and run: bash run.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Server detected at http://127.0.0.1:5000${NC}"
echo ""

python3 security_tests.py
