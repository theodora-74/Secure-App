#!/bin/bash
# ============================================================
# SecurePanel - Setup & Run Script for Kali Linux
# DEV6003 Secure Application Development
# ============================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  SecurePanel - Secure Incident Management Portal${NC}"
echo -e "${CYAN}  DEV6003 Secure Application Development${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 is not installed. Install it with:${NC}"
    echo "    sudo apt update && sudo apt install python3 python3-pip -y"
    exit 1
fi

echo -e "${GREEN}[+] Python3 found: $(python3 --version)${NC}"

# Install dependencies
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt --break-system-packages --quiet 2>/dev/null || \
pip3 install -r requirements.txt --quiet 2>/dev/null

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to install dependencies. Try:${NC}"
    echo "    pip3 install -r requirements.txt --break-system-packages"
    exit 1
fi

echo -e "${GREEN}[+] Dependencies installed successfully${NC}"

# Clean previous database for fresh start
if [ "$1" == "--fresh" ]; then
    echo -e "${CYAN}[*] Removing old database for fresh start...${NC}"
    rm -f secure_portal.db security_audit.log test_report.json
fi

# Start server
echo ""
echo -e "${GREEN}[+] Starting SecurePanel server...${NC}"
echo -e "${GREEN}[+] URL: http://127.0.0.1:5000${NC}"
echo -e "${GREEN}[+] Admin login: admin / Admin@Secure2026${NC}"
echo ""
echo -e "${CYAN}[*] Press Ctrl+C to stop the server${NC}"
echo ""

python3 app.py
