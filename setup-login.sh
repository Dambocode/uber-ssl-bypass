#!/bin/bash
# setup-login.sh — Install dependencies and run the Uber login test
#
# Usage: bash setup-login.sh [phone_number]
# Example: bash setup-login.sh +15551234567

echo "============================================"
echo " Uber Login Setup"
echo "============================================"
echo ""

# Install curl_cffi
echo "[*] Installing curl_cffi..."
pip3 install curl_cffi --break-system-packages 2>/dev/null || pip3 install curl_cffi 2>/dev/null

if python3 -c "from curl_cffi.requests import Session" 2>/dev/null; then
    echo "[+] curl_cffi installed successfully"
else
    echo "[!] curl_cffi failed, trying tls-client..."
    pip3 install tls-client --break-system-packages 2>/dev/null || pip3 install tls-client 2>/dev/null
    if python3 -c "import tls_client" 2>/dev/null; then
        echo "[+] tls-client installed"
    else
        echo "[!] Neither library installed. Try: pip3 install curl_cffi"
        exit 1
    fi
fi

echo ""
mkdir -p cookie-dump

# Run the login script
python3 uber-login.py "$@"
