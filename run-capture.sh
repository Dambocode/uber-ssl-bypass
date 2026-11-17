#!/bin/bash
# run-capture.sh — Quick launch for daily capture sessions
# Run after setup-rooted.sh has been completed once
#
# Usage:
#   ./run-capture.sh              # defaults: port 8080, USB mode
#   ./run-capture.sh --tcp        # use TCP mode (port 1337)
#   ./run-capture.sh --port 9090  # custom proxy port

set -e

PROXY_PORT=8080
FRIDA_MODE="-U"  # USB by default
SCRIPT="scripts/android_ssl_bypass.js"
OUTPUT="uber_capture_$(date +%Y%m%d_%H%M%S).har"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --tcp) FRIDA_MODE="-H 127.0.0.1:1337"; shift ;;
        --port) PROXY_PORT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo "============================================================"
echo " Uber Driver Traffic Capture"
echo " HAR output: $OUTPUT"
echo " Proxy port: $PROXY_PORT"
echo " Frida mode: $FRIDA_MODE"
echo "============================================================"
echo ""

# Kill any existing Frida server
adb shell su -c "pkill -f hluda-server" 2>/dev/null || true
sleep 1

# Start Frida server
echo "[*] Starting Frida server..."
if [ "$FRIDA_MODE" = "-U" ]; then
    adb shell su -c "/data/local/tmp/hluda-server &" 2>/dev/null
else
    adb shell su -c "/data/local/tmp/hluda-server -l 0.0.0.0:1337 &" 2>/dev/null
fi
sleep 2

# Get PC IP for proxy (works on macOS, Linux, and Windows/Git Bash)
PC_IP=""
if command -v ipconfig &>/dev/null && [[ "$(uname)" == "Darwin" ]]; then
    # macOS
    PC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
elif command -v hostname &>/dev/null && hostname -I &>/dev/null; then
    # Linux
    PC_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
else
    # Windows / Git Bash
    PC_IP=$(ipconfig 2>/dev/null | grep -A4 "Wi-Fi\|Ethernet" | grep "IPv4" | head -1 | awk '{print $NF}')
fi

if [ -z "$PC_IP" ]; then
    echo "[!] Could not detect PC IP. Enter it manually:"
    read -r PC_IP
fi

# Set device proxy
echo "[*] Setting device proxy to $PC_IP:$PROXY_PORT..."
adb shell settings put global http_proxy "$PC_IP:$PROXY_PORT"

# Start mitmproxy in background
echo "[*] Starting mitmproxy (HAR: $OUTPUT)..."
mitmdump --listen-port "$PROXY_PORT" \
    --set "hardump=./$OUTPUT" \
    "~d uber.com | ~d oojoovae.org | ~d uberinternal.com" &
MITM_PID=$!
sleep 2

# Launch Uber with bypass
echo "[*] Launching Uber Driver with SSL bypass..."
echo ""
frida $FRIDA_MODE -f com.ubercab.driver \
    -l "$SCRIPT" --no-pause

# Cleanup on exit
echo ""
echo "[*] Cleaning up..."
kill $MITM_PID 2>/dev/null || true
adb shell settings put global http_proxy :0
adb shell su -c "pkill -f hluda-server" 2>/dev/null || true

echo "[+] Done. HAR saved to: $OUTPUT"
