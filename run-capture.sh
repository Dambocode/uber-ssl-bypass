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

# Cleanup on exit (Ctrl+C or error)
cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    [ -n "$MITM_PID" ] && kill $MITM_PID 2>/dev/null || true
    [ -n "$FRIDA_PID" ] && kill $FRIDA_PID 2>/dev/null || true
    adb shell settings put global http_proxy :0 2>/dev/null || true
    adb shell su -c "pkill -f hluda-server" 2>/dev/null || true
    if [ -f "./$OUTPUT" ]; then
        echo "[+] HAR saved to: $OUTPUT ($(ls -lh "./$OUTPUT" | awk '{print $5}'))"
    fi
    echo "[+] Done."
    exit 0
}
trap cleanup INT TERM EXIT

# Kill any existing Frida server
adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null || true
adb shell am force-stop com.ubercab.driver 2>/dev/null || true
sleep 1

# Disable SELinux (common Frida blocker)
adb shell su -c "setenforce 0" 2>/dev/null || true

# Helper: test frida-ps with a timeout (macOS has no `timeout` command)
test_frida_ps() {
    local mode="$1"
    frida-ps $mode > /tmp/frida-ps-out 2>&1 &
    local pid=$!
    ( sleep 8; kill "$pid" 2>/dev/null ) &
    local watcher=$!
    wait "$pid" 2>/dev/null
    local ret=$?
    kill "$watcher" 2>/dev/null 2>&1
    wait "$watcher" 2>/dev/null 2>&1
    if [ $ret -eq 0 ] && head -3 /tmp/frida-ps-out | grep -q "[0-9]"; then
        return 0
    fi
    return 1
}

# Start Frida server — TCP + adb forward is most reliable on macOS
echo "[*] Starting Frida server..."
if [ "$FRIDA_MODE" = "-U" ]; then
    # Default to TCP+forward (works better on macOS), fall back to USB
    adb shell su -c "nohup /data/local/tmp/hluda-server -l 0.0.0.0:27042 >/dev/null 2>&1 &"
    sleep 3
    adb forward tcp:27042 tcp:27042 2>/dev/null || true

    echo "[*] Verifying Frida connection (TCP + adb forward)..."
    if test_frida_ps "-H 127.0.0.1:27042"; then
        echo "[+] Frida connected via TCP (port 27042)."
        FRIDA_MODE="-H 127.0.0.1:27042"
    else
        echo "[!] TCP failed, trying USB mode..."
        adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null || true
        sleep 1
        adb shell su -c "nohup /data/local/tmp/hluda-server >/dev/null 2>&1 &"
        sleep 3

        if test_frida_ps "-U"; then
            echo "[+] Frida connected via USB."
            FRIDA_MODE="-U"
        else
            echo "[!] Cannot connect to Frida. Run these manually to debug:"
            echo "    adb shell su -c '/data/local/tmp/hluda-server'"
            echo "    (should print 'Listening on...' — if error, paste it)"
            exit 1
        fi
    fi
else
    adb shell su -c "nohup /data/local/tmp/hluda-server -l 0.0.0.0:1337 >/dev/null 2>&1 &"
    sleep 3
    adb forward tcp:1337 tcp:1337 2>/dev/null || true

    echo "[*] Verifying Frida connection..."
    if test_frida_ps "$FRIDA_MODE"; then
        echo "[+] Frida connected."
    else
        echo "[!] Cannot connect to Frida. Run these manually to debug:"
        echo "    adb shell su -c '/data/local/tmp/hluda-server'"
        exit 1
    fi
fi

# Get PC IP for proxy (works on macOS, Linux, and Windows/Git Bash)
PC_IP=""
if [[ "$(uname)" == "Darwin" ]]; then
    PC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
elif command -v hostname &>/dev/null && hostname -I &>/dev/null 2>&1; then
    PC_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
else
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

if ! kill -0 $MITM_PID 2>/dev/null; then
    echo "[!] mitmproxy failed to start. Port $PROXY_PORT may be in use."
    echo "    Check: lsof -i :$PROXY_PORT"
    exit 1
fi
echo "[+] mitmproxy running."

# Launch Uber with bypass — try multiple methods
echo "[*] Launching Uber Driver with SSL bypass..."
echo ""

# Method 1: Spawn with frida -f (best — hooks before app init)
echo "[*] Trying spawn method..."
frida $FRIDA_MODE -f com.ubercab.driver -l "$SCRIPT" &
FRIDA_PID=$!
sleep 5

if ! kill -0 $FRIDA_PID 2>/dev/null; then
    echo "[!] Spawn method failed. Trying attach method..."

    # Method 2: Start app then attach
    adb shell am force-stop com.ubercab.driver 2>/dev/null || true
    sleep 1
    adb shell monkey -p com.ubercab.driver -c android.intent.category.LAUNCHER 1 2>/dev/null
    sleep 3

    frida $FRIDA_MODE com.ubercab.driver -l "$SCRIPT" &
    FRIDA_PID=$!
    sleep 5

    if ! kill -0 $FRIDA_PID 2>/dev/null; then
        echo "[!] Attach method also failed."
        echo ""
        echo "Manual debug — run each line and see where it breaks:"
        echo "  frida-ps $FRIDA_MODE | head -5"
        echo "  frida $FRIDA_MODE -f com.ubercab.driver"
        echo "  frida $FRIDA_MODE com.ubercab.driver -l $SCRIPT"
        exit 1
    fi
fi

echo ""
echo "============================================================"
echo " ✓ RUNNING — Uber Driver + SSL Bypass + mitmproxy"
echo "   Traffic capture: $OUTPUT"
echo "   Press Ctrl+C to stop and save"
echo "============================================================"
echo ""

# Wait for Frida to exit (user Ctrl+C triggers cleanup via trap)
wait $FRIDA_PID 2>/dev/null
