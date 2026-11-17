#!/bin/bash
# diagnose.sh — Find exactly why Frida won't connect
# Run: bash diagnose.sh
# Paste ALL output back to Claude

echo "===== DIAGNOSE: $(date) ====="
echo ""

# 1. Versions
echo "--- VERSIONS ---"
echo "PC frida: $(frida --version 2>&1)"
echo "PC frida-tools: $(pip3 show frida-tools 2>/dev/null | grep Version || echo 'unknown')"
echo "PC python: $(python3 --version 2>&1)"
echo "PC OS: $(uname -a)"
echo ""

# 2. Device
echo "--- DEVICE ---"
adb devices 2>&1
echo ""
echo "Model: $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r\n')"
echo "Arch: $(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r\n')"
echo "Android: $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r\n')"
echo "SELinux: $(adb shell getenforce 2>/dev/null | tr -d '\r\n')"
echo ""

# 3. Root
echo "--- ROOT ---"
adb shell su -c "id" 2>&1
echo ""

# 4. Frida binary on device
echo "--- FRIDA BINARY ---"
adb shell su -c "ls -la /data/local/tmp/hluda-server" 2>&1
echo "Server version: $(adb shell su -c '/data/local/tmp/hluda-server --version' 2>&1 | tr -d '\r\n')"
echo ""

# 5. Kill everything
echo "--- KILLING OLD PROCESSES ---"
adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
adb shell su -c "pkill -9 -f frida-server" 2>/dev/null
adb shell su -c "setenforce 0" 2>/dev/null
sleep 2
echo "Done"
echo ""

# 6. Try starting in foreground briefly to see errors
echo "--- START FRIDA (foreground, 5 sec) ---"
adb shell su -c "/data/local/tmp/hluda-server" &
SERVER_PID=$!
sleep 5
echo ""

# Check if it's still alive
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "Server process: ALIVE"
else
    echo "Server process: DEAD (crashed or exited)"
fi
echo ""

# 7. Check what's listening on the device
echo "--- DEVICE LISTENING PORTS ---"
adb shell su -c "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null" 2>&1 | grep -E "27042|1337|frida|hluda" || echo "(no frida ports found)"
echo ""

# 8. Try frida-ps USB
echo "--- FRIDA-PS USB ---"
timeout 10 frida-ps -U 2>&1 | head -10
USB_EXIT=$?
echo "Exit code: $USB_EXIT"
echo ""

# 9. Kill foreground server, try TCP
kill $SERVER_PID 2>/dev/null
adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
sleep 2

echo "--- START FRIDA (TCP 127.0.0.1:27042) ---"
adb shell su -c "nohup /data/local/tmp/hluda-server -l 127.0.0.1:27042 >/dev/null 2>&1 &"
sleep 3

echo "Port forward:"
adb forward tcp:27042 tcp:27042 2>&1
echo ""

echo "--- FRIDA-PS TCP ---"
timeout 10 frida-ps -H 127.0.0.1:27042 2>&1 | head -10
TCP_EXIT=$?
echo "Exit code: $TCP_EXIT"
echo ""

# 10. Check if adb has USB issues
echo "--- ADB USB CHECK ---"
adb usb 2>&1
echo ""

# 11. Check for other frida/Python issues
echo "--- FRIDA PYTHON MODULE ---"
python3 -c "import frida; print('frida module version:', frida.__version__); d = frida.get_usb_device(timeout=5); print('USB device:', d); print('Processes:', len(d.enumerate_processes()))" 2>&1
echo ""

# Cleanup
adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null

echo "===== END DIAGNOSE ====="
echo ""
echo "Copy EVERYTHING above and paste it back."
