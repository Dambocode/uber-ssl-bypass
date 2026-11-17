#!/bin/bash
# start.sh — One script to rule them all
# Just run: ./start.sh
# It handles setup, debugging, Frida connection, proxy, and capture automatically.
# Logs everything to ./debug.log

set -o pipefail

SCRIPT="scripts/android_ssl_bypass.js"
PROXY_PORT=8080
LOG="debug.log"
HAR="uber_capture_$(date +%Y%m%d_%H%M%S).har"
FRIDA_VERSION="17.7.3"

# ── Logging ──────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $1" | tee -a "$LOG"; }
pass() { echo "[$(date +%H:%M:%S)] ✓ $1" | tee -a "$LOG"; }
fail() { echo "[$(date +%H:%M:%S)] ✗ $1" | tee -a "$LOG"; }
warn() { echo "[$(date +%H:%M:%S)] ! $1" | tee -a "$LOG"; }

echo "" > "$LOG"
log "============================================"
log "  Uber SSL Bypass — Auto Start"
log "  $(date)"
log "============================================"

# ── Check tools ──────────────────────────────────────────────────
MISSING=""
for cmd in adb frida frida-ps; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING="$MISSING $cmd"
    fi
done

if [ -n "$MISSING" ]; then
    fail "Missing tools:$MISSING"
    echo ""
    echo "Install them:"
    echo "  brew install android-platform-tools"
    echo "  pip3 install frida-tools"
    exit 1
fi
pass "Tools: adb, frida, frida-ps found"

if ! command -v mitmdump &>/dev/null; then
    warn "mitmdump not found — will skip proxy/HAR capture"
    warn "Install with: pip3 install mitmproxy"
    HAS_MITM=false
else
    pass "mitmproxy found"
    HAS_MITM=true
fi

# ── Check device ─────────────────────────────────────────────────
log ""
log "--- Device Check ---"

if ! adb devices 2>/dev/null | grep -q "device$"; then
    fail "No Android device connected"
    echo ""
    echo "Fix:"
    echo "  1. Connect phone via USB"
    echo "  2. Enable USB Debugging on the phone"
    echo "  3. Tap 'Allow' on the USB debugging popup"
    echo "  4. Run this script again"
    exit 1
fi
DEVICE_MODEL=$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r\n')
DEVICE_ARCH=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r\n')
ANDROID_VER=$(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r\n')
pass "Device: $DEVICE_MODEL ($DEVICE_ARCH) Android $ANDROID_VER"

# ── Check root ───────────────────────────────────────────────────
if adb shell su -c "id" 2>/dev/null | grep -q "uid=0"; then
    pass "Root access: yes"
    HAS_ROOT=true
else
    warn "Root access: no (or not granted)"
    warn "Some features may not work without root"
    HAS_ROOT=false
fi

# ── Check Uber installed ────────────────────────────────────────
log ""
log "--- Uber Driver Check ---"
UBER_INFO=$(adb shell pm list packages -i 2>/dev/null | grep "com.ubercab.driver" || echo "")
if [ -z "$UBER_INFO" ]; then
    fail "Uber Driver is NOT installed"
    echo ""
    echo "Install it from the Google Play Store on the device first."
    exit 1
fi

if echo "$UBER_INFO" | grep -q "com.android.vending"; then
    pass "Uber Driver installed from Play Store"
else
    warn "Uber Driver installed but NOT from Play Store"
    warn "Play Integrity may fail — reinstall from Play Store for best results"
fi

UBER_VERSION=$(adb shell dumpsys package com.ubercab.driver 2>/dev/null | grep "versionName" | head -1 | awk -F= '{print $2}' | tr -d '\r\n')
log "  Version: $UBER_VERSION"

# ── Check bypass script exists ───────────────────────────────────
if [ ! -f "$SCRIPT" ]; then
    fail "Bypass script not found at $SCRIPT"
    echo "Make sure you're running this from the uber-ssl-bypass directory"
    exit 1
fi
pass "Bypass script: $SCRIPT"

# ── Kill everything first ────────────────────────────────────────
log ""
log "--- Cleanup ---"
adb shell am force-stop com.ubercab.driver 2>/dev/null
adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
adb shell su -c "pkill -9 -f frida-server" 2>/dev/null
adb shell settings put global http_proxy :0 2>/dev/null
sleep 1
pass "Killed existing Frida and Uber processes"

# ── Push bypass script ───────────────────────────────────────────
log ""
log "--- Push Script ---"
adb push "$SCRIPT" /data/local/tmp/android_ssl_bypass.js >> "$LOG" 2>&1
pass "Bypass script pushed to device"

# ── Setup Frida server ───────────────────────────────────────────
log ""
log "--- Frida Server ---"

FRIDA_BINARY="/data/local/tmp/hluda-server"
FRIDA_OK=false

if [ "$HAS_ROOT" = true ]; then
    # Check if binary exists and works
    DEVICE_FRIDA_VER=$(adb shell su -c "$FRIDA_BINARY --version" 2>/dev/null | tr -d '\r\n')
    if [ -n "$DEVICE_FRIDA_VER" ]; then
        pass "Frida server on device: v$DEVICE_FRIDA_VER"
    else
        log "Frida server not found on device, downloading..."

        case "$DEVICE_ARCH" in
            arm64-v8a) FRIDA_ARCH="arm64" ;;
            armeabi-v7a) FRIDA_ARCH="arm" ;;
            x86_64) FRIDA_ARCH="x86_64" ;;
            x86) FRIDA_ARCH="x86" ;;
            *) fail "Unsupported arch: $DEVICE_ARCH"; exit 1 ;;
        esac

        FRIDA_FILE="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
        FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_FILE}.xz"

        if [ ! -f "/tmp/${FRIDA_FILE}" ]; then
            log "Downloading from $FRIDA_URL ..."
            curl -sL "$FRIDA_URL" -o "/tmp/${FRIDA_FILE}.xz"
            if command -v xz &>/dev/null; then
                xz -d -f "/tmp/${FRIDA_FILE}.xz"
            elif command -v python3 &>/dev/null; then
                python3 -c "import lzma,sys; open(sys.argv[2],'wb').write(lzma.open(sys.argv[1]).read())" \
                    "/tmp/${FRIDA_FILE}.xz" "/tmp/${FRIDA_FILE}"
            else
                fail "xz not found. Install: brew install xz"
                exit 1
            fi
        fi

        adb push "/tmp/${FRIDA_FILE}" "$FRIDA_BINARY" >> "$LOG" 2>&1
        adb shell su -c "chmod 755 $FRIDA_BINARY" 2>/dev/null
        pass "Frida server pushed to device"
    fi

    # Disable SELinux (common blocker)
    adb shell su -c "setenforce 0" 2>/dev/null
    log "SELinux set to permissive"

    # ── Try Method 1: USB mode on default port ───────────────────
    log ""
    log "--- Starting Frida Server (Attempt 1: USB mode) ---"
    adb shell su -c "nohup $FRIDA_BINARY >/dev/null 2>&1 &"
    sleep 3

    if frida-ps -U 2>/dev/null | head -3 | grep -q "[0-9]"; then
        pass "Frida connected via USB (default port)"
        FRIDA_MODE="-U"
        FRIDA_OK=true
    else
        warn "USB mode failed, trying TCP on port 1337..."

        # ── Try Method 2: TCP mode on custom port ────────────────
        adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
        sleep 1
        adb shell su -c "nohup $FRIDA_BINARY -l 127.0.0.1:1337 >/dev/null 2>&1 &"
        sleep 3
        adb forward tcp:1337 tcp:1337 2>/dev/null

        if frida-ps -H 127.0.0.1:1337 2>/dev/null | head -3 | grep -q "[0-9]"; then
            pass "Frida connected via TCP (port 1337)"
            FRIDA_MODE="-H 127.0.0.1:1337"
            FRIDA_OK=true
        else
            warn "TCP mode 1337 failed, trying port 27042 with adb forward..."

            # ── Try Method 3: Default port with adb forward ──────
            adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
            sleep 1
            adb shell su -c "nohup $FRIDA_BINARY -l 127.0.0.1:27042 >/dev/null 2>&1 &"
            sleep 3
            adb forward tcp:27042 tcp:27042 2>/dev/null

            if frida-ps -H 127.0.0.1:27042 2>/dev/null | head -3 | grep -q "[0-9]"; then
                pass "Frida connected via TCP (port 27042)"
                FRIDA_MODE="-H 127.0.0.1:27042"
                FRIDA_OK=true
            else
                fail "All Frida connection methods failed"
            fi
        fi
    fi
else
    log "No root — trying Frida USB mode (may need manual frida-server start)"
    if frida-ps -U 2>/dev/null | head -3 | grep -q "[0-9]"; then
        pass "Frida connected via USB"
        FRIDA_MODE="-U"
        FRIDA_OK=true
    else
        fail "Cannot connect to Frida. Root required to start frida-server."
    fi
fi

if [ "$FRIDA_OK" != true ]; then
    echo ""
    fail "Could not connect to Frida server"
    echo ""
    echo "Manual debug steps:"
    echo "  1. adb shell su -c 'setenforce 0'"
    echo "  2. adb shell su -c '/data/local/tmp/hluda-server'"
    echo "     (run in foreground — does it print 'Listening on...'?)"
    echo "  3. If it prints an error, paste it here"
    echo ""
    echo "Full log: $LOG"
    exit 1
fi

# ── Setup proxy ──────────────────────────────────────────────────
log ""
log "--- Proxy Setup ---"

MITM_PID=""
if [ "$HAS_MITM" = true ]; then
    # Get Mac IP
    PC_IP=""
    if [[ "$(uname)" == "Darwin" ]]; then
        PC_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
    elif hostname -I &>/dev/null; then
        PC_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    if [ -z "$PC_IP" ]; then
        warn "Could not detect PC IP — skipping proxy setup"
        warn "Set manually: adb shell settings put global http_proxy YOUR_IP:8080"
    else
        pass "PC IP: $PC_IP"
        adb shell settings put global http_proxy "$PC_IP:$PROXY_PORT"
        pass "Device proxy set to $PC_IP:$PROXY_PORT"

        # Start mitmproxy in background
        mitmdump --listen-port "$PROXY_PORT" \
            --set "hardump=./$HAR" \
            "~d uber.com | ~d oojoovae.org | ~d uberinternal.com" >> "$LOG" 2>&1 &
        MITM_PID=$!
        sleep 2

        if kill -0 "$MITM_PID" 2>/dev/null; then
            pass "mitmproxy running (PID $MITM_PID) → $HAR"
        else
            warn "mitmproxy failed to start — capture will not work"
            warn "Check if port $PROXY_PORT is in use: lsof -i :$PROXY_PORT"
            MITM_PID=""
        fi
    fi
fi

# ── Launch Uber with bypass ──────────────────────────────────────
log ""
log "--- Launching Uber Driver ---"

# Force stop first
adb shell am force-stop com.ubercab.driver 2>/dev/null
sleep 1

# Try spawn methods in order
LAUNCHED=false

# Method 1: frida spawn with -f (preferred — hooks before app init)
log "Trying: frida $FRIDA_MODE -f com.ubercab.driver -l $SCRIPT"
timeout 15 frida $FRIDA_MODE -f com.ubercab.driver -l "$SCRIPT" --no-pause >> "$LOG" 2>&1 &
FRIDA_PID=$!
sleep 5

if kill -0 "$FRIDA_PID" 2>/dev/null; then
    # Check if app is running
    if adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; then
        pass "Method 1 (spawn --no-pause): App launched!"
        LAUNCHED=true
    else
        kill "$FRIDA_PID" 2>/dev/null
    fi
fi

if [ "$LAUNCHED" != true ]; then
    log "Method 1 failed, trying without --no-pause..."
    adb shell am force-stop com.ubercab.driver 2>/dev/null
    sleep 1

    timeout 15 frida $FRIDA_MODE -f com.ubercab.driver -l "$SCRIPT" >> "$LOG" 2>&1 &
    FRIDA_PID=$!
    sleep 5

    if kill -0 "$FRIDA_PID" 2>/dev/null; then
        if adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; then
            pass "Method 2 (spawn no flags): App launched!"
            LAUNCHED=true
        else
            kill "$FRIDA_PID" 2>/dev/null
        fi
    fi
fi

if [ "$LAUNCHED" != true ]; then
    log "Method 2 failed, trying attach method..."
    adb shell am force-stop com.ubercab.driver 2>/dev/null
    sleep 1

    # Start the app normally
    adb shell monkey -p com.ubercab.driver -c android.intent.category.LAUNCHER 1 >> "$LOG" 2>&1
    sleep 2

    # Attach with script
    timeout 15 frida $FRIDA_MODE com.ubercab.driver -l "$SCRIPT" >> "$LOG" 2>&1 &
    FRIDA_PID=$!
    sleep 5

    if kill -0 "$FRIDA_PID" 2>/dev/null; then
        if adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; then
            pass "Method 3 (attach): App launched!"
            LAUNCHED=true
        else
            kill "$FRIDA_PID" 2>/dev/null
        fi
    fi
fi

if [ "$LAUNCHED" != true ]; then
    log "Method 3 failed, trying attach with delayed script load..."
    adb shell am force-stop com.ubercab.driver 2>/dev/null
    sleep 1

    # Start app, wait longer, then attach
    adb shell monkey -p com.ubercab.driver -c android.intent.category.LAUNCHER 1 >> "$LOG" 2>&1
    sleep 5

    # Attach without script first
    frida $FRIDA_MODE com.ubercab.driver -e "
        console.log('[*] Attached to Uber Driver');
        console.log('[*] Loading bypass script...');
    " >> "$LOG" 2>&1 &
    FRIDA_PID=$!
    sleep 3

    if kill -0 "$FRIDA_PID" 2>/dev/null; then
        if adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; then
            pass "Method 4 (late attach): App running with Frida attached"
            warn "Bypass script NOT loaded — some hooks may have missed init"
            warn "SSL bypass may be incomplete with this method"
            LAUNCHED=true
        else
            kill "$FRIDA_PID" 2>/dev/null
        fi
    fi
fi

# ── Results ──────────────────────────────────────────────────────
log ""
log "============================================"
if [ "$LAUNCHED" = true ]; then
    log "  ✓ UBER DRIVER IS RUNNING WITH FRIDA"
    log "============================================"
    echo ""
    echo "The app should be open on the phone now."
    echo ""
    if [ -n "$MITM_PID" ]; then
        echo "Traffic capture: ACTIVE → $HAR"
        echo "Press Ctrl+C when done to save the HAR and cleanup."
    else
        echo "Traffic capture: NOT ACTIVE (mitmproxy not running)"
        echo "Press Ctrl+C when done to cleanup."
    fi
    echo ""
    echo "Frida logs: tail -f $LOG"
    echo ""

    # Keep running until Ctrl+C
    cleanup() {
        echo ""
        log "Cleaning up..."
        adb shell settings put global http_proxy :0 2>/dev/null
        adb shell am force-stop com.ubercab.driver 2>/dev/null
        adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
        [ -n "$MITM_PID" ] && kill "$MITM_PID" 2>/dev/null
        [ -n "$FRIDA_PID" ] && kill "$FRIDA_PID" 2>/dev/null
        pass "Proxy cleared, processes stopped"
        if [ -f "./$HAR" ]; then
            HAR_SIZE=$(ls -lh "./$HAR" 2>/dev/null | awk '{print $5}')
            pass "HAR saved: $HAR ($HAR_SIZE)"
        fi
        log "Done. Full log: $LOG"
        exit 0
    }
    trap cleanup INT TERM

    # Stream Frida output
    if [ -n "$FRIDA_PID" ] && kill -0 "$FRIDA_PID" 2>/dev/null; then
        wait "$FRIDA_PID" 2>/dev/null
    else
        # Just wait for Ctrl+C
        log "Monitoring... (Ctrl+C to stop)"
        while adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; do
            sleep 5
        done
        warn "Uber Driver process exited"
        cleanup
    fi
else
    log "  ✗ ALL LAUNCH METHODS FAILED"
    log "============================================"
    echo ""
    fail "Could not launch Uber Driver with Frida"
    echo ""
    echo "===== DIAGNOSTIC INFO ====="
    echo "Device:      $DEVICE_MODEL ($DEVICE_ARCH) Android $ANDROID_VER"
    echo "Root:        $HAS_ROOT"
    echo "Frida mode:  $FRIDA_MODE"
    echo "Uber ver:    $UBER_VERSION"
    echo ""
    echo "===== QUICK MANUAL TEST ====="
    echo ""
    echo "Run these one at a time to find where it breaks:"
    echo ""
    echo "  # 1. Can Frida see the device?"
    echo "  frida-ps $FRIDA_MODE | head -5"
    echo ""
    echo "  # 2. Can Frida spawn any app?"
    echo "  frida $FRIDA_MODE -f com.android.settings -e 'console.log(\"ok\")'"
    echo ""
    echo "  # 3. Can Uber start without Frida?"
    echo "  adb shell am force-stop com.ubercab.driver"
    echo "  adb shell monkey -p com.ubercab.driver -c android.intent.category.LAUNCHER 1"
    echo ""
    echo "  # 4. Does Uber crash when Frida attaches with NO script?"
    echo "  frida $FRIDA_MODE com.ubercab.driver -e 'console.log(\"attached\")'"
    echo ""
    echo "  # 5. Does it crash WITH the script?"
    echo "  frida $FRIDA_MODE com.ubercab.driver -l scripts/android_ssl_bypass.js"
    echo ""
    echo "===== LAST 20 LINES OF LOG ====="
    tail -20 "$LOG"
    echo ""
    echo "Full log: $LOG"

    # Cleanup
    adb shell settings put global http_proxy :0 2>/dev/null
    adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
    exit 1
fi
