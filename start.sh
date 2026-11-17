#!/bin/bash
# start.sh — One script to rule them all
# Just run: ./start.sh
# It handles setup, debugging, Frida connection, proxy, and capture automatically.
# Logs everything to ./debug.log
#
# Options:
#   ./start.sh                     # auto-detect and sync versions
#   ./start.sh --sync-server       # (recommended) download server to match your PC's frida
#   ./start.sh --sync-client       # downgrade PC frida to match server on device
#   ./start.sh --skip-sync         # skip version check entirely

set -o pipefail

SCRIPT="scripts/android_ssl_bypass.js"
PROXY_PORT=8080
LOG="debug.log"
HAR="uber_capture_$(date +%Y%m%d_%H%M%S).har"

# macOS doesn't have `timeout` — use gtimeout or a portable fallback
if command -v timeout &>/dev/null; then
    TIMEOUT="timeout"
elif command -v gtimeout &>/dev/null; then
    TIMEOUT="gtimeout"
else
    # Pure bash fallback: run command in background, kill after N seconds
    _timeout() {
        local secs="$1"; shift
        "$@" &
        local pid=$!
        ( sleep "$secs"; kill "$pid" 2>/dev/null ) &
        local watcher=$!
        wait "$pid" 2>/dev/null
        local ret=$?
        kill "$watcher" 2>/dev/null
        wait "$watcher" 2>/dev/null
        return $ret
    }
    TIMEOUT="_timeout"
fi

# Parse args
SYNC_MODE="auto"
while [[ $# -gt 0 ]]; do
    case $1 in
        --sync-server) SYNC_MODE="server"; shift ;;
        --sync-client) SYNC_MODE="client"; shift ;;
        --skip-sync) SYNC_MODE="skip"; shift ;;
        --port) PROXY_PORT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# ── Logging ──────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $1" | tee -a "$LOG"; }
pass() { echo "[$(date +%H:%M:%S)] ✓ $1" | tee -a "$LOG"; }
fail() { echo "[$(date +%H:%M:%S)] ✗ $1" | tee -a "$LOG"; }
warn() { echo "[$(date +%H:%M:%S)] ! $1" | tee -a "$LOG"; }

echo "" > "$LOG"
log "============================================"
log "  Uber SSL Bypass — Auto Start"
log "  $(date)"
log "  Sync mode: $SYNC_MODE"
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

# Map arch for Frida download
case "$DEVICE_ARCH" in
    arm64-v8a) FRIDA_ARCH="arm64" ;;
    armeabi-v7a) FRIDA_ARCH="arm" ;;
    x86_64) FRIDA_ARCH="x86_64" ;;
    x86) FRIDA_ARCH="x86" ;;
    *) fail "Unsupported arch: $DEVICE_ARCH"; exit 1 ;;
esac

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

# ══════════════════════════════════════════════════════════════════
# ── Frida Version Sync ───────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════
log ""
log "--- Frida Version Check ---"

FRIDA_BINARY="/data/local/tmp/hluda-server"
PC_FRIDA_VER=$(frida --version 2>/dev/null | tr -d '\r\n')
DEVICE_FRIDA_VER=$(adb shell su -c "$FRIDA_BINARY --version" 2>/dev/null | tr -d '\r\n')

log "  PC frida-tools: v$PC_FRIDA_VER"
log "  Device server:  v${DEVICE_FRIDA_VER:-NOT INSTALLED}"

# Helper: download and push frida-server for a specific version
push_frida_server() {
    local VER="$1"
    local FRIDA_FILE="frida-server-${VER}-android-${FRIDA_ARCH}"
    local FRIDA_URL="https://github.com/frida/frida/releases/download/${VER}/${FRIDA_FILE}.xz"

    log "Downloading frida-server v${VER} for ${FRIDA_ARCH}..."
    curl -sL "$FRIDA_URL" -o "/tmp/${FRIDA_FILE}.xz"

    if [ ! -f "/tmp/${FRIDA_FILE}.xz" ] || [ ! -s "/tmp/${FRIDA_FILE}.xz" ]; then
        fail "Download failed from $FRIDA_URL"
        return 1
    fi

    # Decompress
    if command -v xz &>/dev/null; then
        xz -d -f "/tmp/${FRIDA_FILE}.xz"
    elif command -v python3 &>/dev/null; then
        python3 -c "import lzma,sys; open(sys.argv[2],'wb').write(lzma.open(sys.argv[1]).read())" \
            "/tmp/${FRIDA_FILE}.xz" "/tmp/${FRIDA_FILE}"
    else
        fail "xz not found. Install: brew install xz"
        return 1
    fi

    if [ ! -f "/tmp/${FRIDA_FILE}" ] || [ ! -s "/tmp/${FRIDA_FILE}" ]; then
        fail "Decompression failed"
        return 1
    fi

    log "Pushing frida-server to device as hluda-server..."
    adb push "/tmp/${FRIDA_FILE}" "$FRIDA_BINARY" >> "$LOG" 2>&1
    adb shell su -c "chmod 755 $FRIDA_BINARY" 2>/dev/null

    # Verify
    local NEW_VER=$(adb shell su -c "$FRIDA_BINARY --version" 2>/dev/null | tr -d '\r\n')
    if [ "$NEW_VER" = "$VER" ]; then
        pass "Frida server v${VER} installed on device"
        DEVICE_FRIDA_VER="$NEW_VER"
        return 0
    else
        fail "Version verify failed: expected $VER, got $NEW_VER"
        return 1
    fi
}

# Helper: change PC frida-tools to match a specific version
sync_client_to_version() {
    local VER="$1"
    log "Downgrading PC frida to v${VER} to match device..."

    # Map frida core version to frida-tools version is tricky,
    # so we install the matching frida core and let tools come along
    if pip3 install "frida==${VER}" 2>/dev/null; then
        pass "PC frida synced to v${VER}"
    elif pip3 install --break-system-packages "frida==${VER}" 2>/dev/null; then
        pass "PC frida synced to v${VER}"
    else
        fail "Could not install frida==${VER}"
        echo ""
        echo "Try manually:"
        echo "  pip3 install --break-system-packages frida==${VER}"
        echo ""
        echo "Or use a venv:"
        echo "  python3 -m venv ~/uber-venv && source ~/uber-venv/bin/activate"
        echo "  pip install frida==${VER} frida-tools"
        return 1
    fi

    PC_FRIDA_VER=$(frida --version 2>/dev/null | tr -d '\r\n')
    return 0
}

if [ "$SYNC_MODE" = "skip" ]; then
    log "Skipping version sync (--skip-sync)"
    if [ -z "$DEVICE_FRIDA_VER" ]; then
        warn "No frida-server on device — will try to push v${PC_FRIDA_VER}"
        push_frida_server "$PC_FRIDA_VER"
    fi

elif [ -z "$DEVICE_FRIDA_VER" ]; then
    # No server on device — download one matching the PC
    log "No frida-server on device. Downloading v${PC_FRIDA_VER} to match PC..."
    push_frida_server "$PC_FRIDA_VER"

elif [ "$PC_FRIDA_VER" = "$DEVICE_FRIDA_VER" ]; then
    pass "Versions match: v${PC_FRIDA_VER}"

else
    # MISMATCH
    warn "VERSION MISMATCH: PC v${PC_FRIDA_VER} ≠ Device v${DEVICE_FRIDA_VER}"
    echo ""

    if [ "$SYNC_MODE" = "server" ]; then
        log "Syncing server to match PC (--sync-server)..."
        push_frida_server "$PC_FRIDA_VER"

    elif [ "$SYNC_MODE" = "client" ]; then
        log "Syncing PC to match device (--sync-client)..."
        sync_client_to_version "$DEVICE_FRIDA_VER"

    else
        # Auto mode — recommend server sync (easier, no pip issues)
        warn "Auto-fixing: downloading frida-server v${PC_FRIDA_VER} for device"
        warn "(This is the recommended fix — no pip changes needed on your PC)"
        echo ""
        echo "  Other options if this fails:"
        echo "    ./start.sh --sync-client    # downgrade PC frida to v${DEVICE_FRIDA_VER} instead"
        echo "    ./start.sh --skip-sync      # skip version check"
        echo ""
        push_frida_server "$PC_FRIDA_VER"
    fi

    # Final check
    DEVICE_FRIDA_VER=$(adb shell su -c "$FRIDA_BINARY --version" 2>/dev/null | tr -d '\r\n')
    if [ "$PC_FRIDA_VER" != "$DEVICE_FRIDA_VER" ]; then
        fail "Versions still don't match after sync: PC v${PC_FRIDA_VER} ≠ Device v${DEVICE_FRIDA_VER}"
        echo ""
        echo "Manual fix options:"
        echo ""
        echo "  Option 1 (recommended): Update server on device"
        echo "    curl -sL https://github.com/frida/frida/releases/download/${PC_FRIDA_VER}/frida-server-${PC_FRIDA_VER}-android-${FRIDA_ARCH}.xz -o /tmp/frida-server.xz"
        echo "    xz -d -f /tmp/frida-server.xz"
        echo "    adb push /tmp/frida-server /data/local/tmp/hluda-server"
        echo "    adb shell su -c 'chmod 755 /data/local/tmp/hluda-server'"
        echo ""
        echo "  Option 2: Downgrade PC frida"
        echo "    pip3 install --break-system-packages frida==${DEVICE_FRIDA_VER}"
        echo ""
        exit 1
    fi
fi

log ""
log "  Final: PC v${PC_FRIDA_VER} | Device v${DEVICE_FRIDA_VER}"

# ══════════════════════════════════════════════════════════════════
# ── Start Frida Server ───────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════
log ""
log "--- Frida Server ---"

FRIDA_OK=false

if [ "$HAS_ROOT" = true ]; then
    # Disable SELinux (common blocker)
    adb shell su -c "setenforce 0" 2>/dev/null
    log "SELinux set to permissive"

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

    # ── Try Method 1: TCP with adb forward (most reliable on macOS) ──
    log ""
    log "--- Starting Frida Server (Attempt 1: TCP + adb forward) ---"
    adb shell su -c "nohup $FRIDA_BINARY -l 0.0.0.0:27042 >/dev/null 2>&1 &"
    sleep 3
    adb forward tcp:27042 tcp:27042 2>/dev/null

    if test_frida_ps "-H 127.0.0.1:27042"; then
        pass "Frida connected via TCP (port 27042 + adb forward)"
        FRIDA_MODE="-H 127.0.0.1:27042"
        FRIDA_OK=true
    else
        warn "TCP 27042 failed, trying USB mode..."

        # ── Try Method 2: USB mode ──────────────────────────────
        adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
        sleep 1
        adb shell su -c "nohup $FRIDA_BINARY >/dev/null 2>&1 &"
        sleep 3

        if test_frida_ps "-U"; then
            pass "Frida connected via USB"
            FRIDA_MODE="-U"
            FRIDA_OK=true
        else
            warn "USB mode failed, trying TCP on port 1337..."

            # ── Try Method 3: TCP on custom port ─────────────────
            adb shell su -c "pkill -9 -f hluda-server" 2>/dev/null
            sleep 1
            adb shell su -c "nohup $FRIDA_BINARY -l 0.0.0.0:1337 >/dev/null 2>&1 &"
            sleep 3
            adb forward tcp:1337 tcp:1337 2>/dev/null

            if test_frida_ps "-H 127.0.0.1:1337"; then
                pass "Frida connected via TCP (port 1337)"
                FRIDA_MODE="-H 127.0.0.1:1337"
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
frida $FRIDA_MODE -f com.ubercab.driver -l "$SCRIPT" >> "$LOG" 2>&1 &
FRIDA_PID=$!
sleep 8

if kill -0 "$FRIDA_PID" 2>/dev/null; then
    if adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; then
        pass "Method 1 (spawn): App launched!"
        LAUNCHED=true
    else
        kill "$FRIDA_PID" 2>/dev/null
    fi
else
    log "Spawn process exited early"
fi

if [ "$LAUNCHED" != true ]; then
    log "Method 1 failed, trying attach method..."
    adb shell am force-stop com.ubercab.driver 2>/dev/null
    sleep 1

    # Start the app normally
    adb shell monkey -p com.ubercab.driver -c android.intent.category.LAUNCHER 1 >> "$LOG" 2>&1
    sleep 3

    # Attach with script
    frida $FRIDA_MODE com.ubercab.driver -l "$SCRIPT" >> "$LOG" 2>&1 &
    FRIDA_PID=$!
    sleep 8

    if kill -0 "$FRIDA_PID" 2>/dev/null; then
        if adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; then
            pass "Method 2 (attach): App launched!"
            LAUNCHED=true
        else
            kill "$FRIDA_PID" 2>/dev/null
        fi
    else
        log "Attach process exited early"
    fi
fi

if [ "$LAUNCHED" != true ]; then
    log "Method 2 failed, trying late attach with delayed script..."
    adb shell am force-stop com.ubercab.driver 2>/dev/null
    sleep 1

    # Start app, wait longer, then attach
    adb shell monkey -p com.ubercab.driver -c android.intent.category.LAUNCHER 1 >> "$LOG" 2>&1
    sleep 5

    # Attach with script after app has fully started
    frida $FRIDA_MODE com.ubercab.driver -l "$SCRIPT" >> "$LOG" 2>&1 &
    FRIDA_PID=$!
    sleep 8

    if kill -0 "$FRIDA_PID" 2>/dev/null; then
        if adb shell pidof com.ubercab.driver 2>/dev/null | grep -q "[0-9]"; then
            pass "Method 3 (late attach): App launched!"
            warn "Some early hooks may have missed init — SSL bypass might be partial"
            LAUNCHED=true
        else
            kill "$FRIDA_PID" 2>/dev/null
        fi
    else
        log "Late attach process exited early"
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
    echo "Frida:       PC v${PC_FRIDA_VER} | Device v${DEVICE_FRIDA_VER}"
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
