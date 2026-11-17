#!/bin/bash
# setup-rooted.sh — Setup Uber Driver SSL bypass on a ROOTED Android device
# Uses original Uber APK from Play Store + Frida server (not gadget)
# This preserves Play Integrity since the APK is not re-signed
#
# Prerequisites:
#   - Rooted Android device with Magisk
#   - ADB connected to the device
#   - mitmproxy installed on this PC (pip install mitmproxy)
#   - Frida tools on this PC (pip install frida-tools)

set -e

SCRIPT="scripts/android_ssl_bypass.js"
FRIDA_VERSION="17.7.3"
PROXY_PORT=8080

echo "============================================================"
echo " Uber Driver SSL Bypass — Rooted Device Setup"
echo "============================================================"
echo ""

# ── Step 0: Check prerequisites ──────────────────────────────────
echo "[*] Checking prerequisites..."

if ! command -v adb &>/dev/null; then
    echo "[!] adb not found. Install Android SDK Platform Tools."
    exit 1
fi

if ! command -v frida &>/dev/null; then
    echo "[!] frida not found. Run: pip install frida-tools"
    exit 1
fi

if ! command -v mitmdump &>/dev/null; then
    echo "[!] mitmdump not found. Run: pip install mitmproxy"
    exit 1
fi

# Check device connection
if ! adb devices | grep -q "device$"; then
    echo "[!] No device connected. Connect via USB and enable USB debugging."
    exit 1
fi

# Check root access
if ! adb shell su -c "id" 2>/dev/null | grep -q "uid=0"; then
    echo "[!] Device is not rooted or su access denied."
    echo "    Grant ADB shell superuser access in Magisk settings."
    exit 1
fi

echo "[+] All prerequisites met."
echo ""

# ── Step 1: Detect device architecture ───────────────────────────
echo "[*] Detecting device architecture..."
ARCH=$(adb shell getprop ro.product.cpu.abi)
echo "[+] Architecture: $ARCH"

case "$ARCH" in
    arm64-v8a) FRIDA_ARCH="arm64" ;;
    armeabi-v7a) FRIDA_ARCH="arm" ;;
    x86_64) FRIDA_ARCH="x86_64" ;;
    x86) FRIDA_ARCH="x86" ;;
    *) echo "[!] Unsupported architecture: $ARCH"; exit 1 ;;
esac

# ── Step 2: Download and push Frida server ───────────────────────
FRIDA_NAME="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_NAME}.xz"
# Rename to avoid string-based detection
DEVICE_BINARY="/data/local/tmp/hluda-server"

if adb shell su -c "test -f $DEVICE_BINARY && $DEVICE_BINARY --version" 2>/dev/null | grep -q "$FRIDA_VERSION"; then
    echo "[+] Frida server $FRIDA_VERSION already on device."
else
    echo "[*] Downloading Frida server $FRIDA_VERSION..."
    if [ ! -f "/tmp/${FRIDA_NAME}" ]; then
        curl -sL "$FRIDA_URL" -o "/tmp/${FRIDA_NAME}.xz"
        xz -d -f "/tmp/${FRIDA_NAME}.xz"
    fi

    echo "[*] Pushing Frida server to device (renamed to hluda-server)..."
    adb push "/tmp/${FRIDA_NAME}" "$DEVICE_BINARY"
    adb shell su -c "chmod 755 $DEVICE_BINARY"
    echo "[+] Frida server installed."
fi

# ── Step 3: Push SSL bypass script ───────────────────────────────
echo "[*] Pushing SSL bypass script..."
adb push "$SCRIPT" /data/local/tmp/android_ssl_bypass.js
echo "[+] Script pushed."

# ── Step 4: Install mitmproxy CA as system certificate ───────────
echo ""
echo "[*] Installing mitmproxy CA as system certificate..."

MITM_CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [ ! -f "$MITM_CERT" ]; then
    echo "[*] Generating mitmproxy CA cert (first run)..."
    mitmdump --listen-port 0 &
    MITM_PID=$!
    sleep 2
    kill $MITM_PID 2>/dev/null || true
fi

if [ -f "$MITM_CERT" ]; then
    # Get the hash for Android system cert store
    CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$MITM_CERT" 2>/dev/null | head -1)
    CERT_FILE="${CERT_HASH}.0"

    # Check if already installed
    if adb shell su -c "test -f /system/etc/security/cacerts/$CERT_FILE" 2>/dev/null; then
        echo "[+] mitmproxy CA already installed as system cert."
    else
        echo "[*] Pushing CA cert as $CERT_FILE..."
        cp "$MITM_CERT" "/tmp/$CERT_FILE"

        # Mount system as writable and push cert
        adb shell su -c "mount -o rw,remount /system" 2>/dev/null || \
        adb shell su -c "mount -o rw,remount /" 2>/dev/null || true

        adb push "/tmp/$CERT_FILE" "/data/local/tmp/$CERT_FILE"
        adb shell su -c "cp /data/local/tmp/$CERT_FILE /system/etc/security/cacerts/$CERT_FILE"
        adb shell su -c "chmod 644 /system/etc/security/cacerts/$CERT_FILE"
        adb shell su -c "chcon u:object_r:system_file:s0 /system/etc/security/cacerts/$CERT_FILE"

        echo "[+] CA cert installed. A reboot may be required."
        echo "    Alternative: install MagiskTrustUserCerts module to auto-promote user CAs."
        rm -f "/tmp/$CERT_FILE"
    fi
else
    echo "[!] mitmproxy CA cert not found at $MITM_CERT"
    echo "    Run 'mitmproxy' once to generate it, then re-run this script."
fi

# ── Step 5: Check Magisk modules ─────────────────────────────────
echo ""
echo "[*] Checking Magisk modules..."

MAGISK_MODULES=$(adb shell su -c "ls /data/adb/modules/ 2>/dev/null" || echo "")
echo "    Installed modules: $MAGISK_MODULES"

if ! echo "$MAGISK_MODULES" | grep -qi "playintegrity\|pif"; then
    echo ""
    echo "[!] Play Integrity Fix module NOT detected."
    echo "    Install it from: https://github.com/chiteroman/PlayIntegrityFix/releases"
    echo "    Download the .zip → open Magisk → Modules → Install from storage"
fi

if ! echo "$MAGISK_MODULES" | grep -qi "shamiko\|zygisk"; then
    echo ""
    echo "[!] Shamiko/Zygisk module NOT detected."
    echo "    For best root hiding, install Shamiko from:"
    echo "    https://github.com/LSPosed/LSPosed.github.io/releases"
fi

# ── Step 6: Configure DenyList ────────────────────────────────────
echo ""
echo "[*] Configuring Magisk DenyList for Uber..."
adb shell su -c "magisk --denylist add com.ubercab.driver" 2>/dev/null || \
    echo "    [!] Could not auto-configure DenyList. Add manually:"
echo "    Magisk → Settings → Enable Zygisk → Configure DenyList → add com.ubercab.driver"

# ── Step 7: Check Uber is installed from Play Store ──────────────
echo ""
echo "[*] Checking Uber Driver installation..."
UBER_INSTALLER=$(adb shell pm list packages -i 2>/dev/null | grep "com.ubercab.driver" || echo "")

if echo "$UBER_INSTALLER" | grep -q "com.ubercab.driver"; then
    if echo "$UBER_INSTALLER" | grep -q "com.android.vending"; then
        echo "[+] Uber Driver installed from Play Store — Play Integrity will pass."
    else
        echo "[!] Uber Driver installed but NOT from Play Store."
        echo "    For valid Play Integrity, uninstall and reinstall from Play Store:"
        echo "    adb uninstall com.ubercab.driver"
        echo "    Then install from Play Store on the device."
    fi
else
    echo "[!] Uber Driver not installed."
    echo "    Install from Play Store on the device before proceeding."
fi

echo ""
echo "============================================================"
echo " Setup Complete — Run Commands"
echo "============================================================"
echo ""
echo "STEP 1: Kill Frida server if already running"
echo "  adb shell su -c 'pkill -f hluda-server' 2>/dev/null"
echo ""
echo "STEP 2: Start Frida server on device (in background)"
echo "  adb shell su -c '/data/local/tmp/hluda-server -l 0.0.0.0:1337 &'"
echo ""
echo "STEP 3: Start mitmproxy on this PC"
echo "  mitmdump --listen-port $PROXY_PORT --set hardump=./uber_capture.har \\"
echo "    \"~d uber.com | ~d oojoovae.org | ~d uberinternal.com\""
echo ""
echo "STEP 4: Set device proxy to this PC"
echo "  adb shell settings put global http_proxy \$(hostname -I | awk '{print \$1}'):$PROXY_PORT"
echo ""
echo "STEP 5: Launch Uber with SSL bypass"
echo "  frida -H 127.0.0.1:1337 -f com.ubercab.driver \\"
echo "    -l scripts/android_ssl_bypass.js --no-pause"
echo ""
echo "STEP 6: When done, clean up"
echo "  adb shell settings put global http_proxy :0"
echo "  adb shell su -c 'pkill -f hluda-server'"
echo ""
echo "============================================================"
echo " What's different from the patched APK approach:"
echo "============================================================"
echo "  - Original Uber APK from Play Store (not re-signed)"
echo "  - Play Integrity passes (real app + real device + hidden root)"
echo "  - Frida server runs as root (no gadget injection)"
echo "  - SSL bypass script loaded at spawn time via frida CLI"
echo "  - CA cert is system-level (trusted by all apps)"
echo "  - Payout/deposit endpoints should work (valid attestation)"
echo ""
echo " TROUBLESHOOTING:"
echo "  - If frida can't connect: check adb forward or use USB mode"
echo "    frida -U -f com.ubercab.driver -l scripts/android_ssl_bypass.js --no-pause"
echo "  - If Play Integrity fails: check PIF module version, clear GMS cache"
echo "    adb shell su -c 'pm clear com.google.android.gms'"
echo "  - If app detects root: ensure DenyList has com.ubercab.driver"
echo "  - If Frida detected: server is renamed hluda-server, but also check"
echo "    that port 1337 isn't being scanned. Use USB mode (-U) instead."
echo ""
