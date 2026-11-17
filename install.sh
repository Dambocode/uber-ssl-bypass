#!/bin/bash
# Install patched Uber Driver with SSL bypass + Frida gadget
# Run from the uber-ssl-bypass directory

set -e

SPLITS_DIR="apk/patched/splits"
SCRIPT="scripts/android_ssl_bypass.js"

echo "============================================================"
echo " Uber Driver SSL Pinning Bypass — Installer"
echo "============================================================"
echo ""

echo "[*] Uninstalling existing Uber Driver..."
adb uninstall com.ubercab.driver 2>/dev/null || true

echo "[*] Pushing SSL bypass script to device..."
adb push "$SCRIPT" /data/local/tmp/android_ssl_bypass.js

echo "[*] Installing patched APK splits..."
adb install-multiple \
    "$SPLITS_DIR/base.apk" \
    "$SPLITS_DIR/config.arm64_v8a.apk" \
    "$SPLITS_DIR/config.xxxhdpi.apk" \
    "$SPLITS_DIR/BarcodeScanner.apk" \
    "$SPLITS_DIR/BarcodeScanner.config.arm64_v8a.apk"

echo ""
echo "============================================================"
echo " Setup Instructions"
echo "============================================================"
echo ""
echo "STEP 1: Install mitmproxy CA certificate on the device"
echo "  - Export cert: cp ~/.mitmproxy/mitmproxy-ca-cert.cer /tmp/"
echo "  - Push to device: adb push /tmp/mitmproxy-ca-cert.cer /sdcard/"
echo "  - On device: Settings > Security > Encryption > Install from storage"
echo "  - Select the .cer file and install as CA certificate"
echo ""
echo "STEP 2: Start mitmproxy on your computer"
echo "  mitmdump --listen-port 8080 --set hardump=./uber_capture.har"
echo ""
echo "STEP 3: Configure device proxy (replace YOUR_IP with your computer's LAN IP)"
echo "  adb shell settings put global http_proxy YOUR_IP:8080"
echo ""
echo "STEP 4: Launch Uber Driver on the device"
echo "  - The Frida gadget auto-loads the bypass script"
echo "  - Watch the logcat for [SSL] and [HIDE] messages:"
echo "    adb logcat -s Frida"
echo ""
echo "STEP 5: Capture traffic! Check uber_capture.har"
echo ""
echo "STEP 6: When done, clear the proxy:"
echo "  adb shell settings put global http_proxy :0"
echo ""
echo "============================================================"
echo " What the bypass does:"
echo "============================================================"
echo "  - QUIC/HTTP3 DISABLED: forces all traffic to TCP/TLS"
echo "  - Cronet proxy bypass blocked: connections go through proxy"
echo "  - Cronet BoringSSL verification: set to ssl_verify_ok"
echo "  - OkHttp CertificatePinner: check() returns void"
echo "  - GrpcSSLSocketFactory: certificate chain check bypassed"
echo "  - TrustManager: replaced with TrustAll"
echo "  - Conscrypt: verifyChain returns untrusted chain"
echo "  - Anti-detection: /proc/self/maps filtered, dl_iterate_phdr"
echo "    wrapped, root/debug checks spoofed, SeBridge monitored"
echo ""
echo " TROUBLESHOOTING:"
echo "  - If app crashes immediately: check adb logcat for Frida errors"
echo "  - If no traffic captured: ensure QUIC is disabled (look for"
echo "    '[SSL] QUIC DISABLED' in logcat)"
echo "  - If some traffic missing: gRPC may use a separate channel —"
echo "    check for '[SSL] GrpcSSLSocketFactory' in logcat"
echo "  - To view Frida output: adb logcat | grep -E '\[(SSL|HIDE|NET|SE)\]'"
