# Uber Driver SSL Bypass — Usage

## What Was Done
The Uber Driver APK (v4.605.10002) was decompiled, patched, and rebuilt with comprehensive SSL pinning bypass:

### Layer 1: APK Patches (static, built into the APK)
- **network_security_config.xml** replaced with `nsc_mitm.xml` — trusts user-installed CAs and allows cleartext
- **3 HostnameVerifier** instances patched in smali (javax.net.ssl)
- **AndroidManifest.xml** — `debuggable=true`, `extractNativeLibs=true`

### Layer 2: Frida Gadget (native SSL bypass at runtime)
- **libfrida-gadget.so** (v17.7.3) injected into `lib/arm64-v8a/`
- Application class `CarbonSingleBinaryApplication` modified to load gadget via `System.loadLibrary("frida-gadget")`
- Gadget auto-loads `android_ssl_bypass.js` from `/data/local/tmp/`

### Layer 3: Frida Script (`scripts/android_ssl_bypass.js`)
Comprehensive runtime hooks targeting:
- **Cronet BoringSSL** (native): `SSL_CTX_set_custom_verify`, `SSL_set_custom_verify`, `SSL_CTX_set_verify`, `SSL_set_verify` — the CRITICAL hooks, since Uber uses Cronet (`libcronet.129.0.6668.102.so`) for networking
- **OkHttp3** CertificatePinner.check
- **SSLContext.init** — TrustAll TrustManager injection
- **HostnameVerifier** bypass
- **Conscrypt** TrustManagerImpl.verifyChain
- **Cronet Java** — CronetEngine.Builder.addPublicKeyPinning
- **WebView** SSL error bypass
- **dlopen hook** — catches Cronet library load if it happens after script init

## Key Finding: Uber Uses Cronet
Uber Driver bundles `libcronet.129.0.6668.102.so` — Chromium's networking stack with embedded BoringSSL.
SSL pinning happens inside Cronet's native code, NOT through Java OkHttp.
This means Java-layer-only patching (apk-mitm alone) is **insufficient** — the Frida native hooks are essential.

## Files
```
apk/com.ubercab.driver.xapk              — Original XAPK from APKPure
apk/patched/splits/base.apk              — Patched base APK (SSL bypass + Frida gadget)
apk/patched/splits/config.arm64_v8a.apk  — Native libs split (re-signed)
apk/patched/splits/config.xxxhdpi.apk    — Resources split (re-signed)
apk/patched/splits/BarcodeScanner.apk    — Feature split (re-signed)
apk/patched/splits/BarcodeScanner.config.arm64_v8a.apk — Feature native split (re-signed)
scripts/android_ssl_bypass.js             — Frida SSL bypass script
scripts/frida-gadget-config.json          — Gadget auto-load config
gadget/                                   — Frida gadget binary
install.sh                                — One-command installation script
```

## Installation

### Prerequisites
- ADB connected to your Android device (Pixel, arm64-v8a)
- mitmproxy installed (`pip install mitmproxy`)
- Device has mitmproxy CA certificate installed

### Quick Install
```bash
cd uber-ssl-bypass
bash install.sh
```

### Manual Install
```bash
# 1. Uninstall existing Uber Driver
adb uninstall com.ubercab.driver

# 2. Push the bypass script to device
adb push scripts/android_ssl_bypass.js /data/local/tmp/

# 3. Install all split APKs
adb install-multiple \
    apk/patched/splits/base.apk \
    apk/patched/splits/config.arm64_v8a.apk \
    apk/patched/splits/config.xxxhdpi.apk \
    apk/patched/splits/BarcodeScanner.apk \
    apk/patched/splits/BarcodeScanner.config.arm64_v8a.apk
```

## Capturing Traffic

```bash
# 1. Start mitmproxy with HAR capture
mitmdump --listen-port 8080 --set hardump=./uber_capture.har

# 2. Set device proxy to your computer's IP
adb shell settings put global http_proxy <YOUR_IP>:8080

# 3. Launch Uber Driver on device
#    Frida gadget loads automatically and hooks all SSL verification

# 4. Use the app — traffic will flow through mitmproxy

# 5. When done, clear the proxy
adb shell settings put global http_proxy :0
```

## Installing mitmproxy CA Certificate
```bash
# Get the cert
# On first run, mitmproxy generates certs at ~/.mitmproxy/
mitmdump  # start once, then Ctrl+C

# Push to device and install
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
# Then on device: Settings > Security > Install from storage > select the cert
```

## Troubleshooting

### App crashes on launch
- Check logcat: `adb logcat -s "Frida" "SSL" "frida-gadget"`
- Ensure `android_ssl_bypass.js` exists at `/data/local/tmp/`
- The gadget config expects the script at that exact path

### Frida gadget not loading
- Verify `extractNativeLibs` is `true` in the manifest
- Check: `adb shell "ls -la /data/app/*/com.ubercab.driver*/lib/arm64/"`

### Still seeing SSL errors in mitmproxy
- The Cronet hooks are the critical ones — check logcat for `[SSL] Cronet` messages
- If Cronet loads after the gadget, the dlopen hook should catch it
- Try: `adb shell settings put global http_proxy :0` then re-set it

### Play Integrity / SafetyNet failures
- These are separate from SSL pinning — the app may detect it's been modified
- The app should still make network requests even if integrity checks fail
- SSL bypass works independently of integrity verification
