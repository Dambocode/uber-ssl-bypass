# Uber Driver SSL Pinning Bypass

Full SSL pinning bypass for the Uber Driver app (`com.ubercab.driver` v4.603.10001) enabling reliable HTTPS traffic interception and HAR capture. Built for authorized security research and compliance logging.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Device Requirements](#device-requirements)
- [Bypass Script Coverage](#bypass-script-coverage)
- [Anti-Detection Bypass](#anti-detection-bypass)
- [Critical Findings](#critical-findings)
- [Uber API Domains](#uber-api-domains)
- [Target Flows: Auth & Payout](#target-flows-auth--payout)
- [Play Integrity & Request Attestation](#play-integrity--request-attestation)
- [Automation Options](#automation-options-if-play-integrity-is-enforced)
- [Installation](#installation)
- [Proxy & HAR Capture](#proxy--har-capture)
- [Troubleshooting](#troubleshooting)
- [File Structure](#file-structure)

---

## Overview

Uber Driver employs **5+ layers of SSL pinning** and **heavy anti-tampering detection** including two native security engines with hundreds of raw ARM64 syscalls. This project provides a patched APK with an embedded Frida gadget that:

1. **Disables all SSL certificate pinning** (OkHttp, Cronet/BoringSSL, gRPC, Conscrypt, TrustManager)
2. **Blocks QUIC/HTTP3** to force all traffic through TCP/TLS (interceptable by mitmproxy)
3. **Forces proxy compliance** (Cronet and OkHttp both ignore system proxy by default)
4. **Bypasses anti-detection** (/proc/self/maps, dl_iterate_phdr, root/debug/Frida detection)
5. **Captures HAR files** of all API traffic including auth, payouts, earnings, and gRPC

### How It Works

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Uber Driver  │───▶│  Frida Gadget │───▶│   SSL Bypass  │───▶│  mitmproxy   │
│  (patched)    │    │  (embedded)   │    │   Script      │    │  (HAR dump)  │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
       │                    │                    │                    │
       │  App starts        │  Loads script      │  Hooks 21+        │  Captures
       │  normally          │  automatically     │  categories       │  all HTTPS
       │                    │  (no port 27042)   │  before TLS init  │  traffic
```

---

## Architecture

The bypass uses **APK patching with Frida gadget injection** (no root required):

| Component | Description |
|-----------|-------------|
| **Patched base.apk** | `network_security_config.xml` trusts user CAs, `debuggable=true`, `extractNativeLibs=true`, `System.loadLibrary("frida-gadget")` injected into `CarbonSingleBinaryApplication` |
| **libfrida-gadget.so** | 24.8MB Frida gadget in `lib/arm64-v8a/`, loads in **script mode** (no TCP port 27042) |
| **libfrida-gadget.config.so** | Config pointing to `/data/local/tmp/android_ssl_bypass.js` with `on_change: reload` |
| **android_ssl_bypass.js** | 1275-line bypass script with 21+ hook categories |
| **Split APKs** | All 5 splits re-signed with matching V3 certificate |

### Why No Root?

The Frida gadget is embedded directly in the APK. When the app starts, `System.loadLibrary("frida-gadget")` runs before any app code, loading the bypass script automatically. No `frida-server`, no root, no port 27042.

---

## Device Requirements

| Device | Status | Notes |
|--------|--------|-------|
| **Any Android (no root)** | Recommended | Patched APK installs via `adb install-multiple` |
| **Rooted Android** | Also works | Can additionally use iptables for transparent proxy |
| **Android Emulator** | Possible | May fail Play Integrity checks for some features |

> **Note on Play Integrity:** Uber checks `MEETS_STRONG_INTEGRITY` for some features. The re-signed APK will fail this check. This is **orthogonal to SSL interception** — traffic capture works regardless, but some app features (e.g., going online as a driver) may be restricted. For full app functionality on a rooted device, use Magisk + Play Integrity Fix + DenyList.

---

## Bypass Script Coverage

The script (`scripts/android_ssl_bypass.js`) hooks **21+ categories** across 4 layers:

### SSL/TLS Pinning Bypass (18 hooks)

| Layer | Target | Bypass Method | Status |
|-------|--------|---------------|--------|
| Native | Cronet BoringSSL `SSL_CTX_set_custom_verify` | Replace callback → return `ssl_verify_ok` | Hooked |
| Native | Cronet BoringSSL `SSL_set_custom_verify` | Replace callback → return `ssl_verify_ok` | Hooked |
| Native | System `libssl.so` verify functions | `SSL_VERIFY_NONE` + callback override | Hooked |
| Native | UDP:443 socket blocking | `getsockopt(SO_TYPE)` → block SOCK_DGRAM to port 443 | Hooked |
| Java | OkHttp3 `CertificatePinner.check` | Both overloads return void + `Builder.add` blocked | Hooked |
| Java | `SSLContext.init` TrustAll injection | Custom TrustManager accepts all certificates | Hooked |
| Java | `HostnameVerifier` | Returns `true` for all hostnames | Hooked |
| Java | Conscrypt `TrustManagerImpl.verifyChain` | Returns unmodified chain without verification | Hooked |
| Java | Conscrypt `Platform.checkServerTrusted` | No-op (AbstractConscryptSocket overload) | Hooked |
| Java | WebView SSL errors | `onReceivedSslError` → `handler.proceed()` | Hooked |
| Cronet | `addPublicKeyPins` | Blocked on 3 builder classes | Hooked |
| Cronet | `enablePublicKeyPinningBypassForLocalTrustAnchors` | Forced to `true` | Hooked |
| Cronet | Uber's `C31135c` CronetClient builder | Clears pin lists, QUIC hints, forces QUIC off | Hooked |
| Cronet | `setExperimentalOptions` | Strips QUIC config from JSON | Hooked |
| gRPC | `GrpcSSLSocketFactory.m61188c` | Skips certificate chain validation | Hooked |
| gRPC | `C61912d.m38935a` (pin checker) | Returns `true` | Hooked |
| gRPC | `X509ExtendedTrustManager` (`ip7.C61915f`) | All 3 `checkServerTrusted` overloads + catch-all | Hooked |
| gRPC | `ProxyHostnameVerifier` | All `verify()` overloads return `true` | Hooked |
| Payment | 3DS `SSLSocketFactory` (`atd.p058e`) | Custom factory bypass | Hooked |

### QUIC/HTTP3 Blocking (4 layers)

QUIC uses UDP and **completely bypasses TCP-based proxies like mitmproxy**. The script blocks it at 4 levels:

1. **Java builder hooks** — `enableQuic(false)` on `ICronetEngineBuilder`, `ExperimentalCronetEngine$Builder`, `RequestContextConfigOptions$Builder`
2. **Uber config hook** — `C31135c$C31136a.m60618b()` clears pin lists + QUIC hint lists + forces QUIC off
3. **JSON stripping** — `setExperimentalOptions()` removes QUIC configuration from experimental options JSON
4. **Native UDP block** — `connect()` interceptor uses `getsockopt(SO_TYPE)` to detect and block UDP:443 connections with `ECONNREFUSED` errno

### Proxy Enforcement (2 hooks)

Uber's app **ignores system proxy settings** via two mechanisms:

| Bypass Target | Method |
|---------------|--------|
| `dn9.C39764a` (Custom ProxySelector) | Returns `Proxy.NO_PROXY` for all URIs → overridden to return `127.0.0.1:8080` |
| `CronetUrlRequestContext.openConnection` | Passes `Proxy.NO_PROXY` → proxy param replaced |

---

## Anti-Detection Bypass

Uber has **two native security engines** and multiple Java-layer checks:

### Native Security Engines

| Engine | Size | Syscalls | Technique |
|--------|------|----------|-----------|
| **libse.so** (SeBridge) | 666KB | 39 raw SVC | Direct ARM64 `SVC #0` instructions, JNI bridge via `SeBridge.m87595js()` |
| **libeef0.so** | 1.1MB | 425 raw SVC | XOR-obfuscated syscall numbers (MOVZ+MOVK → EOR → AND → ADD → SVC) |

### Detection Vectors & Bypasses

| Detection | Method | Bypass |
|-----------|--------|--------|
| `/proc/self/maps` scanning | `sg8.C101759o0` reads memory map to find injected libs | libc hooks (open/fopen/fgets/read) filter lines containing frida/gadget/xposed/substrate |
| `dl_iterate_phdr` | Enumerates loaded `.so` files via linker internals | Callback wrapper skips frida-gadget entries |
| `syscall()` wrapper | Intercepts raw openat/read/connect/faccessat | Filters sensitive paths + blocks port 27042 |
| `/proc/self/status` TracerPid | Reads `TracerPid` to detect debugger | Patches TracerPid to 0 in read buffer |
| `readlink` | Detects Frida pipe names | Filters Frida pipe paths |
| `__system_property_get` | Checks ro.debuggable, ro.build.tags | Spoofs: `ro.debuggable=0`, `ro.build.tags=release-keys` |
| `getmntent` | Detects Magisk overlay mounts | Filters Magisk mount entries |
| `fnmatch` | Pattern matching for frida/gadget | Returns `FNM_NOMATCH` for detection patterns |
| `File.exists()` | Root binary checks (su, busybox, magisk) | Uses native libc `access()` to avoid recursion |
| `PackageManager` | Queries for root/xposed packages | Returns empty list |
| `Build.TAGS` | Checks for `test-keys` | Returns `release-keys` |
| `Debug.isDebuggerConnected()` | Debugger detection | Returns `false` |
| SeBridge JNI monitoring | `m87595js` / `m87596j` calls | Monitors command IDs and return values |
| libeef0 IPC | `pipe2`/`sendto` for detection reporting | Intercepts IPC to prevent detection reports |

### Frida Gadget Stealth Configuration

```json
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/android_ssl_bypass.js",
    "on_change": "reload"
  }
}
```

**Script mode** means:
- No TCP port 27042 (classic Frida fingerprint)
- No `frida-server` process
- Script loads automatically at startup before security engine init
- `on_change: reload` allows live script updates without reinstalling

---

## Critical Findings

Deep analysis of the decompiled APK revealed **6 critical gaps** that would cause traffic to silently escape interception if not addressed:

### 1. QUIC/HTTP3 Enabled by Default
Uber's Cronet engine enables QUIC (UDP 443). Config in `an2.C3623m`: `networkProbeProtocol = "http3"`, hostname `cn-geo1.uber.com`. Builder `C31135c` calls `enableQuic(true)` and `addQuicHint(host, 443, 443)`. **Standard TCP-based mitmproxy cannot intercept QUIC.**

### 2. Cronet Ignores System Proxy
`CronetUrlRequestContext.openConnection()` passes `Proxy.NO_PROXY`. Even with `adb shell settings put global http_proxy`, Cronet goes direct.

### 3. GrpcSSLSocketFactory (Separate TLS Path)
`GrpcSSLSocketFactory` has its own `SSLContext`, certificate chain validation via `m61188c`, and pin checking via `C61912d.m38935a`. gRPC connections bypass ALL OkHttp/CertificatePinner hooks.

### 4. Custom ProxySelector (`dn9.C39764a`)
Returns `Proxy.NO_PROXY` for **all URIs**. OkHttp-based traffic (REST, WebSocket, LiveKit) bypasses the system proxy.

### 5. gRPC X509ExtendedTrustManager (`ip7.C61915f`)
gRPC uses `X509ExtendedTrustManager` subclass, not standard `X509TrustManager`. Standard TrustAll hooks miss it. All 3 `checkServerTrusted` overloads must be hooked.

### 6. Obfuscated Fallback Domain (`oojoovae.org`)
Uber hardcodes `cn-dc1.oojoovae.org` alongside `cn-geo1.uber.com` and `cn-dc1.uber.com`. Proxy domain filters must capture ALL domains.

### Third-Party SDK SSL (Minor Gaps)
These are caught by our generic `SSLContext.init` → TrustAll hook:
- **PayPal Magnes SDK** (`km9.C70284g`) — fraud detection calls only
- **Twilio Voice SDK** (`p818xf.C119337m`) — voice calling with hardcoded certs
- **3DS Payment** (`atd.p058e`) — payment verification flow only

---

## Uber API Domains

All domains that must be included in proxy filters:

| Domain | Purpose |
|--------|---------|
| `cn-geo1.uber.com` | Primary API (Ramen/gRPC, REST, static assets, network probes) |
| `cn-dc1.uber.com` | Secondary datacenter API |
| `cn-dc1.oojoovae.org` | Obfuscated fallback (anti-censorship/blocking) |
| `auth.uber.com` | Authentication, login, cookies (USL) |
| `accounts.uber.com` | Account management, security settings |
| `payments.uber.com` | 3DS payment verification |
| `earner-online.uber.com` | Earner trip layouts |
| `rewards.uber.com` | Loyalty program |
| `ui.uber.com` | Web UI preload |
| `myprivacy.uber.com` | Privacy center |

**mitmproxy filter:**
```
~d uber.com | ~d oojoovae.org | ~d uberinternal.com
```

---

## Target Flows: Auth & Payout

### Authentication Flow
The login flow uses Uber's OAuth2 system (`AuthUpdateGrant.OAuth`):
- **Domain:** `auth.uber.com`
- **Protocol:** HTTPS REST + gRPC
- **Token exchange:** Access token + refresh token + session ID + expiry
- **Cookies:** Session cookies set after successful auth
- **Key classes:** `AuthUpdateGrant.OAuth`, USL (Uber Secure Login)

### Direct Deposit / Payout Management
The payout flow for updating bank account / direct deposit:

| Operation | Key Class | Details |
|-----------|-----------|---------|
| **Set Direct Deposit** | `SetScheduledDisbursementPreferenceAction` | Sets which payment profile receives scheduled disbursements using `PaymentProfileSetAsDefault` with `DefaultType.DRIVER_DISBURSEMENT` and a `PaymentProfileUuid` |
| **Instant Pay / Cashout** | `CashOutActionFlow` | Handles immediate cashout requests |
| **Add Bank Account** | `BankAccountAddFlowPluginFactory` | Bank account add flow |
| **Bank Account Info** | `BankAccountDescriptor` | Bank account metadata/details |
| **List Payment Profiles** | `PaymentProfileUuid` lookups | Enumerates linked payment methods |

All payout operations go through the same OkHttp/Cronet/gRPC stack that the bypass script hooks — **no additional SSL layers on payment routes**.

### Server-Side Considerations

> **Important:** Two server-side checks may affect payout operations on a patched APK:

**Request Attestation (`RequestAttestor`):**
Uber signs sensitive API requests via `com.ubercab.presidio.security.request_signing` and `PlayIntegrityAttestor`. On a re-signed APK:
- `MEETS_APP_INTEGRITY` will fail (different signing certificate)
- `MEETS_DEVICE_INTEGRITY` passes on real hardware (Pixel), fails on emulator
- Server may reject payment-sensitive operations or allow with degraded trust
- **You'll see the attestation headers and server responses in the HAR regardless**

**Device Fingerprinting:**
`DynamicDeviceFingerprint`, `FraudDeviceData`, `DeviceUpsertContextData` collect device fingerprints. A patched APK may trigger elevated fraud scoring. This affects server-side decisions, not traffic capture.

### What You'll Capture in the HAR

- Login OAuth token exchange (access token, refresh token, session ID, expiry)
- All API calls to `cn-geo1.uber.com`, `cn-dc1.oojoovae.org`, `payments.uber.com`
- Disbursement preference change requests (`PaymentProfileUuid`, `DefaultType.DRIVER_DISBURSEMENT`)
- Bank account list/add/edit payloads (all protobuf-encoded)
- Request attestation headers (visible even if server rejects)
- 3DS payment verification flows

### Capturing the Complete Flow

```bash
# 1. Start mitmproxy with HAR export
mitmdump --listen-port 8080 \
  --set hardump=./uber_payout_capture.har \
  "~d uber.com | ~d oojoovae.org | ~d uberinternal.com"

# 2. Launch patched app → Log in (captures auth flow)
# 3. Navigate: Earnings → Payment Methods → Direct Deposit
# 4. Perform the bank account update
# 5. HAR file contains the complete request/response sequence
```

### Decoding Protobuf/gRPC Payloads

```bash
# Decode raw protobuf from HAR body
echo "<base64_body>" | base64 -d | protoc --decode_raw

# Or use blackboxprotobuf for structured decoding
pip install blackboxprotobuf

# Live gRPC decoding with mitmproxy addon
pip install mitmproxy-addon-grpc
```

### Recommended Test Strategy

1. **Start with the emulator** (`PentestSandbox`) — install patched APK, capture login flow, map payment endpoints
2. If payment endpoints work on emulator, you have everything
3. If blocked by attestation, **switch to the Pixel** — real device gives better integrity scores
4. If even Pixel is blocked on payment ops, you'll need Magisk (root + Zygisk) on a rootable device to pass Play Integrity with the original signed APK

---

## Play Integrity & Request Attestation

### How Uber's Attestation Works

Uber has an **OkHttp interceptor** (`C109104f`) and a **gRPC interceptor** (`C109095b`) that transparently add attestation headers to matching requests:

| Header | Purpose |
|--------|---------|
| `x-uber-sig` | Cryptographic signature (method + path + body hash + selected headers) |
| `x-uber-sig-params` | Signature algorithm/version (`a=<algo>;v=1`) |
| `x-uber-cit` | Client Integrity Token (from Google Play Integrity API) |
| `Repr-Digest` | SHA-256 hash of request body |

### Key Finding: Server-Driven Enforcement

The endpoint list is **NOT hardcoded** in the APK. It's pushed from Uber's server via remote config:

- **`rs_attested_endpoints`** (remote config param, default: `""` empty string) — comma-separated URL path patterns loaded from `mobile_security_mobile` category
- **`rs_enable_grpc_attestation`** — defaults to `false`
- **`rs_kill_switch`** — when `true`, disables ALL attestation (defaults to `false`)
- Pattern matching supports `{}`-style path templates (e.g., `/api/payments/{}/disburse`)

**The first HAR capture reveals the actual enforcement list** — look for the remote config response containing `rs_attested_endpoints`.

### Error Codes When Attestation Fails

The server returns `RequestIntegrityError` with these codes:

| Code | Meaning |
|------|---------|
| `NEEDS_ATTESTATION` | Endpoint requires attestation, none provided (auto-retried) |
| `SIGNATURE_INVALID` | `x-uber-sig` doesn't match |
| `TOKEN_INVALID` | `x-uber-cit` expired or malformed (auto-retried) |
| `INSUFFICIENT_APP_SCOPE` | App integrity failed (re-signed APK detected) |
| `INSUFFICIENT_DEVICE_SCOPE` | Device integrity failed (emulator/rooted) |
| `MISSING_DIGEST_HEADER` | `Repr-Digest` header missing |

### Impact on Patched APK

On a re-signed APK:
- `MEETS_APP_INTEGRITY` → **FAIL** (different signing certificate)
- `MEETS_DEVICE_INTEGRITY` → **PASS** on real Pixel, **FAIL** on emulator
- `MEETS_STRONG_INTEGRITY` → **FAIL** (requires Play Store install + stock bootloader)

The deposit switch action (`SetScheduledDisbursementPreferenceAction`) goes through native gRPC/OkHttp — if the server pushes it into `rs_attested_endpoints`, it will be gated.

---

## Automation Options (If Play Integrity Is Enforced)

If HAR capture reveals that payout endpoints require `x-uber-cit` and the server hard-rejects with `INSUFFICIENT_APP_SCOPE`, here are the options for automation:

### Option 1: In-Process Frida Automation (Recommended)

Make API calls **from inside the Uber app process** using Frida's `Java.perform()`. The app's own interceptors automatically attach valid attestation headers.

```
┌─────────────┐    ┌──────────────────┐    ┌──────────────┐
│ Your Server  │───▶│  Frida Script     │───▶│  Uber's Own   │
│ (sends cmd)  │    │  (inside app)     │    │  HTTP Client   │
└─────────────┘    └──────────────────┘    └──────────────┘
                          │                        │
                          │  Java.perform() calls  │  Interceptors add
                          │  OkHttp/gRPC directly  │  x-uber-cit auto
```

**Setup:**
- Rootable Android device (used Pixel 4a/5a, ~$100-150, unlockable bootloader)
- Magisk + Play Integrity Fix (passes all integrity checks)
- **Original** Uber Driver APK from Play Store (not patched — real signing key)
- Frida server (not gadget) running as root
- Automation script that exposes a local HTTP API and calls Uber's internal classes

**Why it works:** You never forge a token. The real app on a real device generates legitimate Play Integrity tokens. You programmatically trigger the same code paths as a user tap.

**Key classes for automation:**
```
SetScheduledDisbursementPreferenceAction  → switch direct deposit
PaymentProfileSetAsDefault                → set default payment profile
  - DefaultType.DRIVER_DISBURSEMENT       → disbursement type enum
  - PaymentProfileUuid                    → target bank account ID
CashOutActionFlow                         → instant pay / cashout
BankAccountAddFlowPluginFactory           → add bank account
BankAccountDescriptor                     → bank account metadata
```

### Option 2: Web Dashboard Automation (No Play Integrity)

Uber has web-based payment pages that use **cookie-based auth, no Play Integrity**:

| URL | Purpose |
|-----|---------|
| `drivers.uber.com/earnings/webview/` | Earnings viewing |
| `partners.uber.com/p3/payments/v2/trips/` | Trip payment details |
| `partners.uber.com/p3/payments/hcv-driver-fixed-schedule` | Payment scheduling |
| `partners.uber.com/p3/payments/quality-hub/breakdowns/` | Quality hub metrics |

> **Note:** `partners.uber.com` and `drivers.uber.com` are interchangeable — the app replaces one with the other. Both are in the trusted host list.

> **Important:** The decompiled APK only references *some* web URLs. The web dashboard may have additional pages for deposit management that aren't referenced in the mobile app. **Check `drivers.uber.com` in a browser first.**

The app uses `PaymentPresidioWebviewInteractor` to load payment pages in WebView with standard session cookies. If deposit switching exists on the web dashboard:

```python
# Automate with Playwright — no Play Integrity needed
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    # Login and navigate to payment settings
    page.goto("https://drivers.uber.com")
    # ... automate deposit switch
```

### Option 3: Uber Fleet/Partner API

No fleet-level payment management API was found in the decompiled APK. The "fleet" references are limited to `fleet_break_management` (driver break scheduling). If your compliance use case qualifies for Uber's partner program, inquire about API access directly.

### Decision Flowchart

```
1. Capture HAR with patched APK
   │
   ├─ Payout endpoints have NO x-uber-cit header?
   │  └─ ✅ Direct API calls with auth tokens — done
   │
   ├─ Payout endpoints have x-uber-cit but server returns 200?
   │  └─ ✅ Soft enforcement — direct API calls work — done
   │
   └─ Server returns INSUFFICIENT_APP_SCOPE / INSUFFICIENT_DEVICE_SCOPE?
      │
      ├─ Check drivers.uber.com for deposit management in browser
      │  └─ Found? → ✅ Playwright automation — done
      │
      └─ Not on web? → Option 1: Rooted device + original APK + Frida server
```

---

## Installation

### Prerequisites
- `adb` (Android Debug Bridge) installed
- `mitmproxy` installed (`pip install mitmproxy`)
- USB debugging enabled on device
- Device connected via USB

### Quick Start

```bash
# 1. Run the installer
chmod +x install.sh
./install.sh

# 2. Install mitmproxy CA certificate on device
cp ~/.mitmproxy/mitmproxy-ca-cert.cer /tmp/
adb push /tmp/mitmproxy-ca-cert.cer /sdcard/
# On device: Settings > Security > Encryption > Install from storage

# 3. Start mitmproxy
mitmdump --listen-port 8080 --set hardump=./uber_capture.har

# 4. Set device proxy
adb shell settings put global http_proxy <YOUR_COMPUTER_IP>:8080

# 5. Launch Uber Driver on the device
# Frida gadget auto-loads the bypass script

# 6. Monitor bypass output
adb logcat | grep -E '\[(SSL|HIDE|NET|SE)\]'

# 7. When done, clear proxy
adb shell settings put global http_proxy :0
```

### What install.sh Does

1. Uninstalls existing Uber Driver
2. Pushes `android_ssl_bypass.js` to `/data/local/tmp/`
3. Installs all 5 patched split APKs via `adb install-multiple`

### Split APKs

All signed with the same V3 certificate (SHA-256: `fd6daf53...56f0`):

| APK | Contents |
|-----|----------|
| `base.apk` (124MB) | Patched app with Frida gadget, modified network security config |
| `config.arm64_v8a.apk` | 16 native libs including libcronet, libse, libeef0 |
| `config.xxxhdpi.apk` | Display density resources |
| `BarcodeScanner.apk` | Barcode scanner feature module |
| `BarcodeScanner.config.arm64_v8a.apk` | Barcode scanner native libs |

---

## Proxy & HAR Capture

### mitmproxy (Recommended)

```bash
# Interactive web UI + HAR export
mitmweb --listen-port 8080 --set hardump=./uber_capture.har

# Headless with Uber-only domain filter
mitmdump --listen-port 8080 \
  --set hardump=./uber_capture.har \
  "~d uber.com | ~d uberinternal.com | ~d oojoovae.org"

# Save both lossless .mitm and .har
mitmdump --listen-port 8080 \
  --set hardump=./uber_capture.har \
  -w ./uber_capture.mitm \
  "~d uber.com | ~d uberinternal.com | ~d oojoovae.org"
```

### Custom Filter Addon

```python
# uber_filter.py — drop non-Uber traffic
from mitmproxy import http

UBER_DOMAINS = ["uber.com", "uberinternal.com", "oojoovae.org"]

def request(flow: http.HTTPFlow):
    if not any(flow.request.host.endswith(d) for d in UBER_DOMAINS):
        flow.kill()

# Run: mitmdump -s uber_filter.py --set hardump=./uber_only.har
```

### Handling Protobuf/gRPC

- **Protobuf bodies** are saved as base64 in HAR. Decode with `protoc --decode_raw`
- **gRPC** has a 5-byte frame header before each protobuf message
- Use `mitmproxy-addon-grpc` for live gRPC decoding
- Save `.mitm` files alongside `.har` for lossless WebSocket capture

### Convert Saved Flows to HAR

```bash
mitmdump -n -r uber_capture.mitm --set hardump=./uber_capture.har
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| App crashes on launch | Frida gadget error | Check `adb logcat -s Frida` for script errors |
| No traffic in proxy | QUIC still active | Look for `[SSL] QUIC DISABLED` in logcat; if missing, script didn't load |
| Some traffic missing | gRPC on separate channel | Check for `[SSL] GrpcSSLSocketFactory` in logcat |
| SSL handshake errors | CA cert not trusted | Reinstall mitmproxy CA cert; verify it appears in Settings > Security |
| App detects tampering | Anti-detection gaps | Check for `[HIDE]` messages; look for new detection vectors in logcat |
| Install fails | Signature mismatch | Ensure all 5 APKs are signed with same key; check with `apksigner verify` |
| Proxy not intercepting | Cronet bypass | Verify `[NET] ProxySelector` messages in logcat |
| App won't go online | Play Integrity fail | Expected with re-signed APK; traffic capture still works |

### Useful Logcat Commands

```bash
# All bypass output
adb logcat | grep -E '\[(SSL|HIDE|NET|SE)\]'

# SSL hooks only
adb logcat | grep '\[SSL\]'

# Anti-detection only
adb logcat | grep '\[HIDE\]'

# Frida gadget lifecycle
adb logcat -s Frida
```

---

## File Structure

```
uber-ssl-bypass/
├── README.md                          # This file
├── install.sh                         # One-command installer
├── debug-keystore.jks                 # Signing key (storepass: android)
├── scripts/
│   ├── android_ssl_bypass.js          # Core bypass script (1275 lines)
│   └── frida-gadget-config.json       # Gadget config (script mode)
├── apk/
│   ├── patched/
│   │   └── splits/
│   │       ├── base.apk              # Patched base (124MB, with Frida gadget)
│   │       ├── config.arm64_v8a.apk  # Native libraries
│   │       ├── config.xxxhdpi.apk    # Display resources
│   │       ├── BarcodeScanner.apk    # Feature module
│   │       └── BarcodeScanner.config.arm64_v8a.apk
│   └── jadx-output/                   # Decompiled source (for reference)
└── gadget/                            # Frida gadget binaries
```

---

## Legal & Authorization

This tool is for **authorized security research only**. Valid use cases:
- Uber's HackerOne bug bounty program ([uber.com/security](https://uber.com/security))
- Compliance logging for authorized fleet management services
- Personal traffic analysis of your own account

---

*Bypass script v4 | Uber Driver v4.603.10001 | 21+ hook categories | 1275 lines*
