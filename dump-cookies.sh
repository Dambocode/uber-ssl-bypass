#!/bin/bash
# dump-cookies.sh — Extract Uber Driver cookies from rooted device
# Then open payment webviews in your browser using those cookies
#
# Usage: bash dump-cookies.sh

echo "============================================"
echo " Uber Driver Cookie Dumper"
echo "============================================"
echo ""

# Check device
if ! adb devices 2>/dev/null | grep -q "device$"; then
    echo "[!] No device connected"
    exit 1
fi

if ! adb shell su -c "id" 2>/dev/null | grep -q "uid=0"; then
    echo "[!] Root access required"
    exit 1
fi

echo "[+] Device connected with root"
echo ""

DUMP_DIR="./cookie-dump"
mkdir -p "$DUMP_DIR"

# ── 1. Dump WebView cookies (SQLite database) ──────────────────
echo "--- WebView Cookies ---"

# WebView cookie database locations
COOKIE_PATHS=(
    "/data/data/com.ubercab.driver/app_webview/Default/Cookies"
    "/data/data/com.ubercab.driver/app_webview/Cookies"
    "/data/data/com.ubercab.driver/databases/webview.db"
    "/data/data/com.ubercab.driver/databases/webviewCookiesChromium.db"
)

COOKIE_DB=""
for path in "${COOKIE_PATHS[@]}"; do
    if adb shell su -c "test -f '$path' && echo yes" 2>/dev/null | grep -q "yes"; then
        echo "[+] Found cookie DB: $path"
        COOKIE_DB="$path"
        adb shell su -c "cp '$path' /data/local/tmp/uber_cookies.db" 2>/dev/null
        adb shell su -c "chmod 644 /data/local/tmp/uber_cookies.db" 2>/dev/null
        adb pull /data/local/tmp/uber_cookies.db "$DUMP_DIR/webview_cookies.db" 2>/dev/null
        break
    fi
done

if [ -z "$COOKIE_DB" ]; then
    echo "[!] No WebView cookie database found — trying broader search..."
    adb shell su -c "find /data/data/com.ubercab.driver -name '*ookie*' -o -name '*cookie*' 2>/dev/null" | while read f; do
        echo "  Found: $f"
    done
fi

# ── 2. Dump SharedPreferences (tokens, session data) ──────────
echo ""
echo "--- SharedPreferences (auth tokens) ---"

PREFS_DIR="/data/data/com.ubercab.driver/shared_prefs"
adb shell su -c "ls '$PREFS_DIR/'" 2>/dev/null > "$DUMP_DIR/prefs_list.txt"

echo "[*] Found $(wc -l < "$DUMP_DIR/prefs_list.txt" | tr -d ' ') preference files"

# Pull interesting ones
for pref in "auth" "token" "session" "cookie" "login" "identity" "payment" "account" "user" "credential"; do
    MATCHES=$(grep -i "$pref" "$DUMP_DIR/prefs_list.txt" 2>/dev/null)
    if [ -n "$MATCHES" ]; then
        echo "[+] $pref-related prefs:"
        echo "$MATCHES" | while read f; do
            f=$(echo "$f" | tr -d '\r\n')
            echo "    → $f"
            adb shell su -c "cat '$PREFS_DIR/$f'" 2>/dev/null > "$DUMP_DIR/pref_${f}" 2>/dev/null
        done
    fi
done

# ── 3. Dump all cookies via SQLite on device ──────────────────
echo ""
echo "--- Extracting cookies from DB ---"

if [ -f "$DUMP_DIR/webview_cookies.db" ]; then
    # Try sqlite3 on device
    if adb shell su -c "which sqlite3" 2>/dev/null | grep -q "sqlite3"; then
        echo "[+] Using device sqlite3"
        adb shell su -c "sqlite3 /data/local/tmp/uber_cookies.db '.tables'" 2>/dev/null
        adb shell su -c "sqlite3 /data/local/tmp/uber_cookies.db 'SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly FROM cookies;'" 2>/dev/null > "$DUMP_DIR/cookies_raw.txt"
        echo "[+] Cookies dumped to $DUMP_DIR/cookies_raw.txt"
    else
        echo "[!] sqlite3 not on device — trying on PC"
        if command -v sqlite3 &>/dev/null; then
            sqlite3 "$DUMP_DIR/webview_cookies.db" ".tables" 2>/dev/null
            sqlite3 "$DUMP_DIR/webview_cookies.db" "SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly FROM cookies;" 2>/dev/null > "$DUMP_DIR/cookies_raw.txt"
            echo "[+] Cookies dumped to $DUMP_DIR/cookies_raw.txt"
        else
            echo "[!] sqlite3 not available — install it or use DB Browser for SQLite"
            echo "    Open $DUMP_DIR/webview_cookies.db in a SQLite viewer"
        fi
    fi
fi

# ── 4. Search for auth tokens in app data ─────────────────────
echo ""
echo "--- Searching for auth tokens ---"

# Check for token files
TOKEN_SEARCH=$(adb shell su -c "grep -rl 'token\|sid\|csid\|session' /data/data/com.ubercab.driver/shared_prefs/ 2>/dev/null" | head -10)
if [ -n "$TOKEN_SEARCH" ]; then
    echo "[+] Files containing tokens:"
    echo "$TOKEN_SEARCH" | while read f; do
        f=$(echo "$f" | tr -d '\r\n')
        echo "    $f"
    done
fi

# Look for the uber session token specifically
echo ""
echo "--- Looking for Uber session/SID ---"
adb shell su -c "grep -rh 'sid\|csid\|token\|Bearer\|x-uber' /data/data/com.ubercab.driver/shared_prefs/ 2>/dev/null" | grep -iE "sid|token|bearer|uber" | head -20 > "$DUMP_DIR/tokens_found.txt"

if [ -s "$DUMP_DIR/tokens_found.txt" ]; then
    echo "[+] Potential tokens found — saved to $DUMP_DIR/tokens_found.txt"
    echo "    (check this file for session IDs)"
else
    echo "[!] No tokens found in SharedPreferences"
fi

# ── 5. Check for the internal cookie jar ──────────────────────
echo ""
echo "--- Internal app databases ---"

adb shell su -c "find /data/data/com.ubercab.driver -name '*.db' -o -name '*.sqlite' 2>/dev/null" | while read f; do
    f=$(echo "$f" | tr -d '\r\n')
    SIZE=$(adb shell su -c "ls -l '$f'" 2>/dev/null | awk '{print $5}')
    echo "  $f ($SIZE bytes)"
done

# ── 6. Generate browser-ready cookie file ─────────────────────
echo ""
echo "--- Generating browser-importable cookies ---"

if [ -f "$DUMP_DIR/cookies_raw.txt" ] && [ -s "$DUMP_DIR/cookies_raw.txt" ]; then
    # Convert to Netscape cookie format (for curl, browser extensions)
    echo "# Netscape HTTP Cookie File" > "$DUMP_DIR/cookies.txt"
    while IFS='|' read -r host name value path expires secure httponly; do
        host=$(echo "$host" | tr -d ' ')
        name=$(echo "$name" | tr -d ' ')
        value=$(echo "$value" | tr -d ' ')
        path=$(echo "$path" | tr -d ' ')
        [ -z "$path" ] && path="/"
        flag="FALSE"
        [ "$secure" = "1" ] && flag="TRUE"
        httpflag="FALSE"
        [ "$httponly" = "1" ] && httpflag="TRUE"
        echo -e "${host}\tTRUE\t${path}\t${flag}\t${expires}\t${name}\t${value}" >> "$DUMP_DIR/cookies.txt"
    done < "$DUMP_DIR/cookies_raw.txt"

    echo "[+] Netscape cookie file: $DUMP_DIR/cookies.txt"
    echo ""
    echo "  Use with curl:"
    echo "    curl -b $DUMP_DIR/cookies.txt https://drivers.uber.com/earnings/webview/"
    echo ""
    echo "  Or import into browser with 'EditThisCookie' extension"
fi

# ── 7. Test webview URLs ──────────────────────────────────────
echo ""
echo "============================================"
echo " Webview URLs to test with these cookies"
echo "============================================"
echo ""
echo "  PAYMENT/BANKING:"
echo "    https://payments.uber.com/"
echo "    https://payments.uber.com/edit/"
echo "    https://payments.uber.com/payment-history"
echo "    https://earner-payments.uber.com/repayments"
echo "    https://partners.uber.com/p3/payments/cartop"
echo ""
echo "  EARNINGS:"
echo "    https://drivers.uber.com/earnings/webview/"
echo "    https://drivers.uber.com/earnings/trips/"
echo ""
echo "  PROFILE/ACCOUNT:"
echo "    https://drivers.uber.com/earner-profile/copilot"
echo "    https://account.uber.com"
echo ""
echo "  FINANCIAL PRODUCTS:"
echo "    https://finprod.uber.com/financing/"
echo "    https://finprod.uber.com/pcp/management"
echo ""
echo "============================================"
echo ""
echo "Files saved to: $DUMP_DIR/"
ls -la "$DUMP_DIR/" 2>/dev/null
echo ""
echo "Next steps:"
echo "  1. Check $DUMP_DIR/cookies_raw.txt for uber.com cookies"
echo "  2. Check $DUMP_DIR/tokens_found.txt for session tokens"
echo "  3. Import cookies into browser and visit URLs above"
echo "  4. Or use: curl -b $DUMP_DIR/cookies.txt <url>"
