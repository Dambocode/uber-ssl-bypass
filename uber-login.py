#!/usr/bin/env python3
"""
Uber Driver login test using curl_cffi (browser-grade TLS fingerprint).
Bypasses bot detection by impersonating a real browser's TLS handshake.

Usage:
  pip install curl_cffi
  python3 uber-login.py
"""

import json
import re
import sys
import time
from urllib.parse import urlencode, urlparse, parse_qs

try:
    from curl_cffi.requests import Session
    ENGINE = "curl_cffi"
except ImportError:
    try:
        import tls_client
        ENGINE = "tls_client"
    except ImportError:
        print("[!] Install one of: pip install curl_cffi  OR  pip install tls-client")
        sys.exit(1)


UBER_AUTH_URL = "https://auth.uber.com"
UBER_DRIVERS_URL = "https://drivers.uber.com"


def create_session():
    """Create a session with browser-like TLS fingerprint."""
    if ENGINE == "curl_cffi":
        s = Session(impersonate="chrome120")
        s.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        })
        return s
    else:
        s = tls_client.Session(
            client_identifier="chrome_120",
            random_tls_extension_order=True,
        )
        s.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }
        return s


def step1_load_auth_page(session):
    """Load the Uber auth page to get initial cookies and CSRF token."""
    print("\n[1] Loading auth page...")

    resp = session.get(f"{UBER_AUTH_URL}/v2/", allow_redirects=True)
    print(f"    Status: {resp.status_code}")
    print(f"    URL: {resp.url}")

    cookies = dict(resp.cookies) if ENGINE == "curl_cffi" else session.cookies.get_dict()
    print(f"    Cookies received: {list(cookies.keys())}")

    csrf = None
    # Look for CSRF token in page
    csrf_match = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', resp.text)
    if csrf_match:
        csrf = csrf_match.group(1)
        print(f"    CSRF token: {csrf[:20]}...")

    # Look for x-csrf-token in cookies
    if "x-csrf-token" in cookies:
        csrf = cookies["x-csrf-token"]
        print(f"    CSRF from cookie: {csrf[:20]}...")

    # Also check for state token
    state_match = re.search(r'"stateToken"\s*:\s*"([^"]+)"', resp.text)
    state = state_match.group(1) if state_match else None
    if state:
        print(f"    State token: {state[:20]}...")

    # Check for any interesting JSON config in the page
    config_match = re.search(r'window\.__STORE__\s*=\s*({.*?});\s*</script>', resp.text, re.DOTALL)
    if config_match:
        try:
            config = json.loads(config_match.group(1))
            print(f"    Found __STORE__ config with keys: {list(config.keys())[:10]}")
        except json.JSONDecodeError:
            pass

    # Save the full page for debugging
    with open("cookie-dump/auth_page.html", "w", encoding="utf-8") as f:
        f.write(resp.text)
    print("    Saved auth page to cookie-dump/auth_page.html")

    return csrf, state, resp


def step2_submit_phone(session, phone_number, csrf=None, state=None):
    """Submit phone number to start login flow."""
    print(f"\n[2] Submitting phone number: {phone_number}")

    headers = {
        "Content-Type": "application/json",
        "Origin": UBER_AUTH_URL,
        "Referer": f"{UBER_AUTH_URL}/v2/",
        "x-csrf-token": csrf or "",
    }

    # Uber uses several possible endpoints for the initial auth step
    endpoints = [
        "/v2/api/authenticate",
        "/v1/auth/authenticate",
        "/api/v2/authenticate",
    ]

    payload = {
        "phoneNumber": phone_number,
        "countryCode": "US",
        "answerType": "PHONE_NUMBER_SUBMIT",
    }
    if state:
        payload["stateToken"] = state

    for endpoint in endpoints:
        url = f"{UBER_AUTH_URL}{endpoint}"
        print(f"    Trying: {url}")

        try:
            resp = session.post(url, json=payload, headers=headers, allow_redirects=False)
            print(f"    Status: {resp.status_code}")

            if resp.status_code == 404:
                continue

            try:
                data = resp.json()
                print(f"    Response: {json.dumps(data, indent=2)[:500]}")
                return data, resp
            except (json.JSONDecodeError, ValueError):
                print(f"    Response (text): {resp.text[:300]}")
                if resp.status_code in (301, 302):
                    print(f"    Redirect to: {resp.headers.get('Location', 'unknown')}")
                return None, resp

        except Exception as e:
            print(f"    Error: {e}")
            continue

    print("    [!] All auth endpoints failed")
    return None, None


def step3_submit_otp(session, otp_code, csrf=None, state=None):
    """Submit OTP code for verification."""
    print(f"\n[3] Submitting OTP: {otp_code}")

    headers = {
        "Content-Type": "application/json",
        "Origin": UBER_AUTH_URL,
        "Referer": f"{UBER_AUTH_URL}/v2/",
        "x-csrf-token": csrf or "",
    }

    payload = {
        "otpValue": otp_code,
        "answerType": "OTP_SUBMIT",
    }
    if state:
        payload["stateToken"] = state

    url = f"{UBER_AUTH_URL}/v2/api/authenticate"
    resp = session.post(url, json=payload, headers=headers, allow_redirects=False)
    print(f"    Status: {resp.status_code}")

    try:
        data = resp.json()
        print(f"    Response: {json.dumps(data, indent=2)[:500]}")
        return data, resp
    except (json.JSONDecodeError, ValueError):
        print(f"    Response: {resp.text[:300]}")
        return None, resp


def step4_test_authenticated(session):
    """Test if we're authenticated by hitting driver endpoints."""
    print("\n[4] Testing authenticated access...")

    test_urls = [
        f"{UBER_DRIVERS_URL}/earnings/webview/",
        "https://partners.uber.com/p3/payments/cartop",
        "https://payments.uber.com/",
    ]

    for url in test_urls:
        try:
            resp = session.get(url, allow_redirects=False)
            print(f"    {url}")
            print(f"      Status: {resp.status_code}")
            if resp.status_code in (301, 302):
                loc = resp.headers.get("Location", "")
                print(f"      Redirect: {loc[:100]}")
                if "auth.uber.com" in loc:
                    print("      → Not authenticated (redirected to login)")
                else:
                    print("      → Possible auth success!")
            elif resp.status_code == 200:
                print(f"      → Got 200! Page length: {len(resp.text)}")
                if "login" in resp.text.lower()[:500]:
                    print("      → But page contains login form")
                else:
                    print("      → Looks authenticated!")
        except Exception as e:
            print(f"      Error: {e}")

    # Dump final cookies
    if ENGINE == "curl_cffi":
        cookies = dict(session.cookies)
    else:
        cookies = session.cookies.get_dict()

    print(f"\n    Final cookies: {list(cookies.keys())}")
    with open("cookie-dump/session_cookies.json", "w") as f:
        json.dump(cookies, f, indent=2)
    print("    Saved to cookie-dump/session_cookies.json")


def dump_cookies_for_curl(session):
    """Export cookies in Netscape format for curl."""
    if ENGINE == "curl_cffi":
        cookies = session.cookies
    else:
        cookies = session.cookies

    with open("cookie-dump/curl_cookies.txt", "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for cookie in cookies.jar:
            secure = "TRUE" if cookie.secure else "FALSE"
            domain_dot = "TRUE" if cookie.domain.startswith(".") else "FALSE"
            expires = str(int(cookie.expires)) if cookie.expires else "0"
            f.write(f"{cookie.domain}\t{domain_dot}\t{cookie.path}\t{secure}\t{expires}\t{cookie.name}\t{cookie.value}\n")

    print("\n[+] Cookies exported to cookie-dump/curl_cookies.txt")
    print("    Test with: curl -b cookie-dump/curl_cookies.txt https://drivers.uber.com/earnings/webview/")


def main():
    import os
    os.makedirs("cookie-dump", exist_ok=True)

    print("=" * 50)
    print(" Uber Driver Login Test")
    print(f" Engine: {ENGINE}")
    print("=" * 50)

    session = create_session()

    # Step 1: Load auth page
    csrf, state, resp = step1_load_auth_page(session)

    if resp is None or resp.status_code >= 400:
        print("\n[!] Failed to load auth page. Uber may be blocking.")
        print("    Try running from a residential IP or VPN.")
        return

    # Step 2: Submit phone number
    phone = input("\nEnter phone number (e.g. +15551234567): ").strip()
    if not phone:
        print("[!] No phone number entered")
        return

    data, resp = step2_submit_phone(session, phone, csrf, state)

    if data and isinstance(data, dict):
        # Update state token if returned
        new_state = data.get("stateToken") or data.get("data", {}).get("stateToken")
        if new_state:
            state = new_state
            print(f"    Updated state token: {state[:20]}...")

        next_step = data.get("nextStep") or data.get("data", {}).get("nextStep")
        if next_step:
            print(f"    Next step: {next_step}")

    # Step 3: OTP
    otp = input("\nEnter OTP code sent to your phone: ").strip()
    if otp:
        data, resp = step3_submit_otp(session, otp, csrf, state)

        if data and isinstance(data, dict):
            new_state = data.get("stateToken") or data.get("data", {}).get("stateToken")
            if new_state:
                state = new_state

    # Step 4: Test access
    step4_test_authenticated(session)

    # Export cookies
    try:
        dump_cookies_for_curl(session)
    except Exception as e:
        print(f"\n[!] Cookie export error: {e}")


if __name__ == "__main__":
    main()
