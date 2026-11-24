"""
Uber Driver login via curl_cffi (browser-grade TLS fingerprint).
Interactive flow: phone -> OTP(s) -> session cookies.

Usage:
  python uber_login.py
"""
import json
import os
import re
import sys
import time
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
os.makedirs(COOKIE_DIR, exist_ok=True)


def make_session():
    s = Session(impersonate="chrome120")
    s.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    })
    return s


def get_cookies(session):
    return {c.name: c.value for c in session.cookies.jar}


def api_headers(csrf=None):
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://auth.uber.com",
        "Referer": "https://auth.uber.com/v2/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    if csrf:
        h["x-csrf-token"] = csrf
    return h


def submit_form(session, payload, csrf=None):
    url = "https://auth.uber.com/v2/silk-screen/submit-form"
    resp = session.post(url, json=payload, headers=api_headers(csrf), allow_redirects=False)

    new_csrf = resp.headers.get("x-csrf-token") or csrf

    if resp.status_code in (301, 302, 303):
        loc = resp.headers.get("Location", "")
        print(f"  Redirect: {loc[:120]}")
        if loc:
            full = loc if loc.startswith("http") else f"https://auth.uber.com{loc}"
            resp = session.get(full, allow_redirects=True)

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        data = {"_raw": resp.text[:1000], "_status": resp.status_code}

    return data, new_csrf, resp


def print_response(data, label="Response"):
    filtered = {k: v for k, v in data.items() if k not in ("_raw",)}
    text = json.dumps(filtered, indent=2)
    if len(text) > 1200:
        text = text[:1200] + "\n  ..."
    print(f"  {label}:\n{text}")


def detect_screen(data):
    for key in ("screenType", "nextScreenType", "screen"):
        if key in data:
            return data[key]
        if "data" in data and key in data.get("data", {}):
            return data["data"][key]
    return None


def detect_fields(data):
    for key in ("formFields", "fields"):
        if key in data:
            return data[key]
        if "data" in data and key in data.get("data", {}):
            return data["data"][key]
    return None


def test_endpoints(session):
    print("\n" + "=" * 50)
    print(" Testing authenticated access")
    print("=" * 50)

    cookies = get_cookies(session)
    auth_cookies = [n for n in cookies if any(k in n.lower() for k in ("sid", "token", "session", "auth", "csid"))]
    print(f"\n  Auth-related cookies: {auth_cookies}")

    urls = [
        ("https://drivers.uber.com/earnings/webview/", "Earnings"),
        ("https://payments.uber.com/", "Payments"),
        ("https://partners.uber.com/p3/payments/cartop", "Partner Payments"),
        ("https://account.uber.com/", "Account"),
    ]

    for url, label in urls:
        try:
            resp = session.get(url, allow_redirects=False)
            status = resp.status_code
            if status in (301, 302, 303):
                loc = resp.headers.get("Location", "")
                if "auth.uber.com" in loc:
                    print(f"  [{label}] {status} -> login redirect (not authed)")
                else:
                    print(f"  [{label}] {status} -> {loc[:80]}")
            elif status == 200:
                title_m = re.search(r"<title>(.*?)</title>", resp.text)
                title = title_m.group(1) if title_m else "(no title)"
                has_login = "login" in resp.text[:2000].lower() or "sign in" in resp.text[:2000].lower()
                if has_login:
                    print(f"  [{label}] 200 but contains login form - {title}")
                else:
                    print(f"  [{label}] 200 OK! Title: {title}")
                with open(os.path.join(COOKIE_DIR, f"{label.lower().replace(' ','_')}.html"), "w", encoding="utf-8") as f:
                    f.write(resp.text)
            else:
                print(f"  [{label}] HTTP {status}")
        except Exception as e:
            print(f"  [{label}] Error: {e}")

    # Export cookies
    with open(os.path.join(COOKIE_DIR, "cookies.txt"), "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for c in session.cookies.jar:
            secure = "TRUE" if c.secure else "FALSE"
            domain_dot = "TRUE" if c.domain.startswith(".") else "FALSE"
            expires = str(int(c.expires)) if c.expires else "0"
            f.write(f"{c.domain}\t{domain_dot}\t{c.path}\t{secure}\t{expires}\t{c.name}\t{c.value}\n")

    with open(os.path.join(COOKIE_DIR, "session.json"), "w") as f:
        json.dump(cookies, f, indent=2)

    print(f"\n  Cookies saved to {COOKIE_DIR}/cookies.txt")
    print(f"  Session saved to {COOKIE_DIR}/session.json")


def main():
    print("=" * 50)
    print(" Uber Driver Login (curl_cffi)")
    print("=" * 50)

    session = make_session()
    csrf = None

    # Step 1: Load auth page
    print("\n[1/4] Loading auth.uber.com ...")
    resp = session.get("https://auth.uber.com/v2/", allow_redirects=True)
    print(f"  Status: {resp.status_code}")
    cookies = get_cookies(session)
    print(f"  Cookies: {list(cookies.keys())}")

    for c in session.cookies.jar:
        if c.name == "x-csrf-token":
            csrf = c.value
    if not csrf:
        m = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', resp.text)
        if m:
            csrf = m.group(1)
    print(f"  CSRF: {'found' if csrf else 'none'}")

    # Step 2: Phone number
    print("\n[2/4] Phone number")
    phone = input("  Enter phone (e.g. +15551234567): ").strip()
    if not phone:
        print("  Aborted.")
        return

    payload = {
        "phoneNumber": phone,
        "screenType": "PHONE_NUMBER_INITIAL",
    }
    data, csrf, resp = submit_form(session, payload, csrf)
    print_response(data)

    screen = detect_screen(data)
    print(f"  Next screen: {screen}")

    # Step 3+: Handle MFA screens in a loop
    step = 3
    max_steps = 6
    while step <= max_steps:
        if screen is None:
            # Check if we're done (got redirected to app or got tokens)
            if data.get("_raw") and ("redirect" in data.get("_raw", "").lower() or resp.status_code == 200):
                print("\n  Auth flow may be complete.")
                break
            print("\n  [!] No next screen detected. Auth may have failed.")
            print("  Raw response saved. Continuing to test endpoints anyway...")
            break

        screen_lower = screen.lower() if screen else ""

        if any(k in screen_lower for k in ("phone_sms_otp", "phone_otp", "sms_otp", "inbound_sms")):
            print(f"\n[{step}/4] SMS OTP verification ({screen})")
            code = input("  Enter SMS code: ").strip()
            if not code:
                print("  Skipped.")
                break
            payload = {"otpValue": code, "screenType": screen}
            data, csrf, resp = submit_form(session, payload, csrf)
            print_response(data)
            screen = detect_screen(data)
            print(f"  Next screen: {screen}")

        elif any(k in screen_lower for k in ("email_otp", "email_verification")):
            print(f"\n[{step}/4] Email OTP verification ({screen})")
            code = input("  Enter email code: ").strip()
            if not code:
                print("  Skipped.")
                break
            payload = {"otpValue": code, "screenType": screen}
            data, csrf, resp = submit_form(session, payload, csrf)
            print_response(data)
            screen = detect_screen(data)
            print(f"  Next screen: {screen}")

        elif any(k in screen_lower for k in ("password", "identity_password", "email_password")):
            print(f"\n[{step}/4] Password required ({screen})")
            import getpass
            pwd = getpass.getpass("  Enter password: ")
            if not pwd:
                print("  Skipped.")
                break
            payload = {"password": pwd, "screenType": screen}
            data, csrf, resp = submit_form(session, payload, csrf)
            print_response(data)
            screen = detect_screen(data)
            print(f"  Next screen: {screen}")

        elif any(k in screen_lower for k in ("captcha", "challenge", "arkose")):
            print(f"\n  [!] CAPTCHA/challenge required: {screen}")
            print("  This can't be automated easily. Try from a browser.")
            break

        elif any(k in screen_lower for k in ("phone_whatsapp", "whatsapp")):
            print(f"\n[{step}/4] WhatsApp OTP ({screen})")
            code = input("  Enter WhatsApp code: ").strip()
            if not code:
                break
            payload = {"otpValue": code, "screenType": screen}
            data, csrf, resp = submit_form(session, payload, csrf)
            print_response(data)
            screen = detect_screen(data)

        elif any(k in screen_lower for k in ("voice_otp",)):
            print(f"\n[{step}/4] Voice OTP ({screen})")
            code = input("  Enter voice call code: ").strip()
            if not code:
                break
            payload = {"otpValue": code, "screenType": screen}
            data, csrf, resp = submit_form(session, payload, csrf)
            print_response(data)
            screen = detect_screen(data)

        else:
            print(f"\n  [?] Unknown screen: {screen}")
            print(f"  Fields: {detect_fields(data)}")
            user_input = input("  Enter value (or 'skip'): ").strip()
            if user_input == "skip" or not user_input:
                break
            payload = {"otpValue": user_input, "screenType": screen}
            data, csrf, resp = submit_form(session, payload, csrf)
            print_response(data)
            screen = detect_screen(data)

        step += 1

    # Final: test endpoints
    test_endpoints(session)


if __name__ == "__main__":
    main()
