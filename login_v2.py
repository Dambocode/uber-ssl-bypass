"""
Uber login v2 — handles Cloudflare + CSRF properly.
Retries with different fingerprints if blocked.
"""
import json, os, re, sys, time
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
STATE_FILE = os.path.join(COOKIE_DIR, "login_state.json")
os.makedirs(COOKIE_DIR, exist_ok=True)

BROWSERS = ["chrome146", "chrome136", "safari184", "edge101", "chrome124"]


def get_session_through_cf():
    """Try multiple fingerprints until one passes Cloudflare."""
    for browser in BROWSERS:
        s = Session(impersonate=browser)
        try:
            resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
            if resp.status_code == 200 and "Sign up" in resp.text[:5000]:
                print(f"  [+] {browser} passed CF (status {resp.status_code})")
                return s, resp
            else:
                print(f"  [-] {browser}: {resp.status_code}")
        except Exception as e:
            print(f"  [-] {browser}: {e}")
    return None, None


def extract_csrf(session, page_text):
    """Extract CSRF from cookies or page."""
    for c in session.cookies.jar:
        if "csrf" in c.name.lower():
            return c.value

    for pat in [r'"csrfToken"\s*:\s*"([^"]+)"', r'"x-csrf-token"\s*:\s*"([^"]+)"']:
        m = re.search(pat, page_text)
        if m:
            return m.group(1)

    # Uber often requires a CSRF that comes from a specific init call
    # Try fetching the CSRF via the init endpoint
    headers = {
        "Accept": "application/json",
        "Origin": "https://auth.uber.com",
        "Referer": "https://auth.uber.com/v2/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }

    # The CSRF token comes from the cookie set during page load
    # In Uber's SPA, the x-csrf-token header value is derived from the jwt-session
    for c in session.cookies.jar:
        if c.name == "jwt-session":
            # Try using jwt-session as csrf token (some implementations do this)
            return c.value

    return None


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_state():
    with open(STATE_FILE) as f:
        return json.load(f)


def get_cookies(session):
    return {c.name: c.value for c in session.cookies.jar}


def submit(session, payload, csrf):
    """Submit to silk-screen/submit-form with various CSRF approaches."""
    url = "https://auth.uber.com/v2/silk-screen/submit-form"

    # Try multiple CSRF header approaches
    csrf_headers = [
        {"x-csrf-token": csrf} if csrf else {},
        {"x-csrf-token": "x"},
        {},
    ]

    for i, csrf_h in enumerate(csrf_headers):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://auth.uber.com",
            "Referer": "https://auth.uber.com/v2/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            **csrf_h,
        }

        resp = session.post(url, json=payload, headers=headers, allow_redirects=False)

        if resp.status_code == 403 and "csrf" in resp.text.lower():
            print(f"  CSRF attempt {i+1} failed: {resp.text[:100]}")
            # Check if a new csrf cookie was set
            for c in session.cookies.jar:
                if "csrf" in c.name.lower():
                    csrf = c.value
                    print(f"  Got CSRF cookie: {c.name}")
            continue

        # Follow redirects
        if resp.status_code in (301, 302, 303):
            loc = resp.headers.get("Location", "")
            print(f"  Redirect -> {loc[:120]}")
            if loc:
                full = loc if loc.startswith("http") else f"https://auth.uber.com{loc}"
                resp = session.get(full, allow_redirects=True)

        try:
            data = resp.json()
        except:
            data = {"_raw": resp.text[:2000], "_status": resp.status_code}

        new_csrf = resp.headers.get("x-csrf-token") or csrf
        return data, new_csrf

    return {"error": "All CSRF attempts failed"}, csrf


def show(data):
    text = json.dumps(data, indent=2)
    if len(text) > 2000:
        text = text[:2000] + "\n..."
    print(text)
    screen = None
    for key in ("screenType", "nextScreenType"):
        if key in data:
            screen = data[key]
        elif isinstance(data.get("data"), dict) and key in data["data"]:
            screen = data["data"][key]
    if screen:
        print(f"\n  >>> Next screen: {screen}")
    return screen


def test_endpoints(session):
    print("\n" + "=" * 50)
    print(" Testing authenticated access")
    print("=" * 50)

    urls = [
        ("https://drivers.uber.com/earnings/webview/", "Earnings"),
        ("https://payments.uber.com/", "Payments"),
        ("https://partners.uber.com/p3/payments/cartop", "Partners"),
        ("https://account.uber.com/", "Account"),
    ]

    for url, label in urls:
        try:
            resp = session.get(url, allow_redirects=False)
            status = resp.status_code
            loc = resp.headers.get("Location", "")
            if status in (301, 302, 303):
                if "auth.uber.com" in loc:
                    print(f"  [{label}] -> login redirect (not authed)")
                else:
                    print(f"  [{label}] -> {status} {loc[:80]}")
            elif status == 200:
                title_m = re.search(r"<title>(.*?)</title>", resp.text[:2000])
                title = title_m.group(1) if title_m else ""
                print(f"  [{label}] -> 200 OK | {title[:60]}")
                with open(os.path.join(COOKIE_DIR, f"{label.lower()}.html"), "w", encoding="utf-8") as f:
                    f.write(resp.text)
            else:
                print(f"  [{label}] -> {status}")
        except Exception as e:
            print(f"  [{label}] -> Error: {e}")

    # Export
    cookies = get_cookies(session)
    with open(os.path.join(COOKIE_DIR, "session.json"), "w") as f:
        json.dump(cookies, f, indent=2)
    with open(os.path.join(COOKIE_DIR, "cookies.txt"), "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for c in session.cookies.jar:
            secure = "TRUE" if c.secure else "FALSE"
            domain_dot = "TRUE" if c.domain.startswith(".") else "FALSE"
            expires = str(int(c.expires)) if c.expires else "0"
            f.write(f"{c.domain}\t{domain_dot}\t{c.path}\t{secure}\t{expires}\t{c.name}\t{c.value}\n")
    print(f"\n  Session saved to {COOKIE_DIR}/")


# ── Commands ─────────────────────────────────────────────

def cmd_init():
    print("[init] Getting through Cloudflare...")
    session, resp = get_session_through_cf()
    if not session:
        print("[!] All browsers blocked by CF. Try again later or use VPN.")
        return

    cookies = get_cookies(session)
    print(f"  Cookies: {list(cookies.keys())}")

    csrf = extract_csrf(session, resp.text)
    print(f"  CSRF: {csrf[:40] + '...' if csrf else 'none'}")

    save_state({"cookies": cookies, "csrf": csrf, "step": "init", "browser": "chrome146"})
    print("[+] Ready. Next: python login_v2.py phone +19148744178")


def cmd_phone(phone):
    state = load_state()

    # Fresh session through CF
    print("[phone] Getting fresh session through CF...")
    session, resp = get_session_through_cf()
    if not session:
        print("[!] Blocked by CF")
        return

    csrf = extract_csrf(session, resp.text)
    print(f"  CSRF: {csrf[:40] + '...' if csrf else 'none'}")

    print(f"\n[phone] Submitting: {phone}")
    payload = {"phoneNumber": phone, "screenType": "PHONE_NUMBER_INITIAL"}
    data, csrf = submit(session, payload, csrf)

    screen = show(data)
    state.update({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": screen,
        "step": "phone",
        "last_response": data,
    })
    save_state(state)

    if screen:
        print(f"\n[+] Next: python login_v2.py otp <code>")
    else:
        print(f"\n[?] Check response above. May need different approach.")


def cmd_otp(code):
    state = load_state()
    session = Session(impersonate="chrome146")
    for name, val in state["cookies"].items():
        session.cookies.set(name, val, domain=".uber.com")

    screen = state.get("next_screen", "PHONE_SMS_OTP")
    print(f"[otp] Submitting code '{code}' for screen: {screen}")

    payload = {"otpValue": code, "screenType": screen}
    data, csrf = submit(session, payload, state.get("csrf"))

    new_screen = show(data)
    state.update({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": new_screen,
        "step": "otp",
        "last_response": data,
    })
    save_state(state)

    if new_screen and "otp" in new_screen.lower():
        print(f"\n[+] Another OTP! Run: python login_v2.py otp2 <code>")
    elif new_screen and "password" in new_screen.lower():
        print(f"\n[+] Password needed! Run: python login_v2.py password <pwd>")
    else:
        print(f"\n[+] Run: python login_v2.py test")


def cmd_otp2(code):
    state = load_state()
    session = Session(impersonate="chrome146")
    for name, val in state["cookies"].items():
        session.cookies.set(name, val, domain=".uber.com")

    screen = state.get("next_screen", "EMAIL_OTP")
    print(f"[otp2] Submitting code '{code}' for screen: {screen}")

    payload = {"otpValue": code, "screenType": screen}
    data, csrf = submit(session, payload, state.get("csrf"))

    new_screen = show(data)
    state.update({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": new_screen,
        "step": "otp2",
    })
    save_state(state)
    print(f"\n[+] Run: python login_v2.py test")


def cmd_password(pwd):
    state = load_state()
    session = Session(impersonate="chrome146")
    for name, val in state["cookies"].items():
        session.cookies.set(name, val, domain=".uber.com")

    screen = state.get("next_screen", "IDENTITY_PASSWORD")
    print(f"[password] Submitting for screen: {screen}")

    payload = {"password": pwd, "screenType": screen}
    data, csrf = submit(session, payload, state.get("csrf"))

    new_screen = show(data)
    state.update({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": new_screen,
        "step": "password",
    })
    save_state(state)
    print(f"\n[+] Run: python login_v2.py test")


def cmd_test():
    state = load_state()
    session = Session(impersonate="chrome146")
    for name, val in state["cookies"].items():
        session.cookies.set(name, val, domain=".uber.com")
    test_endpoints(session)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python login_v2.py init")
        print("  python login_v2.py phone +19148744178")
        print("  python login_v2.py otp <sms_code>")
        print("  python login_v2.py otp2 <email_code>")
        print("  python login_v2.py password <pwd>")
        print("  python login_v2.py test")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "init":
        cmd_init()
    elif cmd == "phone":
        cmd_phone(sys.argv[2])
    elif cmd == "otp":
        cmd_otp(sys.argv[2])
    elif cmd == "otp2":
        cmd_otp2(sys.argv[2])
    elif cmd == "password":
        cmd_password(sys.argv[2])
    elif cmd == "test":
        cmd_test()
    else:
        print(f"Unknown command: {cmd}")
