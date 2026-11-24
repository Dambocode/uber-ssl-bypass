"""
Uber login v3 — correct request structure from JS reverse engineering.
The API uses: formContainerAnswer.formAnswer.screenAnswers[].fieldAnswers[]
"""
import json, os, re, sys, uuid
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
STATE_FILE = os.path.join(COOKIE_DIR, "login_state.json")
os.makedirs(COOKIE_DIR, exist_ok=True)

BROWSERS = ["chrome146", "chrome136", "safari184", "edge101"]


def fresh_session():
    for browser in BROWSERS:
        s = Session(impersonate=browser)
        resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
        if resp.status_code == 200 and "Sign up" in resp.text[:5000]:
            print(f"  [+] {browser} OK")

            csrf = None
            for c in s.cookies.jar:
                if c.name == "jwt-session":
                    csrf = c.value

            cookies = {c.name: c.value for c in s.cookies.jar}
            in_auth_session = cookies.get("x-uber-analytics-session-id", str(uuid.uuid4()))

            return s, csrf, cookies, in_auth_session
        print(f"  [-] {browser}: {resp.status_code}")
    return None, None, None, None


def get_cookies(session):
    return {c.name: c.value for c in session.cookies.jar}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_state():
    with open(STATE_FILE) as f:
        return json.load(f)


def build_phone_request(phone, country_code, in_auth_session):
    # Strip country code from phone if present
    number = phone
    if number.startswith(country_code):
        number = number[len(country_code):]

    return {
        "formContainerAnswer": {
            "inAuthSessionID": in_auth_session,
            "formAnswer": {
                "flowType": "SIGN_IN",
                "screenAnswers": [{
                    "screenType": "PHONE_NUMBER_INITIAL",
                    "eventType": "TYPE_INPUT_MOBILE",
                    "fieldAnswers": [
                        {"fieldType": "PHONE_COUNTRY_CODE", "phoneCountryCode": country_code},
                        {"fieldType": "PHONE_NUMBER", "phoneNumber": number},
                    ]
                }]
            }
        }
    }


def build_otp_request(otp_code, screen_type, event_type, in_auth_session):
    field_type_map = {
        "PHONE_SMS_OTP": ("PHONE_SMS_OTP", "smsOtp"),
        "PHONE_OTP": ("PHONE_SMS_OTP", "smsOtp"),
        "PHONE_OTP_PWDLESS_DRIVER": ("PHONE_SMS_OTP", "smsOtp"),
        "EMAIL_OTP": ("EMAIL_OTP", "emailOtp"),
        "EMAIL_OTP_CODE": ("EMAIL_OTP", "emailOtp"),
        "EMAIL_VERIFICATION_WITH_OTP": ("EMAIL_OTP", "emailOtp"),
    }

    field_type, field_key = field_type_map.get(screen_type, ("PHONE_SMS_OTP", "smsOtp"))

    return {
        "formContainerAnswer": {
            "inAuthSessionID": in_auth_session,
            "formAnswer": {
                "flowType": "SIGN_IN",
                "screenAnswers": [{
                    "screenType": screen_type,
                    "eventType": event_type or "TYPE_SMS_OTP",
                    "fieldAnswers": [
                        {"fieldType": field_type, field_key: otp_code}
                    ]
                }]
            }
        }
    }


def submit(session, payload, csrf):
    url = "https://auth.uber.com/v2/submit-form"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://auth.uber.com",
        "Referer": "https://auth.uber.com/v2/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "x-csrf-token": csrf or "",
        "x-uber-request-uuid": str(uuid.uuid4()),
    }

    print(f"  POST {url}")
    print(f"  Payload: {json.dumps(payload, indent=2)[:800]}")
    resp = session.post(url, json=payload, headers=headers, allow_redirects=False)
    print(f"  HTTP {resp.status_code}")

    if resp.status_code in (301, 302, 303):
        loc = resp.headers.get("Location", "")
        print(f"  Redirect -> {loc[:120]}")
        if loc:
            full = loc if loc.startswith("http") else f"https://auth.uber.com{loc}"
            resp = session.get(full, allow_redirects=True)
            print(f"  -> {resp.status_code} {resp.url}")

    new_csrf = resp.headers.get("x-csrf-token") or csrf

    try:
        data = resp.json()
    except:
        data = {"_raw": resp.text[:2000], "_status": resp.status_code}

    return data, new_csrf


def show(data):
    text = json.dumps(data, indent=2)
    if len(text) > 2000:
        text = text[:2000] + "\n..."
    print(text)

    # Extract next screen info
    screen = None
    event = None
    if "formContainerAnswer" in data:
        fa = data["formContainerAnswer"].get("formAnswer", {})
        screens = fa.get("screenAnswers", [])
        if screens:
            screen = screens[-1].get("screenType")
            event = screens[-1].get("eventType")
    for key in ("screenType", "nextScreenType", "screen"):
        if key in data and not screen:
            screen = data[key]

    # Also check nested data
    if not screen and "data" in data:
        d = data.get("data", {})
        for key in ("screenType", "nextScreenType"):
            if key in d:
                screen = d[key]

    if screen:
        print(f"\n  >>> Next screen: {screen} (event: {event})")
    return screen, event


def test_endpoints(session):
    print("\n" + "=" * 50)
    print(" Testing authenticated access")
    print("=" * 50)

    cookies = get_cookies(session)
    auth_keys = [k for k in cookies if any(x in k.lower() for x in ("sid", "token", "session", "auth", "csid", "jwt"))]
    print(f"  Auth cookies: {auth_keys}")

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

    with open(os.path.join(COOKIE_DIR, "session.json"), "w") as f:
        json.dump(cookies, f, indent=2)
    with open(os.path.join(COOKIE_DIR, "cookies.txt"), "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for c in session.cookies.jar:
            secure = "TRUE" if c.secure else "FALSE"
            domain_dot = "TRUE" if c.domain.startswith(".") else "FALSE"
            expires = str(int(c.expires)) if c.expires else "0"
            f.write(f"{c.domain}\t{domain_dot}\t{c.path}\t{secure}\t{expires}\t{c.name}\t{c.value}\n")
    print(f"\n  Exported to {COOKIE_DIR}/")


# ── Commands ─────────────────────────────────────────

def cmd_phone(phone):
    print("[*] Getting session through CF...")
    session, csrf, cookies, in_auth = fresh_session()
    if not session:
        print("[!] Blocked")
        return

    # Parse country code
    country = "+1"
    number = phone
    if phone.startswith("+"):
        country = phone[:2]
        number = phone[2:]
        if len(phone) > 2 and not phone[2:].isdigit():
            country = phone[:3]
            number = phone[3:]

    print(f"\n[phone] Country: {country}, Number: {number}")
    payload = build_phone_request(phone, country, in_auth)
    data, csrf = submit(session, payload, csrf)
    screen, event = show(data)

    save_state({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "in_auth": in_auth,
        "next_screen": screen,
        "next_event": event,
        "step": "phone",
    })

    if screen:
        print(f"\n[+] OTP sent! Run: python login_v3.py otp <code>")
    else:
        print(f"\n[?] Check response. May need adjustment.")


def cmd_otp(code, label="otp"):
    state = load_state()
    session = Session(impersonate="chrome146")
    for name, val in state["cookies"].items():
        session.cookies.set(name, val, domain=".uber.com")

    screen = state.get("next_screen", "PHONE_SMS_OTP")
    event = state.get("next_event", "TYPE_SMS_OTP")

    print(f"[{label}] Code: {code} | Screen: {screen} | Event: {event}")
    payload = build_otp_request(code, screen, event, state.get("in_auth", ""))
    data, csrf = submit(session, payload, state.get("csrf"))
    new_screen, new_event = show(data)

    state.update({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": new_screen,
        "next_event": new_event,
        "step": label,
    })
    save_state(state)

    if new_screen and "otp" in new_screen.lower():
        print(f"\n[+] Another OTP! Run: python login_v3.py otp2 <code>")
    elif new_screen and "password" in new_screen.lower():
        print(f"\n[+] Password needed: python login_v3.py password <pwd>")
    else:
        print(f"\n[+] Run: python login_v3.py test")


def cmd_password(pwd):
    state = load_state()
    session = Session(impersonate="chrome146")
    for name, val in state["cookies"].items():
        session.cookies.set(name, val, domain=".uber.com")

    screen = state.get("next_screen", "IDENTITY_PASSWORD")
    event = state.get("next_event", "")

    payload = {
        "formContainerAnswer": {
            "inAuthSessionID": state.get("in_auth", ""),
            "formAnswer": {
                "flowType": "SIGN_IN",
                "screenAnswers": [{
                    "screenType": screen,
                    "eventType": event or "TYPE_PASSWORD",
                    "fieldAnswers": [
                        {"fieldType": "PASSWORD", "password": pwd}
                    ]
                }]
            }
        }
    }
    data, csrf = submit(session, payload, state.get("csrf"))
    new_screen, new_event = show(data)

    state.update({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": new_screen,
        "next_event": new_event,
        "step": "password",
    })
    save_state(state)
    print(f"\n[+] Run: python login_v3.py test")


def cmd_test():
    state = load_state()
    session = Session(impersonate="chrome146")
    for name, val in state["cookies"].items():
        session.cookies.set(name, val, domain=".uber.com")
    test_endpoints(session)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python login_v3.py phone +19148744178")
        print("  python login_v3.py otp <sms_code>")
        print("  python login_v3.py otp2 <email_code>")
        print("  python login_v3.py password <pwd>")
        print("  python login_v3.py test")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "phone":
        cmd_phone(sys.argv[2])
    elif cmd == "otp":
        cmd_otp(sys.argv[2], "otp")
    elif cmd == "otp2":
        cmd_otp(sys.argv[2], "otp2")
    elif cmd == "password":
        cmd_password(sys.argv[2])
    elif cmd == "test":
        cmd_test()
