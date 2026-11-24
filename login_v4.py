"""
Uber login v4 — correct product context via driver-specific auth URL.
"""
import json, os, re, sys, uuid, base64
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
STATE_FILE = os.path.join(COOKIE_DIR, "login_state.json")
os.makedirs(COOKIE_DIR, exist_ok=True)


def fresh_session():
    s = Session(impersonate="chrome146")
    # Use driver-specific auth flow URL
    resp = s.get("https://auth.uber.com/v2/?breeze_local_zone=dca11&next_url=https%3A%2F%2Fdrivers.uber.com%2F&state=x", allow_redirects=True)
    if resp.status_code != 200:
        print(f"  [-] Status {resp.status_code}, trying plain...")
        resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
    print(f"  Status: {resp.status_code} | URL: {resp.url}")

    cookies = {c.name: c.value for c in s.cookies.jar}
    csrf = cookies.get("jwt-session", "")
    print(f"  Cookies: {list(cookies.keys())}")

    # Decode JWT to get the session slate info
    if csrf:
        try:
            parts = csrf.split(".")
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            decoded = json.loads(base64.b64decode(payload))
            print(f"  JWT data: {json.dumps(decoded)}")
        except:
            pass

    return s, csrf, cookies


def get_cookies(s):
    return {c.name: c.value for c in s.cookies.jar}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_state():
    with open(STATE_FILE) as f:
        return json.load(f)


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
        "x-uber-client-name": "usl_desktop",
        "x-uber-request-uuid": str(uuid.uuid4()),
    }

    print(f"  POST {url}")
    resp = session.post(url, json=payload, headers=headers, allow_redirects=False)
    print(f"  HTTP {resp.status_code}")

    if resp.status_code in (301, 302, 303):
        loc = resp.headers.get("Location", "")
        print(f"  Redirect -> {loc[:120]}")
        if loc:
            full = loc if loc.startswith("http") else f"https://auth.uber.com{loc}"
            resp = session.get(full, allow_redirects=True)

    new_csrf = resp.headers.get("x-csrf-token") or csrf

    try:
        data = resp.json()
    except:
        data = {"_raw": resp.text[:2000], "_status": resp.status_code}

    return data, new_csrf


def show(data):
    text = json.dumps(data, indent=2)
    if len(text) > 2500:
        text = text[:2500] + "\n..."
    print(text)

    screen, event = None, None
    # Navigate nested response
    fca = data.get("formContainerAnswer", {})
    fa = fca.get("formAnswer", {})
    sas = fa.get("screenAnswers", [])
    if sas:
        last = sas[-1]
        screen = last.get("screenType")
        event = last.get("eventType")
    for key in ("screenType", "nextScreenType"):
        if key in data and not screen:
            screen = data[key]

    if screen:
        print(f"\n  >>> Screen: {screen} | Event: {event}")
    return screen, event


def test_endpoints(session):
    print("\n" + "=" * 50)
    print(" Testing authenticated access")
    print("=" * 50)

    urls = [
        ("https://drivers.uber.com/earnings/webview/", "Earnings"),
        ("https://payments.uber.com/", "Payments"),
        ("https://partners.uber.com/p3/payments/cartop", "Partners"),
    ]

    for url, label in urls:
        try:
            resp = session.get(url, allow_redirects=False)
            status = resp.status_code
            loc = resp.headers.get("Location", "")
            if status in (301, 302, 303):
                if "auth.uber.com" in loc:
                    print(f"  [{label}] -> login redirect")
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
        json.dump(get_cookies(session), f, indent=2)
    print(f"  Exported to {COOKIE_DIR}/")


def cmd_phone(phone):
    print("[*] Loading auth page...")
    session, csrf, cookies = fresh_session()

    country = "+1"
    number = phone.replace(" ", "").replace("-", "")
    if number.startswith("+1"):
        number = number[2:]
    elif number.startswith("+"):
        country = number[:2] if number[2:].isdigit() or len(number) < 4 else number[:3]
        number = number[len(country):]

    print(f"\n[phone] {country} {number}")

    payload = {
        "formContainerAnswer": {
            "formAnswer": {
                "flowType": "SIGN_IN",
                "screenAnswers": [{
                    "screenType": "PHONE_NUMBER_INITIAL",
                    "eventType": "TYPE_INPUT_MOBILE",
                    "fieldAnswers": [
                        {"fieldType": "PHONE_COUNTRY_CODE", "phoneCountryCode": country},
                        {"fieldType": "PHONE_NUMBER", "phoneNumber": number},
                    ]
                }]
            }
        }
    }

    print(f"  Payload: {json.dumps(payload)[:500]}")
    data, csrf = submit(session, payload, csrf)
    screen, event = show(data)

    save_state({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": screen,
        "next_event": event,
    })

    if screen:
        print(f"\n[+] Run: python login_v4.py otp <code>")


def cmd_otp(code, label="otp"):
    state = load_state()
    s = Session(impersonate="chrome146")
    for n, v in state["cookies"].items():
        s.cookies.set(n, v, domain=".uber.com")

    screen = state.get("next_screen", "PHONE_SMS_OTP")
    event = state.get("next_event", "TYPE_SMS_OTP")

    # Map screen to field type
    if "EMAIL" in (screen or ""):
        ft, fk = "EMAIL_OTP", "emailOtp"
    else:
        ft, fk = "PHONE_SMS_OTP", "smsOtp"

    payload = {
        "formContainerAnswer": {
            "formAnswer": {
                "flowType": "SIGN_IN",
                "screenAnswers": [{
                    "screenType": screen,
                    "eventType": event,
                    "fieldAnswers": [{"fieldType": ft, fk: code}]
                }]
            }
        }
    }

    print(f"[{label}] Code: {code} | Screen: {screen}")
    data, csrf = submit(s, payload, state.get("csrf"))
    ns, ne = show(data)

    state.update({"cookies": get_cookies(s), "csrf": csrf, "next_screen": ns, "next_event": ne})
    save_state(state)

    if ns and "otp" in ns.lower():
        print(f"\n[+] Another OTP: python login_v4.py otp2 <code>")
    elif ns and "password" in ns.lower():
        print(f"\n[+] Password: python login_v4.py password <pwd>")
    else:
        print(f"\n[+] Test: python login_v4.py test")


def cmd_test():
    state = load_state()
    s = Session(impersonate="chrome146")
    for n, v in state["cookies"].items():
        s.cookies.set(n, v, domain=".uber.com")
    test_endpoints(s)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("  python login_v4.py phone +19148744178")
        print("  python login_v4.py otp <code>")
        print("  python login_v4.py otp2 <code>")
        print("  python login_v4.py test")
        sys.exit(0)

    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd == "phone": cmd_phone(args[0])
    elif cmd == "otp": cmd_otp(args[0])
    elif cmd == "otp2": cmd_otp(args[0], "otp2")
    elif cmd == "test": cmd_test()
