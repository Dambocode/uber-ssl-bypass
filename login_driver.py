"""
Uber DRIVER login — loads driver-specific auth context.
"""
import json, os, re, sys, uuid, base64, time
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
STATE_FILE = os.path.join(COOKIE_DIR, "login_state.json")
os.makedirs(COOKIE_DIR, exist_ok=True)


def fresh_driver_session():
    """Load auth page with driver next_url to get driver-specific product context."""
    s = Session(impersonate="safari184")

    # Load with drivers.uber.com as the next URL
    auth_url = "https://auth.uber.com/v2/?next_url=https%3A%2F%2Fdrivers.uber.com%2F"
    resp = s.get(auth_url, allow_redirects=True)
    print(f"  Status: {resp.status_code}")

    if resp.status_code != 200:
        print("  Retrying with chrome146...")
        s = Session(impersonate="chrome146")
        resp = s.get(auth_url, allow_redirects=True)
        print(f"  Retry status: {resp.status_code}")

    if resp.status_code != 200:
        return None, None, None, None

    cookies = {c.name: c.value for c in s.cookies.jar}
    csrf = cookies.get("jwt-session", "")
    print(f"  Cookies: {list(cookies.keys())}")

    # Parse Redux state
    m = re.search(r'id="__REDUX_STATE__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
    if m:
        raw = m.group(1).strip()
        decoded = raw.encode().decode("unicode_escape")
        redux = json.loads(decoded)

        ac = redux.get("appContext", {})
        headers = ac.get("headers", {})
        nav = redux.get("navigation", {})

        print(f"  nextURL: {ac.get('nextURL')}")
        print(f"  primaryIdentifier: {ac.get('primaryIdentifier')}")
        print(f"  currentScreen: {nav.get('currentScreen')}")
        print(f"  x-uber-client-name: {headers.get('x-uber-client-name')}")

        # Save the headers from Redux — these are what the SPA sends
        return s, csrf, cookies, headers
    else:
        print("  [!] No __REDUX_STATE__ found")
        return s, csrf, cookies, {}


def get_cookies(s):
    return {c.name: c.value for c in s.cookies.jar}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_state():
    with open(STATE_FILE) as f:
        return json.load(f)


def submit(session, payload, csrf, uber_headers=None):
    url = "https://auth.uber.com/v2/submit-form"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://auth.uber.com",
        "Referer": "https://auth.uber.com/v2/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "x-csrf-token": csrf,
        "x-uber-request-uuid": str(uuid.uuid4()),
    }
    # Add the uber-specific headers from Redux state
    if uber_headers:
        for k, v in uber_headers.items():
            headers[k] = v

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
    for key in ("screenType", "nextScreenType"):
        if key in data:
            screen = data[key]

    fca = data.get("formContainerAnswer", {})
    fa = fca.get("formAnswer", {})
    sas = fa.get("screenAnswers", [])
    if sas:
        screen = sas[-1].get("screenType") or screen
        event = sas[-1].get("eventType")

    if screen:
        print(f"\n  >>> Screen: {screen} | Event: {event}")
    return screen, event


def test_endpoints(session):
    print("\n" + "=" * 50)
    print(" Testing authenticated access")
    print("=" * 50)

    for url, label in [
        ("https://drivers.uber.com/earnings/webview/", "Earnings"),
        ("https://payments.uber.com/", "Payments"),
        ("https://partners.uber.com/p3/payments/cartop", "Partners"),
    ]:
        try:
            resp = session.get(url, allow_redirects=False)
            loc = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303):
                if "auth.uber.com" in loc:
                    print(f"  [{label}] -> login redirect")
                else:
                    print(f"  [{label}] -> {resp.status_code} {loc[:80]}")
            elif resp.status_code == 200:
                title_m = re.search(r"<title>(.*?)</title>", resp.text[:2000])
                print(f"  [{label}] -> 200 OK | {(title_m.group(1) if title_m else '')[:60]}")
            else:
                print(f"  [{label}] -> {resp.status_code}")
        except Exception as e:
            print(f"  [{label}] -> {e}")


def cmd_phone(phone):
    print("[1] Loading driver auth page...")
    session, csrf, cookies, uber_headers = fresh_driver_session()
    if not session:
        print("[!] Failed to get session")
        return

    number = phone.replace(" ", "").replace("-", "")
    country = "+1"
    if number.startswith("+1"):
        number = number[2:]

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

    print(f"\n[2] Submitting {country} {number}")
    data, csrf = submit(session, payload, csrf, uber_headers)
    screen, event = show(data)

    save_state({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "uber_headers": uber_headers,
        "next_screen": screen,
        "next_event": event,
    })

    if screen:
        print(f"\n[+] Check phone/email! Run: python login_driver.py otp <code>")


def cmd_otp(code, label="otp"):
    state = load_state()
    s = Session(impersonate="safari184")
    for n, v in state["cookies"].items():
        s.cookies.set(n, v, domain=".uber.com")

    screen = state.get("next_screen", "PHONE_SMS_OTP")
    event = state.get("next_event", "TYPE_SMS_OTP")

    if "EMAIL" in (screen or "").upper():
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
    data, csrf = submit(s, payload, state.get("csrf"), state.get("uber_headers"))
    ns, ne = show(data)

    state.update({"cookies": get_cookies(s), "csrf": csrf, "next_screen": ns, "next_event": ne})
    save_state(state)

    if ns and "otp" in ns.lower():
        print(f"\n[+] Another OTP: python login_driver.py otp2 <code>")
    elif ns and "password" in ns.lower():
        print(f"\n[+] Password: python login_driver.py password <pwd>")
    else:
        print(f"\n[+] Test: python login_driver.py test")


def cmd_test():
    state = load_state()
    s = Session(impersonate="safari184")
    for n, v in state["cookies"].items():
        s.cookies.set(n, v, domain=".uber.com")
    test_endpoints(s)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("  python login_driver.py phone +19148744178")
        print("  python login_driver.py otp <code>")
        print("  python login_driver.py otp2 <code>")
        print("  python login_driver.py test")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "phone": cmd_phone(sys.argv[2])
    elif cmd == "otp": cmd_otp(sys.argv[2])
    elif cmd == "otp2": cmd_otp(sys.argv[2], "otp2")
    elif cmd == "test": cmd_test()
