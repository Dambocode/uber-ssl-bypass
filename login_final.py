"""
Uber login — final version with CF retry and correct request format.
"""
import json, os, re, sys, uuid, base64, time
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
STATE_FILE = os.path.join(COOKIE_DIR, "login_state.json")
os.makedirs(COOKIE_DIR, exist_ok=True)

BROWSERS = ["chrome146", "chrome136", "safari184", "edge101", "chrome124"]


def get_clean_session():
    """Get a session that passes Cloudflare, with retries."""
    for attempt in range(3):
        for browser in BROWSERS:
            s = Session(impersonate=browser)
            try:
                resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
                if resp.status_code == 200 and "Sign up" in resp.text[:5000]:
                    cookies = {c.name: c.value for c in s.cookies.jar}
                    csrf = cookies.get("jwt-session", "")
                    print(f"  [{browser}] OK | Cookies: {list(cookies.keys())}")
                    return s, csrf, cookies, resp
            except Exception as e:
                pass
        if attempt < 2:
            print(f"  All browsers failed, retrying in 3s...")
            time.sleep(3)

    print("[!] Cannot bypass Cloudflare after retries")
    return None, None, None, None


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_state():
    with open(STATE_FILE) as f:
        return json.load(f)


def get_cookies(s):
    return {c.name: c.value for c in s.cookies.jar}


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
        "x-csrf-token": csrf,
        "x-uber-client-name": "usl_desktop",
        "x-uber-request-uuid": str(uuid.uuid4()),
    }

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
    fca = data.get("formContainerAnswer", {})
    fa = fca.get("formAnswer", {})
    sas = fa.get("screenAnswers", [])
    if sas:
        screen = sas[-1].get("screenType")
        event = sas[-1].get("eventType")
    for key in ("screenType", "nextScreenType"):
        if key in data and not screen:
            screen = data[key]

    if screen:
        print(f"\n  >>> Screen: {screen} | Event: {event}")
    return screen, event


def cmd_phone(phone):
    print("[1] Getting clean session...")
    session, csrf, cookies, resp = get_clean_session()
    if not session:
        return

    number = phone.replace(" ", "").replace("-", "")
    country = "+1"
    if number.startswith("+1"):
        number = number[2:]
    elif number.startswith("+"):
        country = number[:2]
        number = number[len(country):]

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

    print(f"\n[2] Submitting phone: {country} {number}")
    data, csrf = submit(session, payload, csrf)
    screen, event = show(data)

    save_state({
        "cookies": get_cookies(session),
        "csrf": csrf,
        "next_screen": screen,
        "next_event": event,
    })

    if screen:
        print(f"\n[+] Check your phone/email! Then: python login_final.py otp <code>")
    elif data.get("errorType") == "INVALID":
        print("\n[!] 'Invalid' error — the product context may be wrong.")
        print("    Trying alternate approach...")
        # If that failed, try without flowType
        payload2 = {
            "formContainerAnswer": {
                "formAnswer": {
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
        data2, csrf = submit(session, payload2, csrf)
        screen2, event2 = show(data2)
        save_state({
            "cookies": get_cookies(session),
            "csrf": csrf,
            "next_screen": screen2,
            "next_event": event2,
        })
    else:
        print(f"\n[?] Unexpected response. Check above.")


def cmd_otp(code, label="otp"):
    state = load_state()
    s = Session(impersonate="chrome146")
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

    print(f"[{label}] Submitting {code} for {screen}...")
    data, csrf = submit(s, payload, state.get("csrf"))
    ns, ne = show(data)

    state.update({"cookies": get_cookies(s), "csrf": csrf, "next_screen": ns, "next_event": ne})
    save_state(state)

    if ns and "otp" in ns.lower():
        print(f"\n[+] Another OTP needed: python login_final.py otp2 <code>")
    elif ns and "password" in ns.lower():
        print(f"\n[+] Password needed: python login_final.py password <pwd>")
    else:
        print(f"\n[+] Done! Test: python login_final.py test")


def cmd_test():
    state = load_state()
    s = Session(impersonate="chrome146")
    for n, v in state["cookies"].items():
        s.cookies.set(n, v, domain=".uber.com")

    print("[test] Checking endpoints...")
    cookies = state["cookies"]
    auth_keys = [k for k in cookies if any(x in k.lower() for x in ("sid", "token", "session", "auth", "csid", "jwt"))]
    print(f"  Auth cookies: {auth_keys}")

    for url, label in [
        ("https://drivers.uber.com/earnings/webview/", "Earnings"),
        ("https://payments.uber.com/", "Payments"),
        ("https://partners.uber.com/p3/payments/cartop", "Partners"),
    ]:
        try:
            resp = s.get(url, allow_redirects=False)
            loc = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303):
                if "auth.uber.com" in loc:
                    print(f"  [{label}] -> login redirect")
                else:
                    print(f"  [{label}] -> {resp.status_code} {loc[:80]}")
            elif resp.status_code == 200:
                title_m = re.search(r"<title>(.*?)</title>", resp.text[:2000])
                print(f"  [{label}] -> 200 OK | {(title_m.group(1) if title_m else '')[:60]}")
                with open(os.path.join(COOKIE_DIR, f"{label.lower()}.html"), "w", encoding="utf-8") as f:
                    f.write(resp.text)
            else:
                print(f"  [{label}] -> {resp.status_code}")
        except Exception as e:
            print(f"  [{label}] -> {e}")

    with open(os.path.join(COOKIE_DIR, "session.json"), "w") as f:
        json.dump(cookies, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("  python login_final.py phone +19148744178")
        print("  python login_final.py otp <code>")
        print("  python login_final.py otp2 <code>")
        print("  python login_final.py password <pwd>")
        print("  python login_final.py test")
        sys.exit(0)

    {"phone": lambda: cmd_phone(sys.argv[2]),
     "otp": lambda: cmd_otp(sys.argv[2]),
     "otp2": lambda: cmd_otp(sys.argv[2], "otp2"),
     "password": lambda: cmd_otp(sys.argv[2], "password"),
     "test": cmd_test,
    }.get(sys.argv[1], lambda: print(f"Unknown: {sys.argv[1]}"))()
