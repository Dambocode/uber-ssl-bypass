"""
Uber Driver login via API with CapSolver for Arkose CAPTCHA.

Flow: load auth page → solve Arkose → submit phone → SMS OTP → email OTP → session cookies
Then use cookies to access wallet.uber.com and payment APIs.

Usage:
  python uber_auth.py login +19148744178
  python uber_auth.py sms <code>
  python uber_auth.py email <code>
  python uber_auth.py wallet
  python uber_auth.py bank

Requires: pip install curl_cffi capsolver
Set env: CAPSOLVER_API_KEY=your_key
"""
import json, os, re, sys, uuid, time
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
STATE_FILE = os.path.join(COOKIE_DIR, "session_state.json")
os.makedirs(COOKIE_DIR, exist_ok=True)

ARKOSE_PUBLIC_KEY = "30000F36-CADF-490C-929A-C6A7DD8B33C4"
AUTH_URL = "https://auth.uber.com/v2/"
SUBMIT_URL = "https://auth.uber.com/v2/submit-form"
DRIVER_NEXT = "https://drivers.uber.com/"
IMPERSONATE = "safari184"


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    print(f"  [state saved]")


def load_state():
    with open(STATE_FILE) as f:
        return json.load(f)


def make_session(state=None):
    s = Session(impersonate=IMPERSONATE)
    if state and "cookies" in state:
        for name, val in state["cookies"].items():
            s.cookies.set(name, val, domain=".uber.com")
    return s


def get_cookies(s):
    return {c.name: c.value for c in s.cookies.jar}


def solve_arkose():
    """Solve Arkose FunCaptcha via CapSolver."""
    import capsolver

    api_key = os.environ.get("CAPSOLVER_API_KEY", "")
    if not api_key:
        print("  [!] Set CAPSOLVER_API_KEY env var")
        sys.exit(1)

    capsolver.api_key = api_key
    print("  [capsolver] Solving Arkose challenge...")
    t0 = time.time()

    solution = capsolver.solve({
        "type": "FunCaptchaTaskProxyLess",
        "websiteURL": "https://auth.uber.com",
        "websitePublicKey": ARKOSE_PUBLIC_KEY,
    })

    token = solution.get("token", "")
    elapsed = time.time() - t0
    print(f"  [capsolver] Solved in {elapsed:.1f}s, token: {token[:60]}...")
    return token


def build_headers(csrf, uber_headers=None, arkose_token=None):
    h = {
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
    if uber_headers:
        h.update(uber_headers)
    if arkose_token:
        h["x-uber-challenge-token"] = arkose_token
        h["x-uber-challenge-provider"] = "arkose"
    return h


def submit_form(session, payload, csrf, uber_headers=None, arkose_token=None):
    headers = build_headers(csrf, uber_headers, arkose_token)
    resp = session.post(SUBMIT_URL, json=payload, headers=headers, allow_redirects=False)
    print(f"  HTTP {resp.status_code}")

    new_csrf = csrf
    for c in session.cookies.jar:
        if c.name == "jwt-session":
            new_csrf = c.value

    try:
        data = resp.json()
    except Exception:
        data = {"_raw": resp.text[:2000], "_status": resp.status_code}

    return data, new_csrf


def extract_screen(data):
    screen = data.get("nextScreenType")
    event = data.get("nextEventType")
    if not screen:
        fca = data.get("formContainerAnswer", {})
        fa = fca.get("formAnswer", {})
        sas = fa.get("screenAnswers", [])
        if sas:
            screen = sas[-1].get("screenType")
            event = sas[-1].get("eventType")
    in_auth = data.get("inAuthSessionID", "")
    return screen, event, in_auth


def cmd_login(phone):
    print("[1] Loading driver auth page...")
    s = Session(impersonate=IMPERSONATE)
    auth_url = f"{AUTH_URL}?next_url={DRIVER_NEXT}"
    resp = s.get(auth_url, allow_redirects=True)
    print(f"  Status: {resp.status_code}")

    if resp.status_code != 200:
        s = Session(impersonate="chrome146")
        resp = s.get(auth_url, allow_redirects=True)
        print(f"  Retry: {resp.status_code}")

    if resp.status_code != 200:
        print("  [!] Failed to load auth page")
        return

    cookies = get_cookies(s)
    csrf = cookies.get("jwt-session", "")
    print(f"  Cookies: {list(cookies.keys())}")

    m = re.search(r'id="__REDUX_STATE__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
    uber_headers = {}
    if m:
        raw = m.group(1).strip().encode().decode("unicode_escape")
        redux = json.loads(raw)
        ac = redux.get("appContext", {})
        uber_headers = ac.get("headers", {})
        nav = redux.get("navigation", {})
        print(f"  nextURL: {ac.get('nextURL')}")
        print(f"  currentScreen: {nav.get('currentScreen')}")
        print(f"  shouldProxy: {ac.get('shouldProxyFirstRequest')}")
        print(f"  arkose enabled: {ac.get('arkoseConfig', {}).get('enabled')}")

    # Solve Arkose
    print("\n[2] Solving Arkose CAPTCHA...")
    arkose_token = solve_arkose()

    # Submit phone number
    number = phone.replace(" ", "").replace("-", "")
    country = "+1"
    if number.startswith("+1"):
        number = number[2:]
    elif number.startswith("+"):
        country = "+" + number[1:re.search(r'\d{10}$', number).start()]
        number = number[-10:]

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

    print(f"\n[3] Submitting {country} {number}...")
    data, csrf = submit_form(s, payload, csrf, uber_headers, arkose_token)

    screen, event, in_auth = extract_screen(data)
    print(f"  Screen: {screen} | Event: {event}")
    if in_auth:
        print(f"  inAuthSessionID: {in_auth[:40]}...")

    if "error" in str(data).lower() or "message" in data:
        print(f"  Response: {json.dumps(data, indent=2)[:500]}")

    save_state({
        "cookies": get_cookies(s),
        "csrf": csrf,
        "uber_headers": uber_headers,
        "screen": screen,
        "event": event,
        "in_auth_session_id": in_auth,
        "phone": f"{country}{number}",
    })

    if screen:
        print(f"\n[+] Next step: python uber_auth.py sms <code>")
    else:
        print(f"\n[!] No next screen returned. Check response above.")


def cmd_otp(code, otp_type="sms"):
    state = load_state()
    s = make_session(state)
    csrf = state["csrf"]
    screen = state.get("screen", "")
    event = state.get("event", "")

    if otp_type == "email" or "EMAIL" in (screen or "").upper():
        field_type = "EMAIL_OTP"
        field_key = "emailOtp"
        if "EMAIL" not in (screen or "").upper():
            screen = "EMAIL_OTP"
            event = "TYPE_EMAIL_OTP"
    else:
        field_type = "PHONE_SMS_OTP"
        field_key = "smsOtp"
        if "SMS" not in (screen or "").upper():
            screen = "PHONE_SMS_OTP"
            event = "TYPE_SMS_OTP"

    payload = {
        "formContainerAnswer": {
            "formAnswer": {
                "flowType": "SIGN_IN",
                "screenAnswers": [{
                    "screenType": screen,
                    "eventType": event,
                    "fieldAnswers": [{"fieldType": field_type, field_key: code}]
                }]
            }
        }
    }

    if state.get("in_auth_session_id"):
        payload["inAuthSessionID"] = state["in_auth_session_id"]

    print(f"[OTP:{otp_type}] Code: {code} | Screen: {screen}")
    data, csrf = submit_form(s, payload, csrf, state.get("uber_headers"))

    ns, ne, in_auth = extract_screen(data)
    print(f"  Next screen: {ns} | Event: {ne}")

    if "error" in str(data).lower() or "message" in data:
        print(f"  Response: {json.dumps(data, indent=2)[:800]}")

    state.update({
        "cookies": get_cookies(s),
        "csrf": csrf,
        "screen": ns,
        "event": ne,
        "in_auth_session_id": in_auth or state.get("in_auth_session_id"),
    })
    save_state(state)

    if ns and "email" in ns.lower():
        print(f"\n[+] Email OTP needed: python uber_auth.py email <code>")
    elif ns and "otp" in ns.lower():
        print(f"\n[+] Another OTP: python uber_auth.py sms <code>")
    elif ns and "password" in ns.lower():
        print(f"\n[+] Password needed (not implemented)")
    elif not ns:
        print(f"\n[+] Login may be complete! Test: python uber_auth.py wallet")
    else:
        print(f"\n[+] Unknown screen '{ns}'. Test: python uber_auth.py wallet")


def cmd_wallet():
    """Test authenticated access to Uber Wallet."""
    state = load_state()
    s = make_session(state)

    print("[wallet] Testing authenticated endpoints...\n")

    endpoints = [
        ("https://drivers.uber.com/earnings/", "Driver Earnings"),
        ("https://wallet.uber.com/", "Uber Wallet"),
        ("https://drivers.uber.com/p3/payments", "Driver Payments"),
        ("https://payments.uber.com/", "Payments Hub"),
    ]

    for url, label in endpoints:
        try:
            resp = s.get(url, allow_redirects=False)
            loc = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303):
                if "auth.uber.com" in loc:
                    print(f"  [{label}] -> AUTH REDIRECT (not logged in)")
                else:
                    print(f"  [{label}] -> {resp.status_code} -> {loc[:80]}")
            elif resp.status_code == 200:
                title_m = re.search(r"<title>(.*?)</title>", resp.text[:5000])
                title = title_m.group(1) if title_m else "(no title)"
                print(f"  [{label}] -> 200 OK | {title[:60]}")
                if "wallet" in url.lower() or "payment" in url.lower():
                    # Try to find bank account / payment profile info
                    bank_m = re.findall(r'(?:bank|routing|account|payout)[^<]{0,200}', resp.text, re.I)
                    if bank_m:
                        print(f"    Bank refs: {bank_m[:3]}")
            else:
                print(f"  [{label}] -> {resp.status_code}")
        except Exception as e:
            print(f"  [{label}] -> Error: {e}")

    # Update cookies in state
    state["cookies"] = get_cookies(s)
    save_state(state)


def cmd_bank():
    """Navigate to the bank account management page and extract API details."""
    state = load_state()
    s = make_session(state)

    print("[bank] Loading wallet bank account page...\n")

    # First load wallet to get any redirects/session setup
    resp = s.get("https://wallet.uber.com/", allow_redirects=True)
    print(f"  Wallet: {resp.status_code} | {resp.url[:80]}")

    # Try the bank account add endpoint
    resp2 = s.get("https://wallet.uber.com/payment-profile/add/bank-account", allow_redirects=True)
    print(f"  Add bank: {resp2.status_code} | {resp2.url[:80]}")

    # Look for API endpoints in the page
    if resp.status_code == 200:
        # Extract payment profile data from server-rendered HTML
        balance_m = re.search(r'Balance.*?\$[\d,.]+', resp.text[:5000])
        if balance_m:
            print(f"  {balance_m.group(0)[:60]}")

        # Find the CSRF token for wallet.uber.com
        csrf_m = re.search(r'csrf[^"]*"[^"]*"([^"]+)"', resp.text[:10000])
        if csrf_m:
            print(f"  Wallet CSRF: {csrf_m.group(1)[:40]}...")

        # Find API endpoints referenced in the page
        api_refs = re.findall(r'(?:"/api/|"/rt/|"/v1/|"/v2/)[^"]+', resp.text[:50000])
        if api_refs:
            print(f"  API refs found: {api_refs[:5]}")

    state["cookies"] = get_cookies(s)
    save_state(state)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python uber_auth.py login +19148744178")
        print("  python uber_auth.py sms <code>")
        print("  python uber_auth.py email <code>")
        print("  python uber_auth.py wallet")
        print("  python uber_auth.py bank")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "login":
        cmd_login(sys.argv[2] if len(sys.argv) > 2 else "+19148744178")
    elif cmd == "sms":
        cmd_otp(sys.argv[2], "sms")
    elif cmd == "email":
        cmd_otp(sys.argv[2], "email")
    elif cmd == "wallet":
        cmd_wallet()
    elif cmd == "bank":
        cmd_bank()
    else:
        print(f"Unknown command: {cmd}")
