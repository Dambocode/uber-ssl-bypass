"""
Step-by-step Uber login — run with: python login_step.py <step> [args]

  python login_step.py init
  python login_step.py phone +15551234567
  python login_step.py otp <code>
  python login_step.py otp2 <code>
  python login_step.py test
"""
import json
import os
import re
import sys
from curl_cffi.requests import Session

COOKIE_DIR = "cookie-dump"
STATE_FILE = os.path.join(COOKIE_DIR, "login_state.json")
os.makedirs(COOKIE_DIR, exist_ok=True)


def make_session(cookies=None):
    s = Session(impersonate="chrome146")
    s.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    })
    if cookies:
        for name, val in cookies.items():
            s.cookies.set(name, val, domain=".uber.com")
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


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    print(f"  [state saved]")


def load_state():
    with open(STATE_FILE) as f:
        return json.load(f)


def submit_form(session, payload, csrf=None):
    url = "https://auth.uber.com/v2/silk-screen/submit-form"
    print(f"  POST {url}")
    print(f"  Payload: {json.dumps(payload)}")
    resp = session.post(url, json=payload, headers=api_headers(csrf), allow_redirects=False)
    print(f"  HTTP {resp.status_code}")

    new_csrf = resp.headers.get("x-csrf-token") or csrf

    if resp.status_code in (301, 302, 303):
        loc = resp.headers.get("Location", "")
        print(f"  Redirect -> {loc[:150]}")
        if loc:
            full = loc if loc.startswith("http") else f"https://auth.uber.com{loc}"
            resp = session.get(full, allow_redirects=True)
            print(f"  Followed -> {resp.status_code} {resp.url}")

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        data = {"_raw": resp.text[:2000], "_status": resp.status_code}

    return data, new_csrf


def show(data):
    text = json.dumps(data, indent=2)
    if len(text) > 2000:
        text = text[:2000] + "\n..."
    print(text)

    screen = None
    for key in ("screenType", "nextScreenType"):
        if key in data:
            screen = data[key]
        elif "data" in data and isinstance(data.get("data"), dict) and key in data["data"]:
            screen = data["data"][key]
    if screen:
        print(f"\n  >>> Next screen: {screen}")
    return screen


# ── Commands ──────────────────────────────────────────

def cmd_init():
    print("[init] Loading auth.uber.com/v2/ ...")
    session = make_session()
    resp = session.get("https://auth.uber.com/v2/", allow_redirects=True)
    print(f"  Status: {resp.status_code}")
    cookies = get_cookies(session)
    print(f"  Cookies: {list(cookies.keys())}")

    csrf = None
    for c in session.cookies.jar:
        if c.name == "x-csrf-token":
            csrf = c.value
    if not csrf:
        m = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', resp.text)
        if m:
            csrf = m.group(1)

    print(f"  CSRF: {csrf[:30] + '...' if csrf else 'none'}")

    with open(os.path.join(COOKIE_DIR, "auth_page.html"), "w", encoding="utf-8") as f:
        f.write(resp.text)

    save_state({"cookies": cookies, "csrf": csrf, "step": "init"})
    print("\n  Next: python login_step.py phone +15551234567")


def cmd_phone(phone):
    state = load_state()
    session = make_session(state["cookies"])

    # Re-init to get fresh cookies in case they expired
    print(f"[phone] Refreshing session...")
    resp = session.get("https://auth.uber.com/v2/", allow_redirects=True)
    state["cookies"] = get_cookies(session)
    for c in session.cookies.jar:
        if c.name == "x-csrf-token":
            state["csrf"] = c.value

    print(f"[phone] Submitting: {phone}")
    payload = {"phoneNumber": phone, "screenType": "PHONE_NUMBER_INITIAL"}
    data, csrf = submit_form(session, payload, state.get("csrf"))
    state["csrf"] = csrf
    state["cookies"] = get_cookies(session)

    screen = show(data)
    state["last_response"] = data
    state["next_screen"] = screen
    state["step"] = "phone"
    save_state(state)

    print(f"\n  Next: python login_step.py otp <sms_code>")


def cmd_otp(code, step_name="otp"):
    state = load_state()
    session = make_session(state["cookies"])

    screen = state.get("next_screen")
    if not screen:
        # Guess common screens
        screen = "PHONE_SMS_OTP"
        print(f"  [!] No screen saved, guessing: {screen}")

    print(f"[{step_name}] Submitting code: {code} for screen: {screen}")
    payload = {"otpValue": code, "screenType": screen}
    data, csrf = submit_form(session, payload, state.get("csrf"))
    state["csrf"] = csrf
    state["cookies"] = get_cookies(session)

    new_screen = show(data)
    state["last_response"] = data
    state["next_screen"] = new_screen
    state["step"] = step_name
    save_state(state)

    if new_screen and "otp" in new_screen.lower():
        print(f"\n  Another OTP needed! Run: python login_step.py otp2 <code>")
    else:
        print(f"\n  Next: python login_step.py test")


def cmd_password(pwd):
    state = load_state()
    session = make_session(state["cookies"])

    screen = state.get("next_screen", "IDENTITY_PASSWORD")
    print(f"[password] Submitting for screen: {screen}")
    payload = {"password": pwd, "screenType": screen}
    data, csrf = submit_form(session, payload, state.get("csrf"))
    state["csrf"] = csrf
    state["cookies"] = get_cookies(session)

    new_screen = show(data)
    state["last_response"] = data
    state["next_screen"] = new_screen
    state["step"] = "password"
    save_state(state)
    print(f"\n  Next: python login_step.py test")


def cmd_test():
    state = load_state()
    session = make_session(state["cookies"])

    print("[test] Checking authenticated access...\n")
    cookies = state.get("cookies", {})
    auth_keys = [k for k in cookies if any(x in k.lower() for x in ("sid", "token", "session", "auth", "csid", "jwt"))]
    print(f"  Auth cookies: {auth_keys}")
    for k in auth_keys:
        v = cookies[k]
        print(f"    {k} = {v[:60]}{'...' if len(v) > 60 else ''}")

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
                    print(f"  [{label}] -> login redirect (NOT authed)")
                else:
                    print(f"  [{label}] -> {status} {loc[:80]}")
            elif status == 200:
                title_m = re.search(r"<title>(.*?)</title>", resp.text[:2000])
                title = title_m.group(1) if title_m else ""
                has_login = any(x in resp.text[:3000].lower() for x in ("sign in", "log in", "login"))
                tag = "LOGIN PAGE" if has_login else "OK"
                print(f"  [{label}] -> 200 {tag} | {title[:60]}")
                with open(os.path.join(COOKIE_DIR, f"{label.lower()}.html"), "w", encoding="utf-8") as f:
                    f.write(resp.text)
            else:
                print(f"  [{label}] -> {status}")
        except Exception as e:
            print(f"  [{label}] -> Error: {e}")

    # Export
    with open(os.path.join(COOKIE_DIR, "cookies.txt"), "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for c in session.cookies.jar:
            secure = "TRUE" if c.secure else "FALSE"
            domain_dot = "TRUE" if c.domain.startswith(".") else "FALSE"
            expires = str(int(c.expires)) if c.expires else "0"
            f.write(f"{c.domain}\t{domain_dot}\t{c.path}\t{secure}\t{expires}\t{c.name}\t{c.value}\n")
    with open(os.path.join(COOKIE_DIR, "session.json"), "w") as f:
        json.dump(cookies, f, indent=2)
    print(f"\n  Session exported to {COOKIE_DIR}/")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "init":
        cmd_init()
    elif cmd == "phone" and len(sys.argv) >= 3:
        cmd_phone(sys.argv[2])
    elif cmd == "otp" and len(sys.argv) >= 3:
        cmd_otp(sys.argv[2], "otp")
    elif cmd == "otp2" and len(sys.argv) >= 3:
        cmd_otp(sys.argv[2], "otp2")
    elif cmd == "password" and len(sys.argv) >= 3:
        cmd_password(sys.argv[2])
    elif cmd == "test":
        cmd_test()
    else:
        print(__doc__)
