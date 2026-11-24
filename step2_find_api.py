"""Step 2: Download auth JS bundles and find the login API endpoint."""
import json, re
from curl_cffi.requests import Session

state = json.load(open("cookie-dump/auth_state.json"))

s = Session(impersonate="chrome120")
for name, val in state["cookies"].items():
    s.cookies.set(name, val, domain=".uber.com")

js_files = [
    "/v2/_static/client-main-a0e00f483853fcc9.js",
    "/v2/_static/client-5095-2533443afb84023f.js",
]

for js_path in js_files:
    url = f"https://auth.uber.com{js_path}"
    print(f"[*] Fetching {js_path}...")
    resp = s.get(url)
    print(f"    Size: {len(resp.text)} chars")

    fname = js_path.split("/")[-1]
    with open(f"cookie-dump/{fname}", "w", encoding="utf-8") as f:
        f.write(resp.text)

    # Search for auth-related API patterns
    patterns = [
        (r'"/v[12]/[a-zA-Z0-9/_-]*(auth|login|verify|otp|phone|submit|token|session|challenge)[a-zA-Z0-9/_-]*"', "API route"),
        (r'"(POST|PUT|PATCH)"[^}]{0,100}"(/[a-zA-Z0-9/_-]+)"', "HTTP method+path"),
        (r'(answerType|phoneNumber|otpValue|password|stateToken)', "auth field"),
        (r'x-csrf-token|csrfToken', "CSRF"),
        (r'(PHONE_NUMBER|OTP|PASSWORD|SMS|EMAIL_OTP|CAPTCHA)', "auth step type"),
    ]

    for pat, label in patterns:
        matches = set(re.findall(pat, resp.text))
        if matches:
            print(f"    [{label}]: {list(matches)[:15]}")

    # Look specifically for the fetch/POST call patterns
    fetch_calls = re.findall(r'fetch\s*\(\s*["`]([^"`]+)["`]', resp.text)
    if fetch_calls:
        print(f"    [fetch calls]: {list(set(fetch_calls))[:10]}")

    # Look for the concatenation pattern like baseUrl + "/something"
    concat = re.findall(r'["`](/v\d/[^"`]{3,50})["`]', resp.text)
    if concat:
        auth_routes = [c for c in set(concat) if any(k in c.lower() for k in ['auth', 'login', 'verify', 'otp', 'phone', 'challenge', 'session'])]
        if auth_routes:
            print(f"    [auth routes]: {auth_routes[:15]}")
        else:
            print(f"    [all /v routes]: {list(set(concat))[:20]}")

print("\nDone.")
