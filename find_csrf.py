"""Find the CSRF token from auth.uber.com."""
import json, re
from curl_cffi.requests import Session

s = Session(impersonate="chrome146")
resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
print(f"Status: {resp.status_code}")

for c in s.cookies.jar:
    print(f"  Cookie: {c.name} = {c.value[:80]}{'...' if len(c.value) > 80 else ''} (domain={c.domain})")

# Search page for CSRF patterns
patterns = [
    (r'"csrfToken"\s*:\s*"([^"]+)"', "csrfToken JSON"),
    (r'"csrf_token"\s*:\s*"([^"]+)"', "csrf_token JSON"),
    (r"'csrfToken'\s*:\s*'([^']+)'", "csrfToken single-quote"),
    (r'name="csrf[^"]*"\s+content="([^"]*)"', "meta csrf"),
    (r'name="_csrf[^"]*"\s+value="([^"]*)"', "input csrf"),
    (r'"x-csrf-token"\s*:\s*"([^"]+)"', "x-csrf-token JSON"),
    (r'csrf[Tt]oken\s*=\s*["\x27]([^"\x27]+)', "csrf assignment"),
]

found_csrf = None
for pat, label in patterns:
    ms = re.findall(pat, resp.text)
    if ms:
        print(f"  FOUND [{label}]: {ms[0][:60]}...")
        found_csrf = ms[0]

# Also check the cookie jar endpoint
print("\nTrying to get CSRF from cookie endpoint...")
resp2 = s.get("https://auth.uber.com/v2/silk-screen/prepare-field", headers={
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Origin": "https://auth.uber.com",
    "Referer": "https://auth.uber.com/v2/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
})
print(f"  prepare-field: {resp2.status_code}")
for h in resp2.headers:
    hl = h.lower()
    if "csrf" in hl or "token" in hl or "set-cookie" in hl:
        print(f"  Header: {h} = {resp2.headers[h][:100]}")

# Check if any new cookies appeared
for c in s.cookies.jar:
    if "csrf" in c.name.lower() or "token" in c.name.lower():
        print(f"  NEW Cookie: {c.name} = {c.value[:80]}")
        found_csrf = c.value

# Check set-cookie headers from BOTH responses
for r in [resp, resp2]:
    sc = r.headers.get("set-cookie", "")
    if "csrf" in sc.lower():
        print(f"  set-cookie contains csrf: {sc[:200]}")

if found_csrf:
    # Update state
    state = json.load(open("cookie-dump/login_state.json"))
    state["csrf"] = found_csrf
    state["cookies"] = {c.name: c.value for c in s.cookies.jar}
    with open("cookie-dump/login_state.json", "w") as f:
        json.dump(state, f, indent=2)
    print(f"\nCSRF saved to state: {found_csrf[:40]}...")
else:
    print("\nNo CSRF found. Checking page for all token-like strings...")
    tokens = re.findall(r'"[a-zA-Z]*[Tt]oken[a-zA-Z]*"\s*:\s*"([^"]{8,})"', resp.text)
    for t in tokens[:5]:
        print(f"  Token: {t[:60]}...")
