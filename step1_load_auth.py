"""Step 1: Load Uber auth page and extract tokens."""
import json, re, os
from curl_cffi.requests import Session

os.makedirs("cookie-dump", exist_ok=True)

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

print("[1] Loading auth.uber.com/v2/ ...")
resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
print(f"    Status: {resp.status_code}")
print(f"    Final URL: {resp.url}")

all_cookies = {}
for c in s.cookies.jar:
    all_cookies[c.name] = c.value
print(f"    Cookies: {list(all_cookies.keys())}")

with open("cookie-dump/auth_page.html", "w", encoding="utf-8") as f:
    f.write(resp.text)

csrf = None
m = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', resp.text)
if m:
    csrf = m.group(1)
    print(f"    CSRF: {csrf[:40]}...")

state = None
m = re.search(r'"stateToken"\s*:\s*"([^"]+)"', resp.text)
if m:
    state = m.group(1)
    print(f"    State: {state[:40]}...")

for name, pat in [
    ("__NEXT_DATA__", r'__NEXT_DATA__\s*=\s*(\{.*?\})\s*</script>'),
    ("__STORE__", r'window\.__STORE__\s*=\s*(\{.*?\});\s*</script>'),
]:
    m2 = re.search(pat, resp.text, re.DOTALL)
    if m2:
        try:
            d = json.loads(m2.group(1))
            print(f"    {name} keys: {list(d.keys())[:15]}")
        except:
            print(f"    {name} found but couldn't parse")

title_m = re.search(r'<title>(.*?)</title>', resp.text)
if title_m:
    print(f"    Title: {title_m.group(1)}")

inputs = re.findall(r'<input[^>]*(?:name|id)="([^"]*)"', resp.text)
if inputs:
    print(f"    Form inputs: {inputs[:15]}")

api_hints = set(re.findall(r'(/v[12]/api/[a-zA-Z/_-]+|/api/auth[a-zA-Z/_-]*)', resp.text))
if api_hints:
    print(f"    API endpoints: {list(api_hints)[:10]}")

print(f"\n    Page size: {len(resp.text)} chars")
print(f"    First 800 chars of body:")
body_start = resp.text.find("<body")
if body_start > -1:
    print(resp.text[body_start:body_start+800])
else:
    print(resp.text[:800])

with open("cookie-dump/auth_state.json", "w") as f:
    json.dump({
        "csrf": csrf,
        "state": state,
        "cookies": all_cookies,
        "url": str(resp.url),
    }, f, indent=2)
print("\n[+] State saved to cookie-dump/auth_state.json")
