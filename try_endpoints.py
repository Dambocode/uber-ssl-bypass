"""Try all possible auth submit endpoints."""
import json, re
from curl_cffi.requests import Session

# Get fresh session
s = Session(impersonate="chrome146")
resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
print(f"Init: {resp.status_code}")

csrf = None
for c in s.cookies.jar:
    if c.name == "jwt-session":
        csrf = c.value

headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Origin": "https://auth.uber.com",
    "Referer": "https://auth.uber.com/v2/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "x-csrf-token": csrf or "",
}

payload = json.dumps({"phoneNumber": "+19148744178", "screenType": "PHONE_NUMBER_INITIAL"})

# Try all possible endpoint paths from the JS
paths = [
    "/v2/silk-screen/submit-form",
    "/v2/submit-form",
    "/silk-screen/submit-form",
    "/submit-form",
    "/v2/api/authenticate",
    "/v1/auth/authenticate",
    "/api/v2/authenticate",
    "/v2/silk-screen/prepare-field",
]

for path in paths:
    url = f"https://auth.uber.com{path}"
    r = s.post(url, data=payload, headers=headers, allow_redirects=False)
    preview = r.text[:120].replace("\n", " ")
    print(f"  {path:45s} -> {r.status_code} | {preview}")
