"""Try different payload formats for /v2/submit-form."""
import json, re
from curl_cffi.requests import Session

s = Session(impersonate="chrome146")
resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
print(f"Init: {resp.status_code}")

# Get cookies
cookies = {c.name: c.value for c in s.cookies.jar}
print(f"Cookies: {list(cookies.keys())}")

csrf = cookies.get("jwt-session", "")

base_headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Origin": "https://auth.uber.com",
    "Referer": "https://auth.uber.com/v2/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

url = "https://auth.uber.com/v2/submit-form"

# Try different payload structures
payloads = [
    {"phoneNumber": "+19148744178", "screenType": "PHONE_NUMBER_INITIAL"},
    {"formFields": {"phoneNumber": "+19148744178"}, "screenType": "PHONE_NUMBER_INITIAL"},
    {"phoneNumber": "+19148744178"},
    {"phone": "+19148744178"},
    {"answer": "+19148744178", "answerType": "PHONE_NUMBER_SUBMIT"},
    {"formFields": [{"fieldType": "PHONE_NUMBER", "value": "+19148744178"}]},
]

csrf_variations = [
    {"x-csrf-token": csrf},
    {"x-csrf-token": "x"},
    {},
]

for i, payload in enumerate(payloads):
    for j, csrf_h in enumerate(csrf_variations):
        headers = {**base_headers, **csrf_h}
        r = s.post(url, json=payload, headers=headers, allow_redirects=False)
        body = r.text[:200].replace("\n", " ")
        if r.status_code != 403 or j == 0:
            print(f"  payload[{i}] csrf[{j}] -> {r.status_code} | {body}")
        if r.status_code == 200 or (r.status_code != 403 and r.status_code != 400):
            break
    print()

# Also search the JS more carefully for the request structure
print("\nSearching JS for submit-form request building...")
js = open("cookie-dump/client-main-a0e00f483853fcc9.js", encoding="utf-8").read()

# Find the actual form submission code
for pat in [
    r'formFields\s*[=:]\s*\[([^\]]{10,200})\]',
    r'(phoneNumber|PHONE_NUMBER)[^}]{0,100}submit',
    r'requestObject\s*[=:]\s*(\{[^}]{10,200}\})',
]:
    ms = re.findall(pat, js)
    if ms:
        for m in ms[:3]:
            print(f"  [{pat[:30]}]: {m[:150]}")
