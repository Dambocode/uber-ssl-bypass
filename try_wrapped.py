"""Try wrapping payload in {request: ...} format."""
import json, re, uuid
from curl_cffi.requests import Session

s = Session(impersonate="safari184")
resp = s.get("https://auth.uber.com/v2/?next_url=https%3A%2F%2Fdrivers.uber.com%2F", allow_redirects=True)
print(f"Init: {resp.status_code}")

if resp.status_code != 200:
    s = Session(impersonate="chrome146")
    resp = s.get("https://auth.uber.com/v2/?next_url=https%3A%2F%2Fdrivers.uber.com%2F", allow_redirects=True)
    print(f"Retry: {resp.status_code}")

cookies = {c.name: c.value for c in s.cookies.jar}
csrf = cookies.get("jwt-session", "")

# Parse Redux headers
m = re.search(r'id="__REDUX_STATE__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
raw = m.group(1).strip().encode().decode("unicode_escape")
redux = json.loads(raw)
uber_headers = redux.get("appContext", {}).get("headers", {})
print(f"Headers from Redux: {json.dumps(uber_headers)}")

base_headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Origin": "https://auth.uber.com",
    "Referer": "https://auth.uber.com/v2/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "x-csrf-token": csrf,
    "x-uber-request-uuid": str(uuid.uuid4()),
    **uber_headers,
}

inner_payload = {
    "formContainerAnswer": {
        "formAnswer": {
            "flowType": "SIGN_IN",
            "screenAnswers": [{
                "screenType": "PHONE_NUMBER_INITIAL",
                "eventType": "TYPE_INPUT_MOBILE",
                "fieldAnswers": [
                    {"fieldType": "PHONE_COUNTRY_CODE", "phoneCountryCode": "+1"},
                    {"fieldType": "PHONE_NUMBER", "phoneNumber": "9148744178"},
                ]
            }]
        }
    }
}

# Try different payload wrappings and paths
attempts = [
    ("/v2/submit-form", inner_payload, "bare payload"),
    ("/v2/submit-form", {"request": inner_payload}, "wrapped in {request}"),
    ("/v2/submit-form", inner_payload["formContainerAnswer"]["formAnswer"], "just formAnswer"),
    ("/v2/submit-form", {"request": inner_payload["formContainerAnswer"]["formAnswer"]}, "formAnswer in {request}"),
]

for path, payload, desc in attempts:
    url = f"https://auth.uber.com{path}"
    r = s.post(url, json=payload, headers=base_headers, allow_redirects=False)
    body = r.text[:200].replace("\n", " ")
    print(f"\n  [{desc}] -> {r.status_code} | {body}")
