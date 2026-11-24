"""Try the proxy path and different content types."""
import json, re, uuid
from curl_cffi.requests import Session

s = Session(impersonate="chrome146")
resp = s.get("https://auth.uber.com/v2/?next_url=https%3A%2F%2Fdrivers.uber.com%2F", allow_redirects=True)
print(f"Init: {resp.status_code}")

m = re.search(r'id="__REDUX_STATE__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
raw = m.group(1).strip().encode().decode("unicode_escape")
redux = json.loads(raw)
uber_headers = redux.get("appContext", {}).get("headers", {})
cookies = {c.name: c.value for c in s.cookies.jar}
csrf = cookies.get("jwt-session", "")

payload = {
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

# The proxy function c does: fetch("/" + path, {body: JSON.stringify(r)})
# path = "submit-form"
# So it goes to "/submit-form" on the same host

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
    **uber_headers,
}

paths = [
    "/submit-form",
    "/v2/submit-form",
    # Maybe the proxy adds its own route prefix
    "/v2/silk-screen/submit-form",
]

for path in paths:
    url = f"https://auth.uber.com{path}"
    r = s.post(url, json=payload, headers=headers, allow_redirects=False)
    body = r.text[:200].replace("\n", " ")
    print(f"  {path:40s} -> {r.status_code} | {body}")

# Also try the actual RPC endpoint directly (non-proxied path)
# l() sends to "https://cn-geo1.uber.com/rt/" + path
# but for non-China, it would be a different host. Let me find it.
print("\nTrying direct RPC endpoints...")
rpc_hosts = [
    "https://cn-geo1.uber.com/rt/",
    "https://m.uber.com/rt/",
    "https://api.uber.com/rt/",
]

for host in rpc_hosts:
    url = f"{host}submit-form"
    try:
        r = s.post(url, json=payload, headers={**headers, "Content-Type": "application/json"}, allow_redirects=False, timeout=10)
        body = r.text[:150].replace("\n", " ")
        print(f"  {url:50s} -> {r.status_code} | {body}")
    except Exception as e:
        print(f"  {url:50s} -> Error: {e}")
