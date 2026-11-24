"""Parse __REDUX_STATE__ from auth page."""
import json, re

html = open("cookie-dump/auth_page.html", "r", encoding="utf-8").read()
m = re.search(r'id="__REDUX_STATE__"[^>]*>(.*?)</script>', html, re.DOTALL)
raw = m.group(1).strip()

# Unicode unescape
decoded = raw.encode().decode("unicode_escape")
data = json.loads(decoded)

# Save full parsed state
with open("cookie-dump/redux_state.json", "w") as f:
    json.dump(data, f, indent=2)

ac = data.get("appContext", {})
print("=== appContext ===")
print(f"  nextURL: {ac.get('nextURL')}")
print(f"  primaryIdentifier: {ac.get('primaryIdentifier')}")
print(f"  isEmbedded: {ac.get('isEmbedded')}")
print(f"  isWebview: {ac.get('isWebview')}")
print(f"  headers: {json.dumps(ac.get('headers', {}), indent=4)}")

nav = data.get("navigation", {})
print(f"\n=== navigation ===")
print(f"  currentScreen: {nav.get('currentScreen')}")
print(f"  currentEvent: {nav.get('currentEvent')}")

print(f"\n=== top-level keys ===")
print(f"  {list(data.keys())}")

# Find inAuthSessionID anywhere
def find_key(d, key, path=""):
    if isinstance(d, dict):
        for k, v in d.items():
            if k == key:
                print(f"  Found {key} at {path}.{k}: {str(v)[:60]}")
            find_key(v, key, f"{path}.{k}")
    elif isinstance(d, list):
        for i, v in enumerate(d):
            find_key(v, key, f"{path}[{i}]")

print(f"\n=== Searching for inAuthSessionID ===")
find_key(data, "inAuthSessionID")
find_key(data, "sessionId")
find_key(data, "in_auth_session_id")

# Check request/response structures
print(f"\n=== request info ===")
req = data.get("request", {})
print(f"  {json.dumps(req, indent=2)[:500] if req else 'empty'}")
