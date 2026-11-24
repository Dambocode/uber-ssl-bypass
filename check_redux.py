"""Inspect Redux state deeply to find required fields."""
import json, re

# Re-fetch with driver URL for fresh state
from curl_cffi.requests import Session
s = Session(impersonate="safari184")
resp = s.get("https://auth.uber.com/v2/?next_url=https%3A%2F%2Fdrivers.uber.com%2F", allow_redirects=True)

m = re.search(r'id="__REDUX_STATE__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
raw = m.group(1).strip().encode().decode("unicode_escape")
d = json.loads(raw)

with open("cookie-dump/redux_state_driver.json", "w") as f:
    json.dump(d, f, indent=2)

print("=== Full Redux State Structure ===\n")
for key in d:
    val = d[key]
    if isinstance(val, dict):
        print(f"{key}: {{")
        for k2, v2 in val.items():
            v_str = json.dumps(v2)
            if len(v_str) > 100:
                v_str = v_str[:100] + "..."
            print(f"  {k2}: {v_str}")
        print("}")
    else:
        print(f"{key}: {json.dumps(val)[:200]}")
    print()

# Also check the FUSION_PLUGIN_PARAMETERS
m2 = re.search(r'id="__FUSION_PLUGIN_PARAMETERS__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
if m2:
    raw2 = m2.group(1).strip().encode().decode("unicode_escape")
    params = json.loads(raw2)
    print("\n=== Fusion Parameters (driver-related) ===")
    for k, v in params.get("parameters", {}).items():
        if any(x in k.lower() for x in ("driver", "earner", "phone", "product")):
            print(f"  {k}: {v.get('value')}")
