"""Extract __REDUX_STATE__ and other JSON from auth page."""
import json, re
from curl_cffi.requests import Session

s = Session(impersonate="safari184")
resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
print(f"Status: {resp.status_code}\n")

ids_to_extract = [
    "__REDUX_STATE__",
    "__FUSION_UNIVERSAL_VALUES__",
    "__FUSION_PLUGIN_PARAMETERS__",
    "__DID__",
    "__DID_V__",
    "__PWV_DEVICE_INFO__",
]

for script_id in ids_to_extract:
    pat = rf'id="{script_id}"[^>]*>(.*?)</script>'
    m = re.search(pat, resp.text, re.DOTALL)
    if m:
        raw = m.group(1).strip()
        try:
            data = json.loads(raw)
            text = json.dumps(data, indent=2)
            print(f"=== {script_id} ({len(text)} chars) ===")
            if len(text) > 3000:
                print(text[:3000] + "\n...")
            else:
                print(text)
            # Save full version
            with open(f"cookie-dump/{script_id.strip('_').lower()}.json", "w") as f:
                json.dump(data, f, indent=2)
        except json.JSONDecodeError:
            print(f"=== {script_id} (raw, {len(raw)} chars) ===")
            print(raw[:1000])
    else:
        print(f"=== {script_id}: NOT FOUND ===")
    print()
