"""Extract product context and all config from the auth page."""
import json, re
from curl_cffi.requests import Session

s = Session(impersonate="safari184")
resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
print(f"Status: {resp.status_code}")

text = resp.text

# Find all script content (inline)
scripts = re.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL)
print(f"Found {len(scripts)} inline scripts")

for i, script in enumerate(scripts):
    if len(script) < 20:
        continue
    # Look for product/app config
    has_product = any(k in script for k in ['product', 'appName', 'clientId', 'flowType', 'standardFlow'])
    if has_product:
        print(f"\n  Script {i} ({len(script)} chars) has product info:")
        # Extract JSON-like objects
        for pat in [
            r'window\.__[A-Z_]+__\s*=\s*(\{.*?\});',
            r'self\.__next_f\.push\(\[.*?,\s*"(.*?)"\]\)',
        ]:
            ms = re.findall(pat, script, re.DOTALL)
            for m in ms[:2]:
                if len(m) > 50:
                    print(f"    {m[:300]}...")

    # Look for config JSON specifically
    if 'appConfig' in script or 'flowConfig' in script or 'uberClientId' in script:
        print(f"\n  Script {i} has app/flow config:")
        print(f"    {script[:500]}...")

# Search for specific product identifiers
for pat_name, pat in [
    ("product ID", r'"productId"\s*:\s*"([^"]+)"'),
    ("client ID", r'"clientId"\s*:\s*"([^"]+)"'),
    ("client name", r'"clientName"\s*:\s*"([^"]+)"'),
    ("app name", r'"appName"\s*:\s*"([^"]+)"'),
    ("flow type", r'"flowType"\s*:\s*"([^"]+)"'),
    ("standardFlow", r'"standardFlow"\s*:\s*(\{[^}]+\})'),
    ("appContext", r'"appContext"\s*:\s*(\{[^}]+\})'),
    ("uberApp", r'"uberApp"\s*:\s*"([^"]+)"'),
    ("next_url", r'"next_url"\s*:\s*"([^"]+)"'),
    ("nextURL", r'"nextURL"\s*:\s*"([^"]+)"'),
]:
    ms = re.findall(pat, text)
    if ms:
        for m in ms[:3]:
            print(f"  {pat_name}: {m[:100]}")

# Look for self.__next_f.push data (Next.js hydration)
next_pushes = re.findall(r'self\.__next_f\.push\(\[(\d+),"([^"]{50,})"\]\)', text)
print(f"\nFound {len(next_pushes)} next.js data chunks")
for idx, (num, chunk) in enumerate(next_pushes[:5]):
    # Unescape
    chunk = chunk.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
    if any(k in chunk for k in ['product', 'client', 'flow', 'appName', 'uber']):
        print(f"  Chunk {idx} ({len(chunk)} chars): {chunk[:300]}...")
