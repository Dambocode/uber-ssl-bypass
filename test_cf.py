"""Test different impersonations against Cloudflare on auth.uber.com."""
from curl_cffi.requests import Session

browsers = ["chrome146", "chrome136", "chrome131", "safari184", "firefox147", "edge101"]

for browser in browsers:
    try:
        s = Session(impersonate=browser)
        resp = s.get("https://auth.uber.com/v2/", allow_redirects=True)
        cookies = [c.name for c in s.cookies.jar]
        title = ""
        import re
        m = re.search(r"<title>(.*?)</title>", resp.text[:2000])
        if m:
            title = m.group(1)
        blocked = resp.status_code == 403 or "blocked" in resp.text[:500].lower()
        print(f"  {browser:20s} -> {resp.status_code} | cookies={len(cookies)} | title={title[:40]} | {'BLOCKED' if blocked else 'OK'}")
    except Exception as e:
        print(f"  {browser:20s} -> ERROR: {e}")
