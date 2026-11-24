"""Extract Uber cookies from Chrome browser."""
import browser_cookie3
import json

try:
    cj = browser_cookie3.chrome(domain_name=".uber.com")
    cookies = {}
    for c in cj:
        cookies[c.name] = {
            "value": c.value[:80] + ("..." if len(c.value) > 80 else ""),
            "domain": c.domain,
            "path": c.path,
            "secure": c.secure,
        }

    print(f"Found {len(cookies)} cookies for .uber.com\n")

    by_domain = {}
    for name, info in cookies.items():
        d = info["domain"]
        if d not in by_domain:
            by_domain[d] = []
        by_domain[d].append(name)

    for d in sorted(by_domain.keys()):
        print(f"  {d}: {', '.join(sorted(by_domain[d]))}")

    print("\n--- Key cookies ---")
    for name in sorted(cookies.keys()):
        if any(x in name.lower() for x in ("csrf", "sid", "session", "token", "auth", "jwt")):
            info = cookies[name]
            print(f"  {name:30s} = {info['value'][:60]:60s} [{info['domain']}]")

    export = {c.name: c.value for c in cj}
    with open("cookie-dump/chrome_cookies.json", "w") as f:
        json.dump(export, f, indent=2)
    print(f"\nExported {len(export)} cookies to cookie-dump/chrome_cookies.json")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
