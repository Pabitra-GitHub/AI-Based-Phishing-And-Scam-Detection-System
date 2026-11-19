"""PhishGuard AI - Wait for Backend Health Script
Polls http://127.0.0.1:8000/api/v1/health until healthy or timeout.
"""
import sys
import time
import urllib.request


def wait_for_health(timeout_seconds: int = 30) -> bool:
    start_time = time.time()
    url = "http://127.0.0.1:8000/api/v1/health"
    while time.time() - start_time < timeout_seconds:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as response:
                if response.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


if __name__ == "__main__":
    if wait_for_health():
        print("Backend service is healthy!")
        sys.exit(0)
    else:
        print("Backend service did not respond within timeout.", file=sys.stderr)
        sys.exit(1)
