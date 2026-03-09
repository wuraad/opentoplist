"""
Lightweight load-test stub (stdlib only).
Run a local control-plane server first:
  python -m backend.app.api_server

Then execute:
  python tests/load_test_stub.py http://127.0.0.1:8080 200
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def post_json(url: str, payload: dict) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, resp.read().decode("utf-8")
    except Exception as exc:
        return 599, str(exc)


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: python tests/load_test_stub.py <base_url> <concurrency>")
        return 1

    base_url = sys.argv[1].rstrip("/")
    concurrency = int(sys.argv[2])

    payload = {"user_id": "demo", "password": "demo1234", "device_id": "load-test"}
    start = time.perf_counter()
    ok = 0
    fail = 0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(post_json, f"{base_url}/v1/auth/token", payload)
            for _ in range(concurrency)
        ]
        for future in as_completed(futures):
            status, _ = future.result()
            if status == 200:
                ok += 1
            else:
                fail += 1

    elapsed = time.perf_counter() - start
    print(
        json.dumps(
            {
                "concurrency": concurrency,
                "ok": ok,
                "fail": fail,
                "elapsed_sec": round(elapsed, 3),
            },
            ensure_ascii=False,
        )
    )
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
