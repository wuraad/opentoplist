"""
Lightweight load-test stub (stdlib only).
Run a local control-plane server first:
  python -m backend.app.api_server

Usage:
  python tests/load_test_stub.py <base_url> <concurrency> [scenario]

Scenarios:
  auth      - Concurrent login attempts (default)
  mixed     - Mixed: login + route + risk evaluate
  reconnect - Simulate disconnect/reconnect cycles
"""

from __future__ import annotations

import json
import random
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def post_json(url: str, payload: dict, headers: dict | None = None) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except Exception as exc:
        return 599, str(exc)


def get_json(url: str, headers: dict | None = None) -> tuple[int, str]:
    hdrs = headers or {}
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except Exception as exc:
        return 599, str(exc)


def scenario_auth(base_url: str, _i: int) -> tuple[int, str]:
    payload = {"user_id": "demo", "password": "demo1234", "device_id": "load-device"}
    return post_json(f"{base_url}/v1/auth/token", payload)


def scenario_mixed(base_url: str, i: int) -> tuple[int, str]:
    ops = ["auth", "route", "risk"]
    op = ops[i % len(ops)]

    if op == "auth":
        return scenario_auth(base_url, i)
    elif op == "route":
        status, body = post_json(
            f"{base_url}/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "mix-device"},
        )
        if status != 200:
            return status, body
        token = json.loads(body).get("token", "")
        return get_json(
            f"{base_url}/v1/nodes/route?region=sg",
            headers={"Authorization": f"Bearer {token}"},
        )
    else:
        return post_json(
            f"{base_url}/v1/risk/evaluate",
            {
                "user_id": "demo",
                "session_id": f"load-s-{i}",
                "connection_count": random.randint(10, 400),
                "unique_dst_ports": random.randint(1, 40),
                "burst_bandwidth_mbps": random.randint(5, 150),
            },
        )


def scenario_reconnect(base_url: str, i: int) -> tuple[int, str]:
    device_id = "reconnect-device"
    status, body = post_json(
        f"{base_url}/v1/auth/token",
        {"user_id": "demo", "password": "demo1234", "device_id": device_id},
    )
    if status != 200:
        return status, body

    token = json.loads(body).get("token", "")
    auth_hdr = {"Authorization": f"Bearer {token}"}

    get_json(f"{base_url}/v1/nodes/route?region=sg", headers=auth_hdr)

    post_json(f"{base_url}/v1/auth/logout", {}, headers=auth_hdr)

    time.sleep(random.uniform(0.01, 0.05))

    status2, body2 = post_json(
        f"{base_url}/v1/auth/token",
        {"user_id": "demo", "password": "demo1234", "device_id": device_id},
    )
    return status2, body2


SCENARIOS = {
    "auth": scenario_auth,
    "mixed": scenario_mixed,
    "reconnect": scenario_reconnect,
}


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: python tests/load_test_stub.py <base_url> <concurrency> [scenario]")
        print(f"Scenarios: {', '.join(SCENARIOS.keys())}")
        return 1

    base_url = sys.argv[1].rstrip("/")
    concurrency = int(sys.argv[2])
    scenario_name = sys.argv[3] if len(sys.argv) > 3 else "auth"

    if scenario_name not in SCENARIOS:
        print(f"Unknown scenario: {scenario_name}. Available: {', '.join(SCENARIOS.keys())}")
        return 1

    scenario_fn = SCENARIOS[scenario_name]

    start = time.perf_counter()
    ok = 0
    fail = 0

    with ThreadPoolExecutor(max_workers=min(concurrency, 100)) as pool:
        futures = [
            pool.submit(scenario_fn, base_url, i) for i in range(concurrency)
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
                "scenario": scenario_name,
                "concurrency": concurrency,
                "ok": ok,
                "fail": fail,
                "elapsed_sec": round(elapsed, 3),
                "rps": round(concurrency / elapsed, 1) if elapsed > 0 else 0,
            },
            ensure_ascii=False,
        )
    )
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
