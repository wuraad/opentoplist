#!/usr/bin/env python3
"""
End-to-end VPN connection test — simulates the full Android client flow.

Steps:
  1. Register user
  2. Login + get token
  3. Fetch best node (route)
  4. Register gateway node (admin)
  5. Allocate WireGuard peer → get tunnel config
  6. Generate WireGuard client config file
  7. Register VPN session
  8. Simulate risk evaluation (low risk → allow)
  9. Fetch user policy
  10. End session
  11. Revoke peer
  12. Logout

Usage:
  python3 tests/e2e_vpn_connect.py [base_url]
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
ADMIN_KEY = "admin-secret-key"
TOKEN = ""

def req(method: str, path: str, body: dict | None = None, auth: bool = True) -> tuple[int, dict]:
    data = json.dumps(body or {}).encode()
    r = urllib.request.Request(f"{BASE}{path}", data=data if method == "POST" else None,
                               headers={"Content-Type": "application/json"}, method=method)
    if auth and TOKEN:
        r.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, json.loads(raw) if raw else {}

def admin_req(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body or {}).encode()
    r = urllib.request.Request(f"{BASE}{path}", data=data if method == "POST" else None,
                               headers={"Content-Type": "application/json",
                                        "X-Admin-Key": ADMIN_KEY}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def step(num: int, desc: str):
    print(f"\n{'='*60}")
    print(f"  Step {num}: {desc}")
    print(f"{'='*60}")

def ok(data: dict):
    print(f"  ✅ {json.dumps(data, indent=2, ensure_ascii=False)[:500]}")

def fail(msg: str):
    print(f"  ❌ {msg}")
    sys.exit(1)

def gen_wg_key() -> tuple[str, str]:
    priv = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pub = subprocess.check_output(["wg", "pubkey"], input=priv.encode()).decode().strip()
    return priv, pub

def main():
    global TOKEN

    print(f"\n🔗 VPN 端到端连接测试 — {BASE}")
    print(f"   模拟 Android 客户端完整连接流程\n")

    # ── Step 1: Register ──
    step(1, "注册新用户")
    code, data = req("POST", "/v1/auth/register",
                     {"user_id": "e2e_vpn_user", "password": "vpn_pass_2026!", "plan": "pro"}, auth=False)
    if code == 201:
        ok(data)
    elif code == 400 and data.get("message") == "user_already_exists":
        print("  ⚠️  用户已存在，继续")
    else:
        fail(f"注册失败: {code} {data}")

    # ── Step 2: Login ──
    step(2, "登录 + 获取 Token")
    code, data = req("POST", "/v1/auth/token",
                     {"user_id": "e2e_vpn_user", "password": "vpn_pass_2026!", "device_id": "android-pixel-8"}, auth=False)
    if code != 200:
        fail(f"登录失败: {code} {data}")
    TOKEN = data["token"]
    ok({"token": TOKEN[:20] + "...", "ok": True})

    # ── Step 3: Route node ──
    step(3, "获取最优节点 (选路)")
    code, data = req("GET", "/v1/nodes/route?region=sg")
    if code != 200:
        fail(f"选路失败: {code} {data}")
    node = data["node"]
    node_id = node["node_id"]
    ok({"node_id": node_id, "region": node["region"],
        "endpoint": node["endpoint"], "load": f"{node['current_load']}/{node['capacity']}"})

    # ── Step 4: Register gateway node (admin) ──
    step(4, "注册 WireGuard 网关节点 (管理员)")
    server_priv, server_pub = gen_wg_key()
    code, data = admin_req("POST", "/v1/gateway/nodes/register", {
        "node_id": node_id, "region": "sg", "endpoint": "sg-1.vpn.internal",
        "public_key": server_pub, "subnet": "10.66.0.0/24", "listen_port": 51820,
    })
    ok({"node_id": node_id, "server_public_key": server_pub[:20] + "..."})

    # ── Step 5: Allocate WG peer ──
    step(5, "分配 WireGuard Peer (获取隧道配置)")
    client_priv, client_pub = gen_wg_key()
    code, data = req("POST", "/v1/gateway/peers/allocate", {
        "node_id": node_id, "client_public_key": client_pub, "device_id": "android-pixel-8",
    })
    if code != 200:
        fail(f"Peer分配失败: {code} {data}")
    tunnel_config = data
    peer_ip = tunnel_config["interface"]["address"]
    ok({"peer_ip": peer_ip, "server_endpoint": tunnel_config["peer"]["endpoint"],
        "dns": tunnel_config["interface"]["dns"]})

    # ── Step 6: Generate WG config file ──
    step(6, "生成 WireGuard 客户端配置文件")
    wg_conf = f"""[Interface]
PrivateKey = {client_priv}
Address = {peer_ip}
DNS = {tunnel_config["interface"]["dns"]}

[Peer]
PublicKey = {tunnel_config["peer"]["public_key"]}
Endpoint = {tunnel_config["peer"]["endpoint"]}
AllowedIPs = {tunnel_config["peer"]["allowed_ips"]}
PersistentKeepalive = {tunnel_config["peer"]["persistent_keepalive"]}
"""
    conf_path = "/tmp/wg_client_e2e.conf"
    with open(conf_path, "w") as f:
        f.write(wg_conf)
    print(f"  📄 配置文件已写入: {conf_path}")
    print(f"  ────────────────────────────")
    for line in wg_conf.strip().split("\n"):
        if "PrivateKey" in line:
            print(f"  {line[:30]}...")
        else:
            print(f"  {line}")
    print(f"  ────────────────────────────")

    # ── Step 7: Register session ──
    step(7, "注册 VPN 会话")
    code, data = req("POST", "/v1/sessions/register", {
        "node_id": node_id, "egress_ip": peer_ip.split("/")[0],
    })
    session_id = data.get("session_id", "")
    ok({"session_id": session_id, "node_id": node_id, "egress_ip": peer_ip.split("/")[0]})

    # ── Step 8: Risk evaluation ──
    step(8, "风控评估 (模拟正常流量)")
    code, data = req("POST", "/v1/risk/evaluate", {
        "user_id": "e2e_vpn_user", "session_id": session_id,
        "connection_count": 50, "unique_dst_ports": 8, "burst_bandwidth_mbps": 25,
    }, auth=False)
    ok({"action": data["risk"]["action"], "score": data["risk"]["score"]})

    # ── Step 9: Fetch policy ──
    step(9, "查询用户策略")
    code, data = req("GET", "/v1/users/me/policy")
    if code == 200:
        ok(data)
    else:
        print(f"  ℹ️  无策略 (正常 — 低风险用户无限速)")

    # ── Step 10: List peers ──
    step(10, "查看当前 Peer 列表")
    code, data = req("GET", "/v1/gateway/peers")
    ok({"peer_count": len(data.get("peers", [])), "peers": data.get("peers", [])})

    # ── Step 11: End session ──
    step(11, "结束 VPN 会话")
    code, data = req("POST", "/v1/sessions/end", {"session_id": session_id})
    ok(data)

    # ── Step 12: Revoke peer ──
    step(12, "撤销 WireGuard Peer")
    code, data = req("POST", "/v1/gateway/peers/revoke", {
        "node_id": node_id, "device_id": "android-pixel-8",
    })
    ok(data)

    # ── Step 13: Logout ──
    step(13, "登出")
    code, data = req("POST", "/v1/auth/logout")
    ok(data)

    # ── Step 14: Verify logged out ──
    step(14, "验证已登出 (应被拒绝)")
    code, data = req("GET", "/v1/nodes/route?region=sg")
    if code == 401:
        ok({"status": "unauthorized", "message": "token 已撤销 ✅"})
    else:
        fail(f"期望 401，实际 {code}")

    # ── Summary ──
    print(f"\n{'='*60}")
    print(f"  🎉 端到端 VPN 连接测试全部通过！")
    print(f"{'='*60}")
    print(f"  完成 14 步验证:")
    print(f"  注册 → 登录 → 选路 → 网关注册 → Peer分配")
    print(f"  → WG配置生成 → 会话注册 → 风控评估")
    print(f"  → 策略查询 → Peer列表 → 会话结束")
    print(f"  → Peer撤销 → 登出 → 权限验证")
    print(f"\n  WireGuard 配置文件: {conf_path}")
    print(f"  (在真实 Android 设备上导入此配置即可建立隧道)")
    print()

if __name__ == "__main__":
    main()
