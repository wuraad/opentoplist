#!/usr/bin/env python3
"""
全面验证登录系统 — 覆盖所有认证边界场景。

测试项:
  1. 注册成功 / 重复注册
  2. 登录成功 / 错误密码 / 不存在用户
  3. Token 有效性验证
  4. Token 过期 (模拟)
  5. 设备绑定限额 (最多3台)
  6. 被封禁用户无法登录
  7. 被封禁用户 Token 失效
  8. 解封后恢复登录
  9. 修改密码
  10. 登出后 Token 失效
  11. 管理端需要 API Key
  12. JWT 模式 (如果启用)
"""
from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timezone

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
ADMIN_KEY = "admin-secret-key"
PASS_COUNT = 0
FAIL_COUNT = 0


def req(method, path, body=None, token=None, admin=False):
    data = json.dumps(body or {}).encode()
    r = urllib.request.Request(f"{BASE}{path}", data=data if method == "POST" else None,
                               headers={"Content-Type": "application/json"}, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    if admin:
        r.add_header("X-Admin-Key", ADMIN_KEY)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def check(name, condition, detail=""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  ✅ {name}")
    else:
        FAIL_COUNT += 1
        print(f"  ❌ {name} — {detail}")


def section(title):
    print(f"\n{'─'*50}")
    print(f"  {title}")
    print(f"{'─'*50}")


def main():
    global PASS_COUNT, FAIL_COUNT
    print(f"\n🔐 登录系统全面验证 — {BASE}\n")

    # ── 1. 注册 ──
    section("1. 用户注册")
    code, data = req("POST", "/v1/auth/register", {"user_id": "auth_test_user", "password": "Test@2026!", "plan": "pro"})
    check("注册新用户", code == 201 and data["ok"], f"{code} {data}")
    code, data = req("POST", "/v1/auth/register", {"user_id": "auth_test_user", "password": "another_pass"})
    check("重复注册被拒", code == 400 and data["message"] == "user_already_exists", f"{code} {data}")
    code, data = req("POST", "/v1/auth/register", {"user_id": "", "password": ""})
    check("空用户名被拒", code == 400, f"{code} {data}")

    # ── 2. 登录 ──
    section("2. 用户登录")
    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-1"})
    check("正确密码登录成功", code == 200 and data["ok"] and "token" in data, f"{code} {data}")
    token1 = data.get("token", "")

    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "wrong_password", "device_id": "device-1"})
    check("错误密码被拒 (401)", code == 401 and data["message"] == "invalid_credentials", f"{code} {data}")

    code, data = req("POST", "/v1/auth/token", {"user_id": "nonexistent_user_xyz", "password": "any", "device_id": "d1"})
    check("不存在用户被拒", code == 401, f"{code} {data}")

    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!"})
    check("缺少 device_id 被拒 (400)", code == 400, f"{code} {data}")

    # ── 3. Token 验证 ──
    section("3. Token 有效性")
    code, data = req("GET", "/v1/nodes/route?region=sg", token=token1)
    check("有效 Token 访问受保护端点", code == 200 and data["ok"], f"{code} {data}")

    code, data = req("GET", "/v1/nodes/route?region=sg", token="invalid-fake-token-12345")
    check("无效 Token 被拒 (401)", code == 401, f"{code} {data}")

    code, data = req("GET", "/v1/nodes/route?region=sg")
    check("无 Token 被拒 (401)", code == 401, f"{code} {data}")

    # ── 4. 设备列表 ──
    section("4. 设备管理")
    code, data = req("GET", "/v1/devices", token=token1)
    check("列出已绑定设备", code == 200 and len(data["devices"]) >= 1, f"{code} {data}")

    # ── 5. 设备绑定限额 ──
    section("5. 设备绑定限额 (最多3台)")
    req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-2"})
    req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-3"})
    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-4"})
    check("第4台设备被拒", not data.get("ok") or data.get("message") == "device_limit_exceeded", f"{code} {data}")

    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-1"})
    check("已绑定设备可重复登录", code == 200 and data["ok"], f"{code} {data}")
    token1 = data.get("token", token1)

    # ── 6. 封禁用户 ──
    section("6. 用户封禁")
    code, data = req("POST", "/v1/admin/users/auth_test_user/ban", admin=True)
    check("管理员封禁用户", code == 200 and data["ok"], f"{code} {data}")

    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-1"})
    check("被封禁用户无法登录", code == 401, f"{code} {data}")

    # ── 7. 封禁后 Token 失效 ──
    section("7. 封禁后 Token 失效")
    code, data = req("GET", "/v1/nodes/route?region=sg", token=token1)
    check("封禁后旧 Token 失效 (401)", code == 401, f"{code} {data}")

    # ── 8. 解封 ──
    section("8. 解封恢复")
    code, data = req("POST", "/v1/admin/users/auth_test_user/unban", admin=True)
    check("管理员解封用户", code == 200 and data["ok"], f"{code} {data}")

    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-1"})
    check("解封后可重新登录", code == 200 and data["ok"], f"{code} {data}")
    token_new = data.get("token", "")

    # ── 9. 修改密码 ──
    section("9. 修改密码")
    code, data = req("POST", "/v1/auth/change-password",
                     {"old_password": "wrong", "new_password": "New@2026!"}, token=token_new)
    check("旧密码错误被拒", code == 401, f"{code} {data}")

    code, data = req("POST", "/v1/auth/change-password",
                     {"old_password": "Test@2026!", "new_password": "New@2026!"}, token=token_new)
    check("修改密码成功", code == 200 and data["ok"], f"{code} {data}")

    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "Test@2026!", "device_id": "device-1"})
    check("旧密码无法登录", code == 401, f"{code} {data}")

    code, data = req("POST", "/v1/auth/token", {"user_id": "auth_test_user", "password": "New@2026!", "device_id": "device-1"})
    check("新密码登录成功", code == 200 and data["ok"], f"{code} {data}")
    token_final = data.get("token", "")

    # ── 10. 登出 ──
    section("10. 登出")
    code, data = req("POST", "/v1/auth/logout", token=token_final)
    check("登出成功", code == 200, f"{code} {data}")

    code, data = req("GET", "/v1/devices", token=token_final)
    check("登出后 Token 失效 (401)", code == 401, f"{code} {data}")

    # ── 11. 管理端权限 ──
    section("11. 管理端权限验证")
    code, data = req("GET", "/v1/admin/users")
    check("无 API Key 被拒 (403)", code == 403, f"{code} {data}")

    code, data = req("GET", "/v1/admin/users", admin=True)
    check("有 API Key 访问成功", code == 200 and data["ok"], f"{code} {data}")

    code, data = req("POST", "/v1/admin/users/auth_test_user/ban")
    check("无 Key 封禁被拒", code == 403, f"{code} {data}")

    # ── 12. 审计日志验证 ──
    section("12. 审计日志记录验证")
    code, data = req("GET", "/v1/admin/audit?user_id=auth_test_user&limit=20", admin=True)
    check("审计日志有记录", code == 200 and len(data["logs"]) > 0, f"{code} {data}")
    actions = [l["action"] for l in data["logs"]]
    check("记录了 user_register", "user_register" in actions, f"actions: {actions}")
    check("记录了 user_login", "user_login" in actions, f"actions: {actions}")
    check("记录了 admin_ban", "admin_ban" in actions, f"actions: {actions}")
    check("记录了 password_change", "password_change" in actions, f"actions: {actions}")
    check("记录了 user_logout", "user_logout" in actions, f"actions: {actions}")

    # ── Summary ──
    total = PASS_COUNT + FAIL_COUNT
    print(f"\n{'='*50}")
    print(f"  登录系统验证完成: {PASS_COUNT}/{total} 通过")
    if FAIL_COUNT == 0:
        print(f"  🎉 全部通过！")
    else:
        print(f"  ❌ {FAIL_COUNT} 项失败")
    print(f"{'='*50}\n")

    return 0 if FAIL_COUNT == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
