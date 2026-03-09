# 模块B：数据平面（网关脚本）

## 脚本清单

| 脚本 | 用途 | 权限要求 |
|------|------|----------|
| `provision_wg_node.sh` | WireGuard 节点标准化部署 | root |
| `apply_traffic_controls.sh` | 全局流量整形（HTB + fq_codel） | root |
| `apply_egress_policy.sh` | nftables 出口策略（SMTP/反射阻断） | root |
| `apply_per_user_limits.sh` | Per-user 带宽限额 + 连接数限额 | root |
| `detect_port_scan.sh` | 端口扫描检测与自动封锁 | root |

## 快速使用

```bash
# 部署 WireGuard 节点
sudo bash scripts/provision_wg_node.sh sg-1 sg sg-1.vpn.example.com

# 全局流量控制（500 Mbit）
sudo bash scripts/apply_traffic_controls.sh eth0 500

# 出口策略（SMTP / 反射端口阻断）
sudo bash scripts/apply_egress_policy.sh

# Per-user 限速（50 Mbit）+ 连接限额（500）
sudo bash scripts/apply_per_user_limits.sh eth0 10.66.0.2 50 500

# 端口扫描检测（阈值20端口/10s，封锁300s）
sudo bash scripts/detect_port_scan.sh 20 300
```

## 设计说明

- 所有脚本幂等，可重复执行。
- `apply_per_user_limits.sh` 由控制平面在风控 THROTTLE 时自动调用。
- 扫描检测使用 nftables `meter` + 动态集合，零外部依赖。
- 生产环境建议通过 Ansible/systemd 管理脚本调用。
