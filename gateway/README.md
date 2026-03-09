# 模块B：数据平面（网关）

## 目录

- `scripts/provision_wg_node.sh`：WireGuard 节点标准化部署
- `scripts/apply_traffic_controls.sh`：流量整形与连接限额基线
- `scripts/apply_egress_policy.sh`：SMTP/扫描/异常端口阻断策略

## 快速执行

```bash
sudo bash scripts/provision_wg_node.sh <PUBLIC_IP_OR_DNS> <WG_PRIVATE_KEY>
sudo bash scripts/apply_traffic_controls.sh eth0 500
sudo bash scripts/apply_egress_policy.sh
```

> 注意：生产环境请根据上游运营商和合规要求进一步收紧策略，尤其是 UDP 端口集合、SYN 限速阈值、以及每用户带宽上限。
