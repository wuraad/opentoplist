# 模块D：客户端对接说明（Android 优先）

## 1. 连接流程改造（快连 + 失败重试）

1. App 启动后调用 `POST /v1/auth/token`
2. 获取 token 后调用 `GET /v1/nodes/route?user_id=...&region=...`
3. 采用返回节点配置建立 WireGuard 隧道
4. 若连接失败，执行指数退避重试（1s, 2s, 4s, 8s，上限 20s）
5. 连续失败超过阈值（如 4 次）后切换到下一个候选节点

## 2. 节点测速与优选

- 每个候选节点采集 3 项指标：`latency_ms`、`packet_loss`、`jitter_ms`
- 评分公式（示例）：
  - `score = latency * 0.5 + packet_loss * 40 + jitter * 0.5`
- 选择分数最低节点，若分数接近则优先当前区域节点

## 3. 弱网切换策略

- 判定条件（任一满足）：
  - RTT > 350ms 持续 10s
  - 丢包 > 8% 持续 10s
  - 业务心跳连续 3 次失败
- 动作：
  1. 保持当前连接并预热备选节点
  2. 新连接成功后再切流（避免瞬断）

## 4. 可观测性埋点（不采内容）

建议事件：
- `vpn_connect_start`
- `vpn_connect_success`
- `vpn_connect_fail`
- `vpn_node_switch`
- `vpn_weak_network_detected`

建议字段：
- `user_id_hash`
- `device_id_hash`
- `node_id`
- `carrier`
- `network_type`
- `latency_ms`
- `packet_loss`
- `error_code`

> 隐私要求：仅采集网络质量与错误元数据，不采集用户内容流量。
