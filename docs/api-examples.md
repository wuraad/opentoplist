# API 调用示例

> 假设服务运行在 `http://127.0.0.1:8080`

## 1) 登录并签发 token

```bash
curl -X POST http://127.0.0.1:8080/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"user_id":"demo","password":"demo1234","device_id":"android-001"}'
```

## 2) 节点选路

```bash
curl "http://127.0.0.1:8080/v1/nodes/route?user_id=demo&region=sg"
```

## 3) 节点心跳上报

```bash
curl -X POST http://127.0.0.1:8080/v1/nodes/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "node_id":"sg-2",
    "region":"sg",
    "endpoint":"sg-2.vpn.internal:51820",
    "capacity":800,
    "current_load":100,
    "avg_latency_ms":22,
    "packet_loss_ratio":0.01,
    "healthy":true
  }'
```

## 4) 风险评估

```bash
curl -X POST http://127.0.0.1:8080/v1/risk/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "user_id":"demo",
    "session_id":"s-abcd",
    "connection_count":1800,
    "unique_dst_ports":220,
    "burst_bandwidth_mbps":560
  }'
```

## 5) 投诉反查

```bash
curl -X POST http://127.0.0.1:8080/v1/complaints/trace \
  -H "Content-Type: application/json" \
  -d '{
    "egress_ip":"203.0.113.5",
    "observed_at":"2026-03-09T12:00:00+00:00",
    "window_minutes":15
  }'
```
