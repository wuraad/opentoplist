# 模块A + 模块C：控制平面与风控平面

## 快速启动

```bash
python -m backend.app.api_server
```

服务默认监听：`0.0.0.0:8080`

## 核心 API

- `POST /v1/auth/token`：账号 + token 签发 + 设备首次绑定
- `POST /v1/devices/bind`：设备绑定
- `POST /v1/nodes/heartbeat`：节点健康上报
- `GET /v1/nodes/route`：节点选路
- `POST /v1/admin/users/{user_id}/ban`：封禁用户
- `POST /v1/admin/users/{user_id}/policy`：策略下发
- `POST /v1/risk/evaluate`：风险评分与动作判定
- `POST /v1/complaints/trace`：投诉反查（出口 IP + 时间窗）

## 设计说明

- 当前实现采用内存存储，便于快速联调。
- 生产建议替换为持久化存储（PostgreSQL/Redis）与消息队列。
