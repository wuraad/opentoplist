# VPN 重开发并行开发计划（A~E）

## 并行流（Workstreams）

| 流 | 模块 | 负责人 | 关键产出 | 阻塞依赖 |
|---|---|---|---|---|
| WS-A | 控制平面 | 后端组 | 账号/token/设备绑定、节点健康与选路、管理端封禁与策略下发 API | 无 |
| WS-B | 数据平面 | 网关组 | WG 节点标准化脚本、限速与连接限制、异常端口阻断策略 | 无 |
| WS-C | 风控平面 | 后端+网关 | 风险评分模型、自动处置链路、投诉反查 | 需要 WS-A 会话数据 |
| WS-D | 客户端 | 客户端组 | 快连与重试、节点测速优选、弱网切换与埋点 | 需要 WS-A API 契约 |
| WS-E | 质量保障 | 测试/SRE | API自动化、E2E回归、压测、发布与回滚 | 全模块联调 |

## 本仓库当前落地状态

- A：`backend/app/api_server.py`（可启动基础 API 服务）
- B：`gateway/scripts/*.sh`（节点部署、限速、阻断）
- C：`backend/app/risk.py` + `/v1/risk/evaluate` + `/v1/complaints/trace`
- D：`docs/client-integration.md` + `client/android/ConnectionStateMachine.kt`
- E：`tests/*.py` + `docs/qa-release-runbook.md`

## 并行协作规则（建议）

1. **API 先行冻结**：WS-A 每日固定时间发布契约变更，WS-D 按版本号拉取。
2. **规则灰度发布**：WS-C 风控阈值从观察模式 -> 限速 -> 隔离 -> 封禁分阶段开启。
3. **网关策略分层**：WS-B 区分基础安全策略和高风险策略，两套模板可切换。
4. **回滚优先级**：WS-E 任何阶段均可触发：客户端回滚 > 控制面策略回滚 > 网关流量切离。

## 两周冲刺拆分（示例）

### Week 1
- A：完成 auth/device/node route/admin policy 四类 API
- B：完成 1 个区域节点模板化部署 + 基础流控策略
- C：完成风险评分 v1 + 自动处置动作映射
- D：完成连接状态机改造 + 新节点列表接入
- E：完成 API 冒烟集与核心场景回归脚本

### Week 2
- A：增加审计日志、策略版本管理
- B：补充异常流量检测指标与告警
- C：接入投诉邮件反查自动化
- D：完成弱网切换策略与诊断上报
- E：执行并发压测、断线重连压测、发布回滚演练
