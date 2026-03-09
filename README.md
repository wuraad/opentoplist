# opentoplist

一个按 A~E 模块并行开发的 VPN 重构基线仓库。

## 目录

- `backend/`：模块A（控制平面）+ 模块C（风控平面）基础实现
- `gateway/`：模块B（数据平面）网关脚本与策略模板
- `client/`：模块D 客户端连接状态机示例
- `docs/`：并行开发计划、客户端对接、QA 与发布回滚文档
- `tests/`：基础单元测试与轻量压测脚本

## 快速验证

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python -m backend.app.api_server
```