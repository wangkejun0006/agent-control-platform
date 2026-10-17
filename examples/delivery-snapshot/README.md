# 可分发的虚构交付案例

该目录让全新克隆无需私有.runtime、数据库、模型密钥即可启动只读展示：

```bash
uv sync --locked
uv run --locked --offline python -m showcase.workbench.snapshot_view --port 8433
```

final-workflow.json只保留页面所需候选和历史；validation-report.json为已完成零模型审核报告的选定字段，不是新增真实验证。local-delivery.zip与原交付包字节一致，含三部门正文、实际工具回执、引用与审核记录。

上游及市场v1为离线虚构前置；市场v2为既有真实模型候选；批准是自动化合成测试账号操作。没有真实个人或公司业务数据，不声称生产可用或用户真人批准。
