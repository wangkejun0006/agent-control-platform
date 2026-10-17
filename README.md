# Orbit · Agent任务编排与受控执行平台

基于既有控制平台改造的个人展示项目。以虚构“团队知识助手交付”为案例，贯通产品、技术、市场的规划、固定工具执行、显式交接、退回审核和本地交付。默认离线，无需模型密钥。

重点是执行权限、版本和失败处理：模型提出建议，宿主控制能否执行；评估通过后仍需审核；跨部门只共享获批准的明确产物版本。

## 先看案例（无需Node、数据库或模型）

环境：Ubuntu/WSL2、uv、Python3.14。项目根目录执行：

```bash
uv sync --locked
uv run --locked --offline python -m showcase.workbench.snapshot_view --port 8433
```

打开 http://127.0.0.1:8433/ ，查看市场v1/v2、退回与批准记录，下载完整交付ZIP。所需虚构快照已包含在`examples/delivery-snapshot/`，不依赖作者的私有.runtime。

**证据边界：** 产品、技术与市场v1为离线前置；市场v2是既有真实模型候选，随后在新隔离副本中完成零模型审核与交付。审核由自动化本机测试账号执行，不代表真人或生产批准。旧失败活动保持失败；查看页面不会产生模型费用。

## 操作完整工作台

另需Node24、npm11。首次安装需要包仓库网络，运行默认无需外网：

```bash
uv sync --locked --extra loopback-d0
npm ci --prefix packages/agent-authoring-toolkit --ignore-scripts
npm ci --prefix packages/orbit-control-plane-console --ignore-scripts
npm run build --prefix packages/orbit-control-plane-console
bash scripts/run_demo.sh
```

打开 http://127.0.0.1:8432/ 。首次创建本机管理员账号；在“Agent与工具”评价并明确批准内置候选；创建任务，导入13份虚构资料；依次完成三部门规划确认、执行、产物审核与显式交接。市场退回后产生新尝试，旧候选和意见保留；全部当前版本批准后生成本地ZIP。

完整工作台创建独立`.runtime/workbench/`。只读8433入口不打开此数据库。两者都仅监听本机，未配置常驻或开机启动。

## 核心能力

| 能力 | 实现与验证边界 |
|---|---|
| 规划与执行分离 | 原LangGraph澄清/任务包/确认，原Router与RuntimeComposer控制固定专业任务 |
| 受控实际工具 | 原SQL队列、签名Grant、单Worker和租约；工具在独立进程实际执行，不支持任意Shell或代码 |
| 跨部门交接 | 批准不等于共享，只允许目标部门、绑定版本和授权范围消费指定产物 |
| 返工与审核 | 精确候选摘要/版本批准、旧版拒绝、下游失效、幂等请求和历史保留 |
| 证据与预算 | 原Evaluator与来源门禁；可选模型统一预留，失败计数，默认不授权消费 |
| 生命周期与治理 | 固定Agent/Tool候选的登记、评价、批准、暂停，保留模型路线与审计入口 |

[架构与继承/新增划分](docs/ARCHITECTURE.md) · [五分钟演示](docs/DEMO_CURRENT.md) · [测试与干净环境验证](docs/VALIDATION.md)

![工作台页面](reports/sharing-workbench-desktop.png)

## 验证

```bash
uv run --locked --offline python scripts/validate_offline.py \
  --report .runtime/check-001/report.json --log .runtime/check-001/tests.log
```

报告路径必须全新。前端类型、单元、构建和浏览器命令见[验证文档](docs/VALIDATION.md)；E2E需要8432端口空闲。验证区分当前便携范围与依赖原领域/设备的排除项，不能声称原全量全部通过。GitHub Actions定义已提供，未上传前不声称CI已运行。

本次在白名单导出的新目录、新虚拟环境与新node_modules中完成安装和运行验证，未携带作者私有运行资料；共享了本机包缓存与浏览器。结果、跳过范围和未验证项见[发布候选检查报告](reports/release-readiness-20261017.json)。

历史模型失败、修复与审核记录保留，索引见[收尾前开发记录](docs/history/README-before-release-closeout-20261017.md)。当前真实模型传输仍为可选显式授权适配，不是默认开箱调用；本机兼容配置及预算边界见[模型配置](docs/MODEL_CONFIGURATION.md)。

## 能力边界

SQLite单Worker、本机Cookie身份、固定工具及有界中文检查；不是强OS沙箱、通用事实核验或生产高可用系统。Hermes/Codex Runtime、真实OIDC、Postgres多Worker和生产部署未验收。自然语言与检查PASS不能替代授权或人工判断。

## 来源与许可

MIT。项目所有者已确认公开范围；代码来源、继承能力、个人后续改造和第三方依赖边界见[NOTICE](NOTICE.md)。发布白名单为`release/manifest.json`；导出工具不包含私有运行目录、账号库、私钥、缓存或原Git历史，也不执行推送。
