# 可复现验证

建议Ubuntu/WSL2、Python3.14、Node24、npm11和uv。依赖由uv.lock和两个package-lock.json锁定；Python包声明的兼容范围不代表每个版本都已验收。首次安装需要包仓库网络；安装后默认演示不需要模型或外网。

```bash
uv sync --locked --extra loopback-d0
uv run --locked --offline python scripts/validate_offline.py \
  --report .runtime/check-001/report.json --log .runtime/check-001/tests.log
npm ci --prefix packages/agent-authoring-toolkit --ignore-scripts
npm test --prefix packages/agent-authoring-toolkit
npm run verify:bundle --prefix packages/agent-authoring-toolkit
npm ci --prefix packages/orbit-control-plane-console --ignore-scripts
npm run lint --prefix packages/orbit-control-plane-console
npm test --prefix packages/orbit-control-plane-console
npm run build --prefix packages/orbit-control-plane-console
(cd packages/orbit-control-plane-console && npx playwright install chromium)
npm run test:e2e --prefix packages/orbit-control-plane-console
```

测试报告与日志路径必须全新；重复运行换目录，不覆盖旧记录。Python验证器自动发现当前test_*.py，保留明确的旧领域/设备/外部运行源排除清单，并分别报告失败、跳过和排除，不能称原全量通过。测试使用假传输而不发起模型请求。历史响应重现用例在公开包缺少私有原文件时明确跳过，不使用新结果改写旧失败。

浏览器安装命令建议在console目录使用`npx playwright install chromium`。已有兼容浏览器时可通过PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH选择，不复制浏览器安装目录。E2E使用独立临时数据库，端口8432须空闲，不复用用户工作台。

发布候选由白名单导出：

```bash
uv run --locked --offline python scripts/export_release.py --output /tmp/orbit-candidate-001
```

目的目录必须不存在。候选不含.runtime、虚拟环境、node_modules、账号库、私钥、缓存、原Git历史或一次性脱敏替换脚本。发布前应对导出内容复核并在该目录重新安装依赖验证；导出并不执行Git提交、推送或公开。

`.github/workflows/offline.yml`为将来上传后的离线行为验证定义；本地收尾不会实际运行GitHub Actions。包安装与浏览器下载是联网步骤，不是模型请求。

历史机器报告保持原样。当前收尾结果另存`reports/release-readiness-20261017.json`；该报告生成前不得将本轮写为全部通过。源码安装和共享下载缓存的验证不等于全新物理机器、空缓存或生产部署验收。

## GitHub Runner portability note

The optional PowerShell-to-WSL native transport harness also requires
`deploy/lan-stage1/department-device/OrbitFirstInstall.ps1`. The portable
portfolio does not bundle that device installer. These tests are reported as
skipped even when PowerShell is preinstalled; they remain enabled when both
dependencies exist. This does not verify Windows/WSL deployment. The initial
GitHub run 39098883371 failed on this missing asset and remains a failed run.

## P0 页面验收（全新账号、离线返工和最终审核）

前端构建后，确认8432端口空闲，在前端目录执行：

```bash
npx playwright install chromium
npx playwright test --config playwright.p0.config.js --output /tmp/orbit-p0-result-001
```

输出路径须自行选取全新目录。默认使用新的临时工作台目录；也可用
`ORBIT_P0_ACCEPTANCE_STATE_ROOT`指定一个未使用的/tmp子目录或项目
`.runtime/workbench/`子目录。不要指定已有案例。本用例通过页面创建管理员、
评价/批准候选、创建任务、导入虚构资料、依次规划执行和交接，再退回市场初稿，
检查新版实质修改、最终待办与概览跳转、刷新和实际ZIP下载。没有API预置步骤，
外部浏览器请求会被阻止；仅验收受支持的离线模板，不认证任意自然语言返工。

`tests/test_offline_rework.py`覆盖原失败表达、未知/混合/否定/条件意见、
意见回显或伪造处理表；集成回归确认未解决要求不能批准且旧候选保持不变。


## P1 可用性页面验收

在前端目录、8432端口空闲时执行：

```bash
ORBIT_P1_ACCEPTANCE_STATE_ROOT=/tmp/orbit-p1-case-001 \
npx playwright test --config playwright.p1.config.js --output /tmp/orbit-p1-evidence-001
```

案例及输出目录必须全新，不要指向已有数据库或历史证据。此用例不使用API预置：
从本机账号开始，验证首页准备清单、任务中进入资源配置、刷新后返回原任务、
未交接部门等待、资料就绪后的规划入口、实际工具执行终态、交接后进入接收部门、
返工原意见与正文新增/删除行、最终待办和真实ZIP下载。支持本机已有Chromium的
显式可执行路径覆盖，方式同原Playwright配置。测试仅使用离线固定工具和模板，
不能作为任意业务资料、真实模型或多人企业身份的验收。

状态投影只读取当前持久对象：执行完成与候选批准分开，旧交接不会自动匹配新尝试。
历史对象及台账不为界面文案而改写。差异比较只比较业务正文，最多前500行；
超出范围会提示核查完整原文。检查项仅在页面按名称合并，任一同名失败仍显示失败，
原始独立检查记录保留在候选与交付证据中。
