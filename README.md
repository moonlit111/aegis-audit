**AegisAudit** 是基于大模型多智能体的软件漏洞挖掘与验证项目，面向源码和二进制开展程序理解、安全审计、独立复核及利用验证，使用历史漏洞检验通用分析能力。

已确定技术栈：Rust + Axum/Tokio、Svelte + TypeScript、Connect RPC、SQLite；Python/Java 用于必要的工具适配。

当前版本为 **0.1.0：程序结构分析工作台**，已实现浏览器导入、真实源码/二进制解析、任务与事件持久化、代码及调用关系展示、JSON / HTML / Markdown 报告导出。

支持 Python、Go、C、C++ 源码，以及 PE x86/x64、ELF x86_64。源码使用 Tree-sitter；二进制使用 Ghidra Headless。源码调用边标记为推断或未解析，伪代码只做函数级地址映射。解析失败、覆盖缺口和未执行的检查均保留在界面与报告中。

**这还不是完整的漏洞挖掘系统。** DeepSeek 官方连接检测、JSON 响应校验和用量记录已接通。多智能体审计、去壳/解混淆、动态模糊测试、利用验证和正式课程样本验收将在后续阶段实现；目前没有已通过的正式漏洞验收案例。原课程要求不作删减，见[首轮交付记录](Docs/首轮交付记录.md)和[正式样本筛选](Docs/正式样本筛选.md)。

在具备 Python 3.9+、Git 和 C/C++ 构建工具的环境中运行：

```bash
python3 scripts/bootstrap.py
python3 scripts/manage.py build
python3 scripts/manage.py doctor
python3 scripts/manage.py start --open
```

Windows PowerShell 将 `python3` 换成 `py -3`。Windows 原生构建需 Visual Studio Build Tools 的“使用 C++ 的桌面开发”和 Windows SDK。工具安装在项目 `.tools/` 及独立 Ghidra 缓存中，不修改全局 shell 配置。具体前提、版本、运行包和排错见[安装与运行](Docs/安装与运行.md)。

打开 **http://127.0.0.1:7331**，新建项目，导入 ZIP / 本地文件夹 / HTTPS Git 指定版本 / PE 或 ELF，等待快照就绪后点击“开始结构分析”。任务不依赖浏览器保持连接。

```bash
python3 scripts/manage.py stop        # 停止进程，保留本地数据
python3 scripts/manage.py check       # Rust、协议、前端检查
python3 scripts/aegis.py pnpm --dir frontend exec playwright install chromium
python3 scripts/e2e.py                # 使用真实独立服务和执行器的浏览器测试
python3 tests/smoke.py --binary --git  # 对已启动服务执行真实解析与报告测试
python3 scripts/package.py           # 生成当前平台运行包及依赖许可证
```

服务数据库、源文件、日志、凭据在 `.data/`，均不提交到 Git。默认只有本机浏览器能建立操作会话。首轮不会执行导入目标的构建脚本或运行目标程序；Ghidra 与 Git 工具在执行器中运行。

| 文档 | 内容 |
| --- | --- |
| [文档索引](Docs/README.md) | 项目定位、环境和当前状态 |
| [具体实现方案](Docs/具体实现方案.md) | 工程结构、数据与状态、智能体、分析工具、接口、界面和验收依据 |
| [项目方案](Docs/选题一可行性分析与初步方案.md) | 课程需求、项目范围和技术路线 |
| [开发实施计划](Docs/开发实施计划.md) | 实现依赖、执行顺序和完成标准 |
| [测试与验收方案](Docs/测试与验收方案.md) | 历史漏洞测试、修复对照和正式验收 |
| [技术栈对比与建议](Docs/技术栈对比与建议.md) | 技术选择及取舍 |
| [安装与运行](Docs/安装与运行.md) | Windows / macOS / Linux 环境、启停、检查和打包 |
| [首轮交付记录](Docs/首轮交付记录.md) | 实际能力、验证结果和剩余要求 |
| [正式样本筛选](Docs/正式样本筛选.md) | 六项正式对象的来源与资格证据 |
| [开源参考与依赖](Docs/开源参考与依赖.md) | 参考项目、自研部分及第三方许可证 |
