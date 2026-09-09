**AegisAudit** 是基于大模型多智能体的软件漏洞挖掘与验证项目，面向源码和二进制开展程序理解、安全审计、独立复核及利用验证，使用历史漏洞检验通用分析能力。

已确定技术栈：Rust + Axum/Tokio、Svelte + TypeScript、Connect RPC、SQLite；Python/Java 用于必要的工具适配。

**当前唯一支持的构建、开发与部署平台为 Windows 11 x64。** 不再提供 macOS / Linux 宿主平台支持。Windows 原生动态隔离仍在迁移中，旧 Linux 容器实现及历史测试记录不等于 Windows-only 目标已经完成。完整迁移范围和验收门槛见[Windows 专用实施方案](Docs/Windows专用实施方案.md)。

当前版本为 **0.2.0：程序结构分析、多智能体审计与动态验证工作台**。Windows 主程序、导入、结构分析、模型审计和原生 Semgrep 规则扫描不要求 WSL、Docker 或另一台计算机。任务、事件和证据持久化，支持 JSON / HTML / Markdown 报告导出。执行不可信目标所需的 Windows 隔离环境另行验收。

支持 Python、Go、C、C++ 源码，以及 PE x86/x64、ELF x86_64。源码使用 Tree-sitter；二进制使用 Ghidra Headless。源码调用边标记为推断或未解析，伪代码只做函数级地址映射。解析失败、覆盖缺口和未执行的检查均保留在界面与报告中。

基线版本已有 DeepSeek 四类缺陷开发回归和 Linux 容器动态回归；这些历史记录不计为 Windows 通过。本机已完成 Windows 源码/PE32/PE64/ELF 静态解析、报告和浏览器回归，并将 Semgrep 1.176.1 Windows beta 接入真实任务准备及证据上传。规则命中仍只是审计线索，不等于漏洞成立或利用成功。

**正式课程验收仍为 0/6。** 独立运行包的完整验收、原生 PE 动态执行、自动去壳/解混淆、完整目标利用、开源系统对照和正式样本仍需完成。历史能力与实测边界见[审计与动态验证交付记录](Docs/审计与动态验证交付记录.md)，Windows 当前状态见[Windows 专用实施方案](Docs/Windows专用实施方案.md)，正式对象见[正式样本筛选](Docs/正式样本筛选.md)。

在 Windows x64 的 Developer PowerShell 中，具备 Python 3.9+、Git 和 MSVC/Windows SDK 后运行：

```powershell
py -3 scripts/bootstrap.py
py -3 scripts/manage.py build
py -3 scripts/manage.py doctor
py -3 scripts/manage.py start --open
```

Windows 原生构建需 Visual Studio Build Tools 的“使用 C++ 的桌面开发”和 Windows SDK。工具安装在项目 `.tools/` 及独立 Ghidra 缓存中，不修改全局 shell 配置。无需开发工具的便携版入口为 `AegisAudit.exe`，见[Windows 独立运行](Docs/Windows独立运行.md)。具体前提、版本和排错见[安装与运行](Docs/安装与运行.md)。

打开 **http://127.0.0.1:7331**，新建项目，导入 ZIP / 本地文件夹 / HTTPS Git 指定版本 / PE 或 ELF，等待快照就绪后开始结构分析或安全审计。结构分析无需模型；安全审计使用本地已配置的 DeepSeek API。不要为使用这些能力安装 WSL 或 Docker。原生 Windows 动态执行仍待完成，旧容器代码只是迁移参考。任务不依赖浏览器保持连接。

```powershell
py -3 scripts/manage.py stop        # 停止进程，保留本地数据
py -3 scripts/manage.py check       # Rust、协议、前端检查
py -3 scripts/aegis.py cargo test --workspace --locked native_ -- --ignored --test-threads=1
py -3 scripts/aegis.py pnpm --dir frontend exec playwright install chromium
py -3 scripts/e2e.py                # 使用真实独立服务和执行器的浏览器测试
py -3 scripts/check_audit.py --live-model  # 真实模型开发回归，需要已配置 API
py -3 tests/smoke.py --binary --git  # 对已启动服务执行真实解析与报告测试
py -3 scripts/package.py --standalone-windows  # 构建含私有运行组件的 Windows 包
py -3 scripts/prepare_windows.py    # 导出含未提交改动的 Windows 源码交接包
```

服务数据库、源文件、日志、凭据在 `.data/`，均不提交到 Git。默认只有本机浏览器能建立操作会话。导入、结构解析和 Semgrep 扫描不启动目标程序；Windows Job Object 负责工具超时、取消及进程树回收，但不是执行漏洞程序的安全沙箱。原生动态执行必须在断网、受资源限制且可回滚的 Windows 隔离环境中验证，不能直接在宿主运行正式漏洞目标。

| 文档 | 内容 |
| --- | --- |
| [文档索引](Docs/README.md) | 项目定位、环境和当前状态 |
| [具体实现方案](Docs/具体实现方案.md) | 工程结构、数据与状态、智能体、分析工具、接口、界面和验收依据 |
| [项目方案](Docs/选题一可行性分析与初步方案.md) | 课程需求、项目范围和技术路线 |
| [开发实施计划](Docs/开发实施计划.md) | 实现依赖、执行顺序和完成标准 |
| [测试与验收方案](Docs/测试与验收方案.md) | 历史漏洞测试、修复对照和正式验收 |
| [技术栈对比与建议](Docs/技术栈对比与建议.md) | 技术选择及取舍 |
| [安装与运行](Docs/安装与运行.md) | Windows x64 环境、启停、检查和打包 |
| [Windows 专用实施方案](Docs/Windows专用实施方案.md) | Windows-only 目标、原生隔离、验证门槛与未完成工作 |
| [Windows 原生工具调研](Docs/Windows原生工具调研.md) | 同类项目架构、原生工具选择和本机 Semgrep 证据 |
| [Windows 实机验证记录](Docs/Windows实机验证记录.md) | 便携包、DPAPI、异常恢复、代理修复和实测边界 |
| [审计与动态验证交付记录](Docs/审计与动态验证交付记录.md) | 0.2.0 实际能力、回归证据和剩余要求 |
| [Windows 接力任务](Docs/Windows接力任务.md) | 源码交接、Windows 环境检查与实机验证顺序 |
| [首轮交付记录](Docs/首轮交付记录.md) | 0.1.0 结构分析阶段的历史记录 |
| [正式样本筛选](Docs/正式样本筛选.md) | 六项正式对象的来源与资格证据 |
| [开源参考与依赖](Docs/开源参考与依赖.md) | 参考项目、自研部分及第三方许可证 |
