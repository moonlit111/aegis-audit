# AegisAudit

基于大模型多智能体的软件漏洞挖掘与验证工作台，对应课程“设计实现类”第 1 题。技术栈为 **Rust + Axum/Tokio、Svelte + TypeScript、Connect RPC、SQLite**；当前支持 Windows 11 x64，Python/Java 用于工具适配。

源码或二进制导入后，系统建立程序索引，进行语义审计、独立复核和验证方案生成，保留工具/模型/运行证据，支持人工修订及 JSON、HTML、Markdown 报告。

**当前是集成中的 0.2.0 原型，不是课程验收完成版。Windows 宿主机 VERIFY 与智能体规划的去壳/解混淆链路已合入 `main`，但 FUZZ、完整自动利用和六项正式软件验收尚未完成。** 准确状态统一维护在[课程要求与进度](Docs/课程要求与进度.md)，不要用旧交付记录推断最新版本已通过。

## 文档

| 文档 | 内容 |
| --- | --- |
| [课程要求与进度](Docs/课程要求与进度.md) | 老师原文、R01-R15 对照、当前阻断、分工与交付清单 |
| [具体实现方案](Docs/具体实现方案.md) | 实际架构、代码入口、智能体、证据与运行契约 |
| [安装与运行](Docs/安装与运行.md) | 源码/便携包、配置、排错、逆向工具与宿主运行边界 |
| [测试与验收方案](Docs/测试与验收方案.md) | 本轮测试、历史证据、六项正式对象与验收方法 |
| [开源参考与依赖](Docs/开源参考与依赖.md) | 技术选择、自研范围、上游引用与许可证 |

## 运行入口

在 Windows x64 的 Developer PowerShell 中，具备 Python 3.9+、Git、MSVC 和 Windows SDK 后，在仓库根目录运行：

```powershell
py -3 scripts/bootstrap.py
py -3 scripts/manage.py build
py -3 scripts/manage.py doctor
py -3 scripts/manage.py start --open
```

默认地址为 http://127.0.0.1:7331，停止命令为 `py -3 scripts/manage.py stop`。上述命令是启动方法，不代表当前导入回归已经修复。便携包入口为 `AegisAudit.exe`，需要完整目录，不能只取一个 EXE。

主服务、源码解析、Ghidra、Semgrep、模型审计、宿主机 VERIFY，以及 UPX / FLOSS / Ghidra / 可选 IDA + D-810 的智能体恢复链路都运行在 Windows 宿主，**不要求 WSL、Docker 或 Sandbox**。`bootstrap.py` 会安装固定版 UPX 与 FLOSS；IDA / Hex-Rays 由使用者本机提供并通过 `scripts/configure_d810.py` 探测。模型审计需配置 DeepSeek，纯结构分析不需要模型 API。

`.data/` 保存本机数据库、产物、日志及凭据，`.tools/` 保存私有工具，均不提交。不要将目标安装脚本或客体运行脚本直接在日常宿主执行；Job Object 负责资源与进程回收，不是安全隔离。
