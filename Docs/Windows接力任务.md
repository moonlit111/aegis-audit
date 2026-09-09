# Windows 实机接力

当前接手入口为[后续执行与三人分工](后续执行与三人分工.md)，已列明所有剩余工作、A/B/C 文件所有权、共享接口、依赖、验收与命令。分别将[任务书 A](任务书-A-Windows动态执行.md)、[任务书 B](任务书-B-审计与逆向.md)、[任务书 C](任务书-C-集成验收与交付.md)交给三个负责人。本文件继续保留环境与源码交接方法。

此文件用于在 Windows 电脑上继续项目。自 2026-09-09 起，开发、构建、部署和最终动态运行的目标均为 Windows-only，不再安排 Mac 会话或将 WSL/Linux 容器作为安装前提。当前进度以[Windows 专用实施方案](Windows专用实施方案.md)及[原生工具调研](Windows原生工具调研.md)为准。准备交接文件本身不代表实机验收通过。

## 本机最新状态

2026-09-09 更新（Asia/Hong_Kong）：11:51 的 DeepSeek 真实连接检测已通过，模型为 `deepseek-v4-flash`，服务商返回合计 44 tokens。凭据仅以当前用户 DPAPI 密文保存在本机；不要读取、打印或带入交接包。用户随后已手动重启；本轮只读核验的系统启动时间为 11:55:26，`WindowsSandbox.exe` 已存在，并观察到服务与执行器进程。用户最后确认继续使用 Windows Sandbox，但隔离、断网、目录边界、清理及跨任务污染尚未验收。不要重复启用功能或自动重启。原始证据及剩余边界见[Windows 实机验证记录](Windows实机验证记录.md)；网页可见模型配置、Windows 真实审计回归、原生动态执行和正式 6 项验收仍未完成。

## 接上当前源码

源码仓库为 `https://github.com/moonlit111/aegis-audit`。提交推送完成后，可克隆仓库并检出交付记录给出的提交号；已有克隆先保留本机改动，再同步对应版本。也可以使用 `py -3 scripts/prepare_windows.py` 生成的源码 ZIP，解压到较短的路径，例如 `D:\AegisAudit`，在包含 README.md 的项目根目录新开会话。本机源码位于 `C:\Users\Unite\codespace\aegis-audit`，Windows 改动在 `windows/relay-20260909` 分支，不能用旧 `main` 覆盖尚未提交的改动。

快照含当前源码、锁文件、协议生成物、开发夹具及文档。`SOURCE-MANIFEST.json` 记录版本、Git HEAD、是否含未提交改动及每个文件的 SHA-256；ZIP 旁有整包校验值。项目本地数据、模型凭据、工具缓存及构建产物不进入交接包。若清单中的 `git_dirty` 为 true，其 Git HEAD 只是基准提交，必须使用 ZIP 中的源码才能还原该快照。

ZIP 方式先用 PowerShell 的 `Get-FileHash -Algorithm SHA256 <源码包路径>` 与旁边的 `.sha256` 核对，再在解压后的项目根目录运行 `py -3 scripts/prepare_windows.py --verify`。逐文件校验只需要 Python 3.9+，无需 Git、Rust、Node 或现有 Mac 工具目录；安装或修改源码之前执行。通过 Git 获取的源码没有 `SOURCE-MANIFEST.json`，直接核对 `git rev-parse HEAD`。

可把下面这段作为新会话的任务：

> 阅读 README.md、Docs/Windows专用实施方案.md、Docs/Windows原生工具调研.md、Docs/安装与运行.md 和 Docs/Windows接力任务.md。确认当前分支、已有未提交改动和实际证据，继续 Windows 原生开发与验证，不重复已完成工作，不把历史 Mac/Linux 记录计为 Windows 通过。主程序和静态工具不要求 WSL/Docker；正式历史漏洞程序的动态测试必须使用经过验证、可回滚的 Windows 隔离环境。新增变更和原始日志需保留，说明实际平台、命令、结果与剩余要求；管理员操作或重启前先确认。

## 执行顺序

1. 在 PowerShell 运行 `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_preflight.ps1`。脚本只检查环境并生成 `.data/windows/preflight-*.json`，不会安装软件或启用系统功能。非管理员检查不到的可选功能会如实标记未知。
2. 根据实际报告核对 Windows 版本、磁盘空间、MSVC/Windows SDK、Rust、Python、Node、Java 和原生 Semgrep。使用 `py -3 scripts/bootstrap.py` 按安装文档准备工具；先完成不依赖重启的步骤。虚拟化仅是隔离动态执行的单独检查项，不用 Docker/WSL 的不可用阻断静态工具开发。
3. 运行 `py -3 scripts/manage.py build`、`py -3 scripts/manage.py check`、`py -3 scripts/manage.py doctor`。保留 Windows Job Object 的超时、取消及子进程回收测试记录。
4. 启动服务，执行 `py -3 tests/smoke.py --binary --git`。PE32、PE64 的导入、Ghidra 分析、地址及报告必须来自 Windows 实机运行；Mac 或 GitHub runner 的旧记录不能替代本机结果。
5. 运行 `py -3 scripts/aegis.py cargo test --workspace --locked native_ -- --ignored --test-threads=1`，实际验证原生 Semgrep 的路径、覆盖、取消及任务产物回传。保留 Windows 工具能力检测结果；旧 Linux 容器测试仅是历史/迁移参考，不作为本机必须完成的安装步骤。
6. 准备可回滚 Windows 隔离执行环境，再实现、测试原生 PE 动态执行。先使用来源可复现的正常/缺陷/修复夹具检查任务、超时、取消、日志和回收，再推进正式闭源样本。

## 回传材料

回传环境报告、执行命令及退出结果、测试摘要、必要的脱敏日志和源码差异。标清哪些变更基于交接快照，保留本机已有改动。原始目标及模型凭据保持在相应本机的数据目录；正式样本按来源、版本、保护特征和真实验证证据逐项核对。

《审计与动态验证交付记录》保留原基线的历史事实。R14 的六个正式样本、Windows PE 动态验证、自动保护处理和完整课程交付仍需后续落实，不能因本轮工程或原生扫描测试通过而标为完成。
