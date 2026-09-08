# Windows 实机接力

此文件用于在目标 Windows 电脑上新建 Codex 会话。Mac 继续处理通用审计、Linux 容器和界面；Windows 会话负责本机环境与 Windows 专用验证。开始实际操作前由用户确认当前电脑可用。准备文件本身不代表 Windows 实机验收通过。

## 接上当前源码

源码仓库为 `https://github.com/moonlit111/aegis-audit`。提交推送完成后，可克隆仓库并检出 Mac 会话给出的提交号；已有克隆先保留本机改动，再同步对应版本。也可以使用 `python3 scripts/prepare_windows.py` 生成的源码 ZIP，解压到较短的路径，例如 `D:\AegisAudit`，在包含 README.md 的项目根目录新开 Codex 会话。

快照含当前源码、锁文件、协议生成物、开发夹具及文档。`SOURCE-MANIFEST.json` 记录版本、Git HEAD、是否含未提交改动及每个文件的 SHA-256；ZIP 旁有整包校验值。项目本地数据、模型凭据、工具缓存及构建产物不进入交接包。若清单中的 `git_dirty` 为 true，其 Git HEAD 只是基准提交，必须使用 ZIP 中的源码才能还原该快照。

ZIP 方式先用 PowerShell 的 `Get-FileHash -Algorithm SHA256 <源码包路径>` 与旁边的 `.sha256` 核对，再在解压后的项目根目录运行 `py -3 scripts/prepare_windows.py --verify`。逐文件校验只需要 Python 3.9+，无需 Git、Rust、Node 或现有 Mac 工具目录；安装或修改源码之前执行。通过 Git 获取的源码没有 `SOURCE-MANIFEST.json`，直接核对 `git rev-parse HEAD`。

可把下面这段作为新会话的任务：

> 阅读 README.md、Docs/审计与动态验证交付记录.md、Docs/安装与运行.md 和 Docs/Windows接力任务.md。确认源码对应 Mac 会话交付的提交或快照，先检查 Windows 环境并保存报告，再完成 Windows 原生构建、工程测试及受支持 PE 的 Ghidra 结构分析。与 Mac 会话协调修改范围，重点处理 Windows 适配代码和 Windows 证据，不把已知缺口标为通过。新增变更和日志需保留，说明实际运行的平台、命令、结果及仍缺少的环境。正式历史漏洞程序的动态测试使用可回滚的 Windows 隔离环境。当前 Linux Docker 运行器不能当成原生 PE 执行器。

## 执行顺序

1. 在 PowerShell 运行 `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_preflight.ps1`。脚本只检查环境并生成 `.data/windows/preflight-*.json`，不会安装软件或启用系统功能。非管理员检查不到的可选功能会如实标记未知。
2. 根据实际报告核对 Windows 版本、虚拟化、磁盘空间、MSVC/Windows SDK、Rust、Python、Node、Java、Docker/WSL。使用 `py -3 scripts/bootstrap.py` 按安装文档准备工具；先完成不依赖重启的步骤。
3. 运行 `py -3 scripts/manage.py build`、`py -3 scripts/manage.py check`、`py -3 scripts/manage.py doctor`。保留 Windows Job Object 的超时、取消及子进程回收测试记录。
4. 启动服务，执行 `py -3 tests/smoke.py --binary --git`。PE32、PE64 的导入、Ghidra 分析、地址及报告必须来自 Windows 实机运行；Mac 或 GitHub runner 的旧记录不能替代本机结果。
5. 若 Docker Linux 容器可用，构建 `py -3 scripts/manage.py runtime` 并运行 `py -3 scripts/check_runtime.py`。它检验 Linux 组件、ELF 和模糊测试，单独记录结果。
6. 准备可回滚 Windows 隔离执行环境，再实现、测试原生 PE 动态执行。先使用来源可复现的正常/缺陷/修复夹具检查任务、超时、取消、日志和回收，再推进正式闭源样本。

## 回传材料

回传环境报告、执行命令及退出结果、测试摘要、必要的脱敏日志和源码差异。标清哪些变更基于交接快照，避免用旧 main 覆盖 Mac 的新代码。原始目标及模型凭据保持在相应本机的数据目录；正式样本按来源、版本、保护特征和真实验证证据逐项核对。

Mac 当前状态以《审计与动态验证交付记录》为准。R14 的六个正式样本、Windows PE 动态验证、自动保护处理和完整课程交付仍需后续落实。
