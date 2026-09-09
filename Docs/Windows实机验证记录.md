# Windows 实机验证记录

更新：2026-09-09。主机为 Windows 11 Pro x64 build 26200。源码位于 `C:\Users\Unite\codespace\aegis-audit`，基线提交为 `fd15f65`，Windows 改动仍在 `windows/relay-20260909` 的未提交工作区。以下是实测记录，不是完整项目已交付的声明。

## 工程检查

- 最新常规检查：36 项 Rust 测试、18 项 Python 测试、协议再生成、Clippy、Svelte/TypeScript、格式及前端构建通过。日志为 `.data/windows/native-proxy-check-verified-20260909.log`。
- 另显式运行 4 项真实 Windows 工具测试：Semgrep 扫描/覆盖/回收、执行器扫描产物回传、目标目录内同名 `git.exe` 不被选为工具、Python DPAPI 写入与 Rust 服务读取互通。日志为 `.data/windows/native-tools-final-20260909.log`。测试使用非服务商凭据，不调用模型 API。
- 48 项协议生成示例被上游标记忽略，不计入测试通过数。Release 原生构建完成，日志 `.data/windows/native-proxy-release-20260909.log`。
- 浏览器已有 4 项通过、1 项旧容器动态用例跳过；不能将跳过项计为 Windows 动态执行通过。

## 便携包

首个包含原生 Semgrep 的候选包通过了 13,969 个文件的完整清单核验，但重定位后能力检测失败。原因是版本探针仍回退调用安装机生成的 `pysemgrep.exe` 脚本，而便携包有意不带这些绝对路径脚本。修复为版本检测与扫描均使用固定版本的原生 CLI 模式，没有恢复对安装机路径的依赖。

后续候选包 `windows-recovery-20260909` 的 SHA-256 为 `016104c12af97e298d5cf2d4fd094879eb309ff4397a356b47daa43184bc0a49`。它通过 13,970 个文件的清单核验，并在含中文和空格的独立目录执行以下实际检查：

| 检查 | 结果与边界 |
| --- | --- |
| 无开发工具 PATH | 只提供 Windows `System32`，并故意设置错误的外部 Python/Java/Ghidra 路径；包内工具仍可启动 |
| 重复启动 | 复用相同服务/执行器 PID，没有另起一套后端 |
| 端口冲突 | 显式占用端口被拒绝，不停止原占用者；默认启动可选择后续空闲端口 |
| 真实静态分析 | 源码 11 个程序单元，PE32/PE64/ELF 各 2 个；JSON/HTML/Markdown 报告保留动态 `NOT_RUN` |
| 正常退出与恢复 | 后端进程退出；重启后项目和旧报告摘要一致 |
| 强制退出 | Ghidra 的 Java 子进程运行时结束启动器；已观察的服务、执行器、批处理、Java 和控制台进程全部退出 |
| 中断恢复 | 查询原命名 Job 已关闭，保存回收证据，把中断任务标为 FAILED；随后新导入和分析可以完成，未重跑或伪造旧任务成功 |
| 独立 Semgrep | 重定位后的私有 Python 实际扫描 4 个开发夹具文件，2 条线索、0 个错误；不执行目标代码 |
| 模型配置窗口 | 实际验证空值拒绝、密码掩码、保存、重新打开和取消；保存的是 DPAPI 密文，Rust 服务可以读取，模型调用数为 0 |

原始记录位于 `.data/verification/winpkg-recovery-20260909/summary.json` 和 `supplement.json`。窗口截图在 `.data/windows/standalone-model-*-20260909.png`。窗口部分为真实原生 UI 操作与截图核验，不冒充无界面自动测试。

上述候选包早于随后完成的代理修复；新的打包结果必须按自己的 SHA-256 和运行记录登记，不能套用旧 ZIP 的整包结论。发布物未签名，`Get-AuthenticodeSignature` 返回 `NotSigned`。

## 安全与恢复

模型配置现在使用 Windows 当前用户 DPAPI 加密，并通过临时文件及原子替换保存。损坏或其他账户无法解密的值会被拒绝，不能被当作明文 API key 发给服务商。旧明文配置仅保持读取兼容；重新保存会转换格式。上述自动化和便携包测试没有使用真实服务商凭据；后续真实连接检测单独记录如下。

启动器用全局命名空间的安装级互斥量和每次启动唯一的 kill-on-close Job Object 管理进程。执行器先向 Windows 核验成员身份和 Job 限制，再把所有权与机器身份写入活动记录。自动恢复只适用于有这种记录的导入/静态分析任务；机器不匹配、Job 仍有进程、旧版无记录以及动态隔离任务都不自动认定已回收。

Job Object 仍不是漏洞执行沙箱。包的退出回收测试不能替代 Windows Sandbox/Hyper-V 的断网、目录权限、回滚及跨任务污染测试。

## 真实模型连接与沙盒准备

2026-09-09 11:51（Asia/Hong_Kong），按用户授权替换本机模型凭据。密钥通过私有标准输入交给现有配置程序，保存为当前用户 DPAPI 密文，未写入源码、明文临时文件或发布包。由正在运行的 Rust 服务实际调用 `https://api.deepseek.com`，`deepseek-v4-flash` 的连接检测结果为 `SUCCEEDED`：服务商返回输入 39、输出 5、合计 44 tokens，耗时 1,034 ms。证据为 `.data/windows/real-model-connection-20260909-115100.json`，不包含密钥。先前凭据的 HTTP 401 记录保留在 `.data/windows/real-model-connection-20260909.json`。连接检测不等于真实漏洞审计回归通过。

用户已明确授权启用 Windows Sandbox，并要求自行手动重启。管理员进程通过 `Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart` 完成启用，功能状态由 Disabled 变为 Enabled，返回重启需求，进程退出码 3010；没有触发重启。证据为 `.data/windows/sandbox-enable-20260909.json`。用户随后已手动重启，不再处于等待首次重启的阶段。

2026-09-09 三人交接整理时只读查询 Win32_OperatingSystem，LastBootUpTime 为 11:55:26.5（Asia/Hong_Kong）；确认 `C:\Windows\System32\WindowsSandbox.exe` 存在，并观察到 aegis-server、aegis-executor 进程。该查询没有启动沙盒、运行漏洞程序或重跑模型测试，不能证明进程业务健康或隔离验收通过。后续按用户最终选择继续使用 Windows Sandbox，仍需真实启动、断网、映射边界、关闭销毁及跨任务污染测试。

同轮确认 `.data/dist/windows-verified-20260909/` 中候选 ZIP 存在，但预期的 `.data/verification/winpkg-final-20260909/summary.json` 不存在。此候选的最终验收仍按待核实处理，不借用旧 recovery 包结论。

## Git 网络

较早的两次 Git 导入因直连 `github.com:443` 超时失败，原日志保留。进一步检查发现本机配置了本地代理，而工具环境白名单没有把代理设置交给 Git。现已增加 Windows 手动代理读取及 Git 专用的代理白名单，同时保持 hooks、全局 Git 配置和凭据助手禁用；不转交带用户名/密码的代理 URL。

修复后在本机真实服务上完成了相同 HTTPS 仓库及固定提交的导入与报告。该仓库没有支持的源码，分析诚实保留 PARTIAL 和 0 个程序单元。证据为 `.data/windows/native-git-proxy-verified-20260909.json`，不是靠跳过网络用例获得通过。

## 未完成项

- Windows Sandbox 功能已启用且用户已重启，仍待验证真实启动、断网、目录边界、清理和跨任务污染。不得自动重启或提前在宿主运行正式漏洞程序。
- 真实 DeepSeek 连接已通过，Windows 上的真实审计与缺陷/修复回归仍待执行。网页目前只有连接检测按钮，模型配置仍在原生托盘窗口；网页可见配置入口尚未实现。
- 原生 PE 动态执行、成熟 Windows 模糊测试引擎、自动保护处理、完整目标利用、开源系统对照和保留集仍未完成。
- 正式课程对象仍为 **0/6**。开发夹具、规则线索、API 连接与便携包测试都不能抵扣正式对象。
- 尚无全新 Windows 虚拟机中的部署结果；清除开发工具 PATH 是有价值的本机测试，但不等于干净操作系统验收。
- 本轮 Windows 代码与新 CI 配置尚未提交/推送，不能宣称远端 CI 已验证这些改动。
