# 六项正式软件候选调研

调研日期：2026-09-11，Windows 11 x64。本页由公开信息调研加本机只读筛查得出，**没有下载新样本、没有执行任何目标、没有改变正式通过数（仍为 0/6）**。状态口径与缺口只在[课程要求与进度](../../Docs/课程要求与进度.md)维护，本页只提供候选和验证状态。

## 0. 判定基准

候选是否「省事」，按产品现有的动态执行能力衡量，而不是按软件是否知名：

| 层 | 现有取值 |
| --- | --- |
| 适配器 | `WINDOWS_PYTHON_CALL`、`WINDOWS_NATIVE_SOURCE`、`WINDOWS_ORIGINAL_PE32`、`WINDOWS_ORIGINAL_PE64`、`WINDOWS_LIBFUZZER_PREBUILT` |
| 模式 | `VERIFY`、`FUZZ` |
| 观察器 | `FILE_CREATED`、`SANITIZER`（`RETURN_CANARY` 在 Windows 不支持） |
| 夹具上限 | 最多 16 个测试文件/全局变量，总大小不超过 128 KiB |
| 壳识别 | `protection.rs` 可识别 UPX、ASPack、Themida/WinLicense、VMProtect、MPRESS、PECompact；**只有 UPX 能被自动脱壳** |

因此选型目标是让六项都落在「文件输入 → 进程执行 → 崩溃或标记观察」这一条已有路径上，不新增适配器。

## 1. 本机既有样本池的实测结论（本轮新证据）

对 `.data/formal-samples/` 下全部 189 个 PE 文件用仓库自带 UPX 5.2.1 做只读 `upx -t` 筛查，**仅 3 个确认为 UPX 加壳**：

| 文件 | 性质 | 可用性 |
| --- | --- | --- |
| `packed/iview433_setup.exe` | IrfanView 4.33 **安装器** | 是安装器，不是查看器主体 |
| `packed/Mediajukebox80400.exe` | Media Jukebox 8.0.400 **安装器** | 同上 |
| `packed/winamp-5.12-extracted/Plugins/lame_enc.dll` | Winamp 5.12 分发内的编码器组件 | 是产品分发的真实组件 |

原始结果：`.data/verification/upx-sweep-raw.json`。

**结论：主流闭源免费软件的主体 EXE 极少使用 UPX。**WinRAR 3.60、XnView Classic 2.03、Winamp 5.12、Media Jukebox 8.0.400、AnyDesk 9.0.4、TeamViewer 15.64.7 的主体均未检出 UPX。UPX 实际集中在**安装器、自解压包和个别随附组件**上。这一点直接决定了 P 档的选型难度，见第 3 节。

工具链偏差：`scripts/inspect_candidate_files.ps1` 写死 `#requires -Version 7.0`，**本机只有 Windows PowerShell 5.1，该脚本无法直接运行**。本轮用等价的只读 Python 管线替代（同样只调用 `upx -t` 并前后对比 SHA-256，不执行、不修改目标）。建议后续把该脚本降到 5.1 兼容或改为 Python，否则干净环境验收会再次卡住。

## 2. S1/S2 开源大模型软件

这一档最实，且有几个利用路径明确、Windows 可本地部署的候选。

| 候选 | 许可 | 缺陷 | 修复版本 | Windows 可跑 | 利用难度 |
| --- | --- | --- | --- | --- | --- |
| **Ollama** | MIT | CVE-2024-37032 路径遍历 → 任意文件写/RCE（≤0.1.33）；CVE-2025-63389 接口无鉴权（≤0.12.3） | 0.1.34 / 0.12.4 | 原生安装包 + CLI | 中：需本地伪造 registry（一个极小 HTTP 服务） |
| **Langflow** | MIT | CVE-2025-3248 未认证代码注入 RCE（`POST /api/v1/validate/code` 直接 `exec`） | 1.3.0 | pip，纯 Python | 低：单个 POST 即任意代码执行 |
| **Open WebUI** | 见固定提交许可文件（历史上多次变更） | CVE-2024-6707 上传文件名路径遍历 → 任意文件写/反序列化 RCE | 见对应公告 | pip | 中：一次带 `../` 文件名的上传 |
| **llama-cpp-python** | MIT | CVE-2024-34359 GGUF `chat_template` 无沙箱 Jinja2 → SSTI → RCE（0.2.30–0.2.71） | 0.2.72 | pip，CPU | 低但偏组件级：真实 GGUF 远超 128 KiB 夹具上限，需放进快照或直接调用 `Jinja2ChatFormatter` |

推荐组合：**Ollama + Langflow**（利用路径最确定），或 **Ollama + Open WebUI**（都是本地部署栈的知名品牌，叙事完整）。

另一条更省力的路线值得先评估：**复用已导入的 ChatGLM3 / DeepSeek-Coder**。两者已有真实 DeepSeek 静态审计证据（ChatGLM3 有 2 条静态 VALIDATED），挖掘侧已付费；缺的是正常运行条件和利用验证。如果那 2 条 VALIDATED 能对应到 `openai_api_demo/api_server.py` 的可达入口，S2 的边际成本会低于换新目标。**风险**：官方 demo 服务是 HTTP 入口，仍需驱动脚本；且静态结论不能直接当利用证据。

## 3. P1/P2 加壳闭源软件

口径按「被加壳的闭源软件」。**硬约束是必须真有 UPX 壳**——只有 UPX 能自动脱壳，其他壳（Themida/VMProtect/ASPack/PECompact/MPRESS）只能识别，拿不到派生产物就进不了 Ghidra 和语义审计。

结合第 1 节实测，现实可行的只有三条路径：

**路径 A：把「加壳的安装器/自解压包」本身当作审计对象。** 本机已有两个确认 UPX 的样本。安装器的解包落盘逻辑就是被审计代码，可审计「解包路径遍历、任意路径落盘、临时目录 DLL 劫持」，利用证据用 `FILE_CREATED` 观察器即可闭合，完全复用现有适配器。**风险**：文档已经担心「安装器不等于软件主体」，这条需要先和老师确认，见第 5 节。

**路径 B：定向找 UPX 压缩的闭源工具类软件。** 本机未下载、需要用第 1 节的管线逐个实测。待测方向（命令行可驱动、文件解析、闭源免费）：

| 方向 | 待测对象 | 为什么值得试 |
| --- | --- | --- |
| 图像 | NConvert（XnView 官方 CLI）、FastStone Image Viewer、Honeyview | CLI 可喂文件，解析型内存缺陷多 |
| 媒体 | PotPlayer、KMPlayer、GOM Player、Media Jukebox | 解析型 CVE 密集，命令行参数可驱动 |
| 压缩 | UnRAR.exe / WinRAR 发布包、Bandizip、PowerArchiver、UltraISO | 本身就是「具备加壳功能」的产品，且处理不可信输入 |
| 转换 | 格式工厂等国产闭源工具 | 中文软件使用 UPX 的比例明显更高 |

**路径 C：接受「有 CVE 但壳证据待补」的强候选先做挖掘。** 例如 WinRAR <6.23 的 CVE-2023-38831（修复版 6.23，在野利用）。但必须注意：**该漏洞由用户双击压缩包内的文件触发**，命令行 `WinRAR.exe x` 是否能复现未经验证，不能假定 CLI 可用。

同时要避免一个具体错误：**CVE-2022-30333（UnRAR ≤6.11 路径遍历）只影响 Linux/UNIX 上的 UnRAR，WinRAR 本身不受影响**，它不能作为 Windows 宿主上的验收案例。

## 4. O1/O2 混淆闭源软件

能力边界必须先说清楚：解混淆实际只有 **FLOSS 取字符串 + 内建 XOR/Base64 启发式 + D-810 常量折叠**。

- **可用**：字符串加密、符号剥离、常量混淆、部分控制流平坦化（能恢复可读伪代码 + 关键字符串）。
- **不可用**：VMProtect / Themida 的**代码虚拟化**。目标是虚拟化代码时只能「识别」不能「恢复」，R03/R04 拿不到分。

筛选准则（按此排序，而不是按名气）：

1. 有命令行入口，能用文件参数驱动；
2. 二进制里能看到**字符串级**保护（栈上构造字符串、XOR/Base64 字符串表），FLOSS 能取到部分明文；
3. 有公开的**解析型**缺陷（内存破坏或路径遍历），且有修复版本可比对；
4. 体量不要过大，避免 TeamViewer / Zoom / AnyDesk 这类「体量大 + GUI + 强保护」的组合。

待测名单与 P 档高度重叠（很多老旧闭源免费工具同时是「压缩壳 + 字符串加密」），建议同一次筛查一次取两份结果。**明确不建议**：基于 .NET / Java 的混淆（Ghidra 对字节码恢复有限）、Electron/JS 混淆（工具链完全不覆盖）。

## 5. 必须先确认的两个口径问题

这两个问题直接决定 P/O 两档的工作量，建议今天就问：

1. **「具备加壳功能闭源软件」是「被加壳的软件」还是「本身具有加壳功能的软件」（WinRAR、Bandizip 这类压缩/打包工具）？** 本轮实测证明前一种读法下，UPX 加壳的主体程序很难找；后一种读法下这档几乎不需要脱壳链。同一句里的「具备混淆功能」也同理。
2. **加壳的安装器/自解压包能不能作为该项的审计对象？** 如果能，本机已有的 `iview433_setup.exe`、`Mediajukebox80400.exe` 可以立刻进入流程；如果不能，P 档必须从零找主体程序。

## 6. 下一步最小动作

1. 用第 1 节的只读管线对第 3、4 节的待测名单下载官方发布物并逐个 `upx -t`，产出「UPX_CONFIRMED 短名单」，与第 4 节的字符串保护观察共用一次分析。
2. 对 S 档先验证「复用 ChatGLM3 既有静态发现」是否可行；不可行则按 Ollama + Langflow 推进。
3. 把 `inspect_candidate_files.ps1` 降到 PowerShell 5.1 兼容或改写为 Python，消除干净环境下的工具链缺口。

本页所有候选的 `formal_acceptance` 仍为 `NOT_RUN`；文件名、版本资源、壳线索都不等于正式资格。
