# Windows 原生工具与同类项目调研

核查日期：2026-09-09。结论是 **不把 WSL 作为 AegisAudit 的安装或运行前提**。工具的 Windows 可用性与执行漏洞程序所需的安全隔离是两个不同问题；前者优先采用原生 Windows 工具，后者使用独立的 Windows 隔离执行环境。

以下来源来自上游文档、源码及发行文件，不把项目 README 的效果宣传当成已复现的对比成绩。Semgrep 能力检查和后续原生适配/任务证据回传是在本机真实运行的测试；其余条目是架构与工具调研，没有声称跑过这些项目的效果对比。

## 同类实现

| 项目 | 核查到的实际做法 | 对本项目的判断 |
| --- | --- | --- |
| [DeepAudit](https://github.com/lintsinghua/DeepAudit/tree/324133fe60b540327d182fbb8c800aa65a613349) | 多智能体源码审计，验证角色使用 Docker 沙箱；[沙箱 Dockerfile](https://github.com/lintsinghua/DeepAudit/blob/324133fe60b540327d182fbb8c800aa65a613349/docker/sandbox/Dockerfile) 基于 Python Debian Bullseye，配置非 root 用户和独立工作目录 | 借鉴任务编排、工具接口和证据回传，不照搬其 Linux 沙箱依赖。开源实现为 AGPL-3.0；其 README 部分 CVE 成绩注明来自闭源版本，不能当作开源版本对照结果 |
| [Strix](https://github.com/usestrix/strix/tree/52b19233477a783004467c1522651eec96015e73) | 开源本地模式要求 Docker；[工具容器](https://github.com/usestrix/strix/blob/52b19233477a783004467c1522651eec96015e73/containers/Dockerfile) 基于 Kali Linux，聚合命令行、浏览器和验证工具 | Docker 在这里承担工具环境统一与执行隔离，不说明智能体算法必须运行于 Linux。不能把这一容器直接当作原生 PE 执行环境 |
| [WinAFL](https://github.com/googleprojectzero/winafl/blob/fd85f38548b14352f4b70ad414f364ea6dc1a769/README.md) | 明确针对 Windows 黑盒二进制；支持 DynamoRIO、TinyInst 等插桩方式，有 Visual Studio/CMake 的 32/64 位构建方法 | 是原生 PE 覆盖引导模糊测试的候选，不需要 WSL。目标函数、调用约定、输入传递和状态重置仍要适配；不是把 AFL++ 的命令名换成 EXE 就能等价迁移 |
| [Jackalope](https://github.com/googleprojectzero/Jackalope/blob/8fb27c9039c10a53639455d22ac4b2158d2256e3/README.md) | 支持 Windows 黑盒目标，默认使用 TinyInst；将输入变异、插桩、文件/共享内存输入投递拆成独立组件；提供 Windows 示例 | 其组件划分适合设计运行器接口。与 WinAFL 的取舍要基于本机 harness 稳定性、异常/取消处理和覆盖反馈实测，不按宣传或星数选择 |
| [Microsoft OneFuzz](https://github.com/microsoft/onefuzz) | 历史方案支持 Windows 执行节点、自定义 OS 镜像、崩溃回传和编排；GitHub 仓库已归档 | 可参考执行节点和证据流水线，不作为当前维护中的产品依赖，也不为本项目引入 Azure 前置条件 |

上述两类项目侧重点不同：DeepAudit/Strix 更接近多智能体源码/Web 审计；WinAFL/Jackalope 更接近 Windows 原生二进制执行。AegisAudit 应组合前者的编排思想与后者的原生工具能力，而不是整体移植某一个 Linux 项目。

## Windows 工具事实

- **Semgrep**：[官方快速开始](https://docs.semgrep.dev/getting-started/quickstart) 明确列出 `Windows (beta)`；[PyPI 1.176.1](https://pypi.org/project/semgrep/1.176.1/#files) 提供 `win_amd64.whl`。本机已经完成该版本的真实扫描，因此当前把 Semgrep 强行绑定到 Linux 容器并非必要。Beta 状态仍要求路径、忽略规则、语言覆盖、大项目、超时及子进程回收回归。
- **Ghidra / JDK**：当前固定的 Ghidra 12.1.3 有 Windows 原生反编译器；本机已完成 PE32/PE64/ELF 静态分析。不需要 WSL。SDK、JDK 与地址映射证据应继续固定和核验。
- **MSVC AddressSanitizer**：[微软文档](https://learn.microsoft.com/en-us/cpp/sanitizers/asan)说明 `/fsanitize=address` 支持 Windows 10 及以上的 x86/x64、EXE/DLL，有转储与调用栈支持；同时列出与 `/RTC`、增量链接等的兼容性限制。不能将 Linux 上所有 Sanitizer 的支持范围直接照搬。
- **Git、Python、LLVM 和调试工具**：采用 Windows 原生发行物，依实际适配器需求选择并锁定版本。不能仅因存在 Windows 下载就宣布完整组合已经通过，需要验证 DLL、启动参数、输出编码、路径、许可证和取消语义。
- **Windows Sandbox**：[微软文档](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)说明它是基于虚拟化、使用独立内核的可销毁 Windows 环境，关闭后丢弃状态；它不是 WSL。默认启用网络，因此执行不可信目标前必须显式关闭网络、限制映射目录。文档也说明当前不支持并发多个 Sandbox 实例；并行、固定检查点和复杂长期安装更适合进一步评估 Hyper-V Windows VM。

## 本机新增证据

证据摘要：[windows-native-tools-research.json](../tests/evidence/windows-native-tools-research.json)。原始日志与 JSON 在 `.data/windows/native-semgrep-*`。

| 项目 | 实际结果 |
| --- | --- |
| 安装范围 | 项目私有 `.tools/windows-semgrep/`，Python 3.13.13；没有安装或启动 WSL/Docker |
| 工具版本 | Semgrep 1.176.1；`semgrep-core.exe` 文件头核对为 PE AMD64 (`0x8664`) |
| 输入 | 已知开发夹具的 3 个 Python 文件和 1 个 C 文件，记录逐文件 SHA-256；不执行目标代码 |
| 规则 | 当前项目的本地 `tools/runtime/rules.yml`；关闭 metrics 和版本检查，没有请求模型 API |
| 扫描 | 实际扫描 4 个文件，2 条规则命中，0 个扫描错误，退出码 0 |
| 首次尝试 | 原 tests 目录被 Semgrep 默认忽略规则跳过，实际扫描数为 0；该结果没有计为成功。随后在独立输入目录复验，保留两次记录 |
| 首次结论边界 | 该次能力检查只证明工具可用，当时尚未接入服务；后续适配结果见下节。规则命中不等于漏洞成立，更不等于动态利用，也不是正式样本成绩 |

### 原生适配回归

后续已将 Semgrep 接入 `crates/application/src/sast.rs` 与执行器的安全审计准备阶段，能力检测不再依赖 Docker 镜像。`bootstrap.py` 将固定依赖安装到项目私有 `.tools/windows-python/`；打包配置同步包含该运行时。服务端保留工具命令、版本、核心/规则摘要、stdout/stderr 产物与逐文件覆盖。完整独立包仍须重新构建和单独验收。

两项显式启用的真实工具集成测试均通过，原始证据在 `.data/windows/native-sast-standalone-path-20260909/`：

- 原生适配器实际扫描 5 个源码文件，产生 2 条规则线索、0 个错误；测试包含中文/空格工作路径、`tests` 目录、目标内的忽略文件和同名 `semgrep.py`。扫描器 PATH 只保留 Windows `System32`，没有借用开发工具 PATH，也没有导入/执行目标 Python 模块。
- 无源码目录保留 `NO_TARGETS`，不算“完整扫描成功”；未扫描的源码文件、解析错误或跳过规则会保留不完整状态。超时/取消的子进程回收检查通过。
- 真实 HTTP 控制服务、快照导入、工作租约、执行器扫描、产物上传和持久化经过集成回归：4 个开发夹具文件、2 条规则线索，并核验原始 JSON 与工具日志。模型调度器没有运行，模型调用记录为空；测试在静态准备后取消模型工作流，不能声称完成一次真实模型审计。

本机也发现并修复了两个“有 Windows 包仍不能直接照搬命令”的问题：顶层 `python -m semgrep` 已被上游废弃，会直接退出；现改用固定发行包的控制台模块入口。深层临时目录还触发原生核心的 `socketpair` 错误，改用独立的短临时目录后原样复验通过，没有降低错误判定来伪装成功。失败日志也保留在 `.data/windows/native-sast-adapter-*`。

扫描适配固定使用该版本的原生 CLI 模式及忽略文件控制参数，包含上游标记为实验性的选项。它们不被当成永久稳定 API；升级版本时必须重新跑真实扫描、零目标、路径、取消及任务回传测试，而不能只更新版本号。当前本地规则主要覆盖 Python / C / Go 的少量边界线索，不代表 Semgrep 全规则库或全部语言的检测能力。

```powershell
$env:AEGIS_NATIVE_SAST_EVIDENCE = Join-Path $PWD '.data/verification/native-sast'
py -3 scripts/aegis.py cargo test --workspace --locked native_ -- --ignored --test-threads=1
```

## 调整后的路径

1. 主程序、导入、结构分析、模型审计与静态规则扫描直接使用 Windows 原生组件，不依赖 WSL、Docker 或虚拟化就能启动。
2. Semgrep 已从容器适配中拆出并完成首轮本机回归；继续做大项目、规则覆盖及最新独立包的重定位验证。固定版本与真实回归仍是升级门槛。
3. 源码动态适配使用 Windows Python 与 Windows C/C++ 工具链；闭源 PE 模糊测试评估 WinAFL/Jackalope 等成熟引擎，不自造覆盖引导引擎。
4. 只在需要执行不可信目标/漏洞验证时进入隔离的 Windows 环境。Job Object 负责进程资源与回收，但不能替代虚拟机的安全边界。隔离能力未就绪时仍可独立推进主程序、静态审计和工具适配。
5. 按同一目标哈希、输入、环境、正反对照和原始日志判定真实结果。移除 WSL 依赖不会降低原生 PE、保护处理、六项正式对象与最终交付的要求。
