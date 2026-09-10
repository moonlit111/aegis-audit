# 参考项目补充调研

更新：2026-09-10。来源为公开网络检索（GitHub / arXiv / 安全媒体），**未逐一克隆验证版本、许可与最新状态**；正式引用前须按各仓库 LICENSE 与固定 commit 复核。目的：为 R03 / R05 / R07 / R09 / R13 找可比参考。

> 说明：本文件补充现有 [开源参考与依赖](../../Docs/开源参考与依赖.md) 第 3 节，不替换其中已固定的版本信息。攻击性/双用途项目仅作架构研究，只能对**有权测试**的目标使用。

## 1. 同类 LLM 代码审计 / 漏洞挖掘系统（对标 R13、R04–R06、R08）

| 项目 | 定位 | 与本项目的关系 |
| --- | --- | --- |
| DeepAudit（lintsinghua/DeepAudit，AGPL-3.0） | 多智能体 Orchestrator / Recon / Analysis / Verification + Docker 沙箱 PoC 验证 + RAG(CWE/CVE) | 已用于 R13。**它有"沙箱 PoC 验证"环节，是 R09 最接近的对照** |
| IRIS（iris-sast/iris，ICLR'25） | 神经符号：LLM 生成 CodeQL source/sink 规格 + LLM 过滤误报路径；CWE-Bench-Java 含 120 个真实 Java 漏洞 | R05/R06/R08 方法论参考：LLM 与静态分析互补，CodeQL 27 → IRIS+GPT-4 55 |
| RepoAudit（ICML'25） | Autonomous LLM agent 仓库级审计：tree-sitter 找 source/sink + LLM 抽数据流事实 + 约束矛盾检测 | R04/R05：仓库级数据流推理路径 |
| Vul-RAG | 知识级 RAG 增强 LLM 漏洞检测（arXiv 2025-06） | R06：知识库增强、降低误报 |
| shashvik/LLM_Agentic_security_ADK | Google ADK 实现单/多智能体 SAST，本地 Ollama，Sequential/Parallel agents | R01/R06 轻量参考 |
| lodetomasi/zero-day-llm-ensemble（MIT） | 多智能体 LLM 集成 + Thompson Sampling 做零日检测 | R01 集成/投票策略参考 |

## 2. 自主渗透与自动利用智能体（对标 R09、R01）

| 项目 | 要点 |
| --- | --- |
| PentAGI | 多智能体：orchestrator 规划攻击链，researcher / developer / executor 子智能体；20+ 工具（Nmap / Metasploit / SQLmap）；Docker 隔离；PostgreSQL+pgvector 长期记忆 + Neo4j 知识图谱；三层记忆 |
| VulnBot | 多智能体协作的自动化渗透框架（arXiv 2025） |
| xOffense | 微调 Qwen3-32B + 多智能体，子任务完成率 79.17%，优于通用大模型 |
| HPTSA | 层级智能体团队，零日利用效率比单体 agent 高 4.3× |
| D-CIPHER | 多智能体 + 规划器，比单体多解 65% 的 MITRE ATT&CK 技术 |
| Cybermes 2.0 | 开源红队 agent，Go 原生，50+ 安全技能；**核心是"零误报关卡"——发现写入报告前必须有确定性证据 + 可独立复现的 PoC**；产出 MD/JSON/HTML/PDF 四种交付物 |
| HexStrike-AI | 150+ 安全工具 + 12 智能体，用 MCP 把工具包成可调用函数，支持 JIT exploit 生成。⚠️ 已被真实攻击者滥用（Storm-1575 用于打 Citrix NetScaler CVE-2025-7775）——**只作架构研究，严禁用于未授权目标** |
| 其他 | Strix、CAI、Zen-AI-Pentest、HackSynth、AutoPentest、Aracne、Incalmo、Cochise、PentestGPT |

## 3. LLM 逆向 / 反编译 / 解混淆（对标 R03、R08）

| 项目 | 要点 |
| --- | --- |
| auto-re-agent（Dryxio/auto-re-agent） | Ghidra + LLM 从二进制重构 C/C++ 函数；**独立 reverser/checker 双模型 + 候选构建/测试门 + 结构验证 + parity 分级（GREEN/YELLOW/RED）** |
| DecompAI（louisgthier/decompai） | LangGraph + Gradio；工具 objdump / gdb / Ghidra / Kali；Docker 沙箱 runner |
| mjurzak/llm-reverse-engineering | radare2 + LLM，Streamlit，含重编译与比对指标 |
| LLM4Decompile | 首个开源反编译大模型（基于 **DeepSeek-Coder 微调**）；Decompile-Eval；与 S1 候选直接相关 |
| Reversecore_MCP | MCP server 编排 Ghidra / Radare2 / YARA，含 ESIL 模拟执行（不真跑） |
| AnalystAIPack（Apache-2.0） | 118 个恶意分析/逆向 skill，SKILL.md 格式，映射 MITRE ATT&CK/D3FEND/CAR；脚本只读静态、**不执行样本**；含脱壳/去混淆 skill |
| reverse-skill | 面向 coding agent 的逆向"路由式"技能包，含自演进知识库 |
| LLM CFF 去混淆实践 | 用 DeepSeek v4 / Gemini 3.1 / Claude 4.5 对反编译伪代码做控制流平坦化还原（OLLVM 案例） |

## 4. 模糊测试（对标 R07）

| 项目 | 要点 |
| --- | --- |
| Jackalope（googleprojectzero，Apache-2.0） | 覆盖引导、可定制、分布式的 Windows/macOS 黑盒 fuzzer；默认 TinyInst 插桩；需自写 custom mutator / sample delivery |
| WinAFL + TinyInst | `afl-fuzz -y` 用 TinyInst 收集 basic-block/edge 覆盖；需 `-instrument_module / -target_module / -target_method / -nargs / -persist -loop` 逐目标适配 |
| ChatAFL | LLM 引导协议 fuzzing（NDSS'24） |
| Locus | Agentic predicate synthesis 做定向 fuzzing |
| TitanFuzz / FuzzGPT | LLM 对深度学习库做 fuzzing |

## 5. 评测基准与论文索引（对标 R13/R14）

- 基准：CVE-Bench、AutoPenBench、CyberGym、Sec-bench、CWE-Bench-Java（IRIS）、BigVul、SecCodePLT
- 索引：`varun369/Awesome-Agentic-Security`、`ucsb-mlsec/Awesome-Agentic-AI`（security.md）、`kagnlp/Awesome-Agentic-Security`

## 6. 映射建议（按本项目缺口）

| 缺口 | 优先参考 | 可借鉴的点 |
| --- | --- | --- |
| R07 动态模糊测试 | Jackalope、WinAFL+TinyInst | 目标适配参数与覆盖收集；ChatAFL 提供 LLM 变异思路 |
| R09 自动利用 | PentAGI、Cybermes、DeepAudit | 沙箱执行 + orchestrator/executor 分工；Cybermes 的"零误报关卡" |
| R03 去壳/解混淆 | auto-re-agent、AnalystAIPack | 双模型复核 + 构建/测试门；脱壳与去混淆 skill 化 |
| R05/R06/R08 | IRIS、RepoAudit、Vul-RAG | "LLM 推断规格 → 静态分析 → 误报过滤"三段式 |
| R13 开源对比 | DeepAudit（已引用） | 明确功能边界不对等：DeepAudit 无二进制/动态能力 |

## 7. 使用边界提醒

1. 上述多为攻击性/双用途工具，**只能对有权测试的目标使用**，与项目"不实现完整攻击链渗透"的定位保持一致。
2. 网络检索结果可能滞后或含二手转述；引用前以各仓库 **LICENSE + 固定 commit** 为准。
3. **不要把"框架存在"当作"本项目已具备该能力"**——参考项目只提供机制与思路，不替代本项目的实现与实测。
