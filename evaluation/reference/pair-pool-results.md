# 对照池评测结果（9 对已核实对照，2026-09-11）

> 判据、批次证据、逐对结论与系统性发现。证据在 `.data/verification/pair-pool/`（不入库）。
> **口径提醒**：本轮检验的是**语义审计通道**（AUDITOR/REVIEWER），不是规则引擎——Semgrep 规则对 9 个目标基本不命中（见[对照池评测方案](../../Docs/对照池评测方案.md) §1）。结论不能写成"整条工具链的检出率"。
> 在线判定与离线复判共用同一 `classify` 实现（`scripts/check_pair_pool.py --rejudge`），复判记录：`.data/verification/pair-pool/rejudge-20260911.txt`。

**一句话结论**：7 对可判定中 **2 对 PASS**（p01 踩中公开 CVE-2024-34359 的修复点；p06 机理完全正确）；5 对非 PASS 各有明确原因（上游修复不完整 ×2、权限类被复核规则压制 ×1、命中的是同文件其它真实 bug ×2）；p05/p02 因实例整体关停被截断、不可判。**修复包"零命中"受覆盖率限制，不等于"修复版安全"。**

---

## 1. 判定口径

- **输入构造**：`git show <rev>:<file>` 打成单文件 ZIP（保留原相对路径）钉死范围；两包同路径、同配置；只有源码本身进入模型（**盲测**：不喂 CVE 编号 / 公告 / 修复提交信息）。
- **四分列**（不合并）：命中（类别匹配 + `VALIDATED` + 引文覆盖目标文件） / 有候选未成立（有 finding 但非 VALIDATED，如 INCONCLUSIVE） / 未检出（已审计但零 finding） / 未覆盖（目标文件下没有任何成功的 AUDITOR 任务——**不算"安全"**）。
- **更严一档"命中改动点"**：VALIDATED 的引文行 ∩ `git diff -U0` 改动行 ≠ ∅。
- **PASS = 漏洞包命中改动点 ≥1 且修复包命中改动点 0**。
- 失败与截断批次原样保留，不因"没检出"加预算重跑。
- 覆盖率 = 成功 AUDITOR 任务数 / 目标文件总单元数（该覆盖率限定了"零命中"的证据强度）。

## 2. 结果总表

| 对 | 目标文件（单元数） | 类别 | 漏洞包 | 修复包 | PASS | 关键事实 |
| --- | --- | --- | --- | --- | --- | --- |
| p01 | `llama_chat_format.py`（91） | INJECTION | **命中改动点** ×2（19/91 覆盖） | 有候选未成立（1/91 覆盖） | ✅ | 未沙箱化的 Jinja2 渲染 `chat_template`（CVE-2024-34359 修复点） |
| p02 | `llama.py`（61） | MEMORY_BOUNDS | 有候选未成立（6/61 覆盖） | 连接失败未跑 | — | **截断不可判**（实例关停） |
| p03 | `gradio_patch.py`（7） | INJECTION | **命中改动点** ×1（7/7 覆盖） | **命中改动点** ×2 | ✗ | 上游修复不完整 + 修复引入新缺陷（见 §3） |
| p04 | `readline/history.go`（10） | AUTHORIZATION | 有候选未成立（8/10 覆盖） | 有候选未成立（10/10 覆盖） | ✗ | 权限/umask 类被复核规则压成 INCONCLUSIVE（**规则问题**） |
| p05 | `llm/server.go`（17） | MEMORY_BOUNDS | 有候选未成立（14/17 覆盖） | 连接失败未跑 | — | **截断不可判**（实例关停） |
| p06 | `server/download.go`（19） | MEMORY_BOUNDS | **命中改动点** ×1（5/19 覆盖） | 有候选未成立（2/19 覆盖） | ✅* | HEAD `Content-Length` 未校验 → Parts 空 → 越界 panic；*修复包覆盖缺口显式备注 |
| p07 | `server/images.go`（30） | PATH_TRAVERSAL | **命中改动点** ×1（4/30 覆盖） | **命中改动点** ×2（5/30 覆盖） | ✗ | **发现上游修复不彻底**（`realpath(mfDir, from)` 仍无目录边界约束） |
| p08 | `auth/auth.go`（5） | AUTHORIZATION | 有候选未成立（5/5 覆盖） | 有候选未成立（5/5 覆盖） | ✗ | ground truth 主张被 REJECTED；同文件 `NewNonce` DoS 反被 VALIDATED（类别不符） |
| p09 | `llama/runner/image.go`（10） | MEMORY_BOUNDS | 命中类别但不在改动点（5/10 覆盖） | 命中类别但不在改动点（10/10 覆盖） | ✗ | 两侧各 2 条 VALIDATED 均为 `hashImage` 数据竞争（真实 bug，非目标零长度校验） |

合计：**PASS 2 / 非 PASS 5 / 截断 2**。

## 3. 逐对详述

### p01 · llama-cpp-python Jinja 沙箱（INJECTION，CVE-2024-34359）✅ PASS
- 批次 `stage3-p01`，漏洞包 run `CANCELLED`（207 次调用 / 1,172,508 token，含 1 次用量未知），审 19/91 单元，13 条候选，**2 条 VALIDATED 落在改动点**：
  - 「未沙箱化的 Jinja2 渲染远程 `chat_template` 自带模板（SSTI 风险）」
  - 「未沙箱化的 Jinja2 渲染 `tokenizer_config` `chat_template` 自带模板」
- 修复包 run `PARTIAL`（25 次调用 / 143,236 token），仅审 1/91 单元，0 条 VALIDATED。
- **PASS，但修复包覆盖 1/91——"修复版零命中"证据弱，仅能说"未发现"**。

### p02 · llama-cpp-python `detokenize` 缓冲区（MEMORY_BOUNDS）⛔ 截断
- 批次 `stage3-p02`，漏洞包 `CANCELLED`（111 次调用 / 848,004 token，含 1 次用量未知），审 6/61 单元，7 条候选、0 条 VALIDATED。
- 修复包在实例关停后未能启动（连接失败）。**如实记录为截断，不重跑**。

### p03 · FastChat XSS（INJECTION）✗（修复不干净，含金量高）
- 首轮 `stage1-p03`：漏洞包协议失败（1 个 AUDITOR 任务报「证据的行范围或引用文本无效」，整轮中止，0/7 单元、0 条结果）；修复包正常。
- 重跑 `stage1-p03-rerun1`（有效批次）：漏洞包 7/7 覆盖，**命中改动点**——
  「`postprocess` 把消息以第一人称原文拼进 `<pre>` HTML，未转义」（另有 1 条 `markdown2` safe_mode 相关 VALIDATED，类别命中但不在改动点）。
- 修复包 7/7 覆盖，**2 条 VALIDATED 落在改动点**：
  - 「助手/模型消息经 `markdown2` 渲染前未净化，注入原始 HTML → XSS」——**上游修复不完整**；
  - 「用户消息直接传入 `nh3.clean`，非字符串（tuple/list/dict）会抛未捕获异常」——**修复引入新缺陷**。
- 严格判据不算 PASS；这两条正是"修复不干净"的高价值证据。
- **后续利用验证（2026-09-11，`对照池评测材料-20260911/04-利用验证`）复核**：用户侧 XSS（漏洞版浏览器内执行、修复版被 `nh3.clean` 拦截）与助手侧"修复不完整"（修复版浏览器内仍执行）均**实测成立**；但"非字符串崩溃为修复引入"**不成立**——漏洞版同样抛 `TypeError`，属既有缺陷，归因有误，以利用验证记录为准。

### p04 · ollama 历史文件权限（AUTHORIZATION，CWE-276）✗（规则问题，非能力问题）
- 批次 `c1-p04`。漏洞包 `PARTIAL`（102 次调用 / 470,019 token）审 8/10 单元 10 条候选；修复包 `COMPLETED`（105 次调用 / 544,473 token）审 10/10 单元 9 条候选；两侧 **0 条 VALIDATED**。
- 候选精确指向 `0o666`（L133/L135/L150），三项必要条件 SUPPORTED，但 `EXTRA_PRECONDITION: UNKNOWN`（umask / 多用户前提）→ 全部 INCONCLUSIVE。模型甚至主动给出反证（"umask=0o077 时风险不成立"）后被规则按住。
- **权限 / umask / TOCTOU 类缺陷在"源码快照即全部输入"下天然无法 VALIDATED**：评测口径需给这类单列一档，否则永远计 0。

### p05 · ollama `GPUSizes[i]` 越界（MEMORY_BOUNDS）⛔ 截断
- 批次 `stage2-p05`。漏洞包 `CANCELLED`（217 次调用 / 1,357,645 token，含 1 次用量未知），审 14/17 单元，11 条候选、0 条 VALIDATED（其中 1 个 AUDITOR 任务以「执行器已停止，结果未知」结束——关停痕迹）。
- 修复包在实例关停后未能启动（连接失败）。**截断，不重跑**。

### p06 · ollama 下载 Parts 越界（MEMORY_BOUNDS，CWE-129）✅ PASS（带覆盖缺口备注）
- 批次 `stage2-p06`。漏洞包 `PARTIAL`（148 次调用 / 893,186 token），审 5/19 单元，**命中改动点**——
  「HEAD `Content-Length` 未校验导致 Parts 为空并越界 panic」（机理与 ground truth 完全一致）。
- 修复包：首轮 `stage2-p06` 协议失败（1 任务失败、0/19 单元）；重跑 `stage2-p06-fixed-rerun1`（59 次调用 / 322,951 token）审 2/19 单元、4 条候选、0 条 VALIDATED。
- 按判据 **PASS**；**修复包覆盖 2/19，缺口 17/19 显式记录**——不重跑第三轮。

### p07 · ollama 相对路径解析（PATH_TRAVERSAL，CWE-22）✗（发现修复不彻底）
- 批次 `stage2-p07`。漏洞包 `PARTIAL`（73 次调用 / 441,686 token）审 4/30 单元，**命中改动点**——
  「`CreateModel` 的 model/adapter 路径未约束直接打开本地文件」，与 ground truth 同机理。
- 修复包 `PARTIAL`（100 次调用 / 485,519 token）审 5/30 单元，**2 条 VALIDATED 落在改动点**：
  「`realpath` 不做目录边界约束，绝对路径/符号链接落点仍交给 `os.Open`」。
- 非 PASS，但**发现了上游修复不彻底**：修复后的 `realpath(mfDir, from)` 在改动点仍有被复核成立的遗留问题。

### p08 · ollama 私钥文件类型校验（AUTHORIZATION，CWE-59）✗
- 批次 `stage1-p08`。漏洞包 `COMPLETED`（51 次调用 / 186,626 token）审 5/5 单元，3 条候选：ground truth 主张（私钥文件类型/可读性校验）被 **REJECTED**，其余 2 条 INCONCLUSIVE。
- 修复包 `COMPLETED`（59 次调用 / 244,895 token）审 5/5 单元，5 条候选：**`NewNonce` 未校验 length → 超大值 panic（DoS）被 VALIDATED**，但类别不等，不计命中。
- 结论：同文件找到了**其它真实缺陷**；ground truth 条目的表述（"按文件类型校验"）与模型理解偏离。

### p09 · ollama 零长度图像（MEMORY_BOUNDS，CWE-20）✗（找到别的真 bug）
- 批次 `stage1-p09`。漏洞包 `PARTIAL`（94 次调用 / 468,126 token）审 5/10 单元；修复包 `COMPLETED`（136 次调用 / 584,799 token）审 10/10 单元。
- 两侧各 **2 条 VALIDATED**，均为「`hashImage` 锁外共享 `maphash.Hash` 数据竞争」——真实 bug，但**不是目标（零长度校验）**，也不在改动点上。
- 非 PASS；类别对、位置不对。

## 4. 系统性发现（必须随结果一起记录）

1. **权限 / umask / TOCTOU 类缺陷在"源码快照即全部输入"下无法 VALIDATED。** `ReviewDraft::validate_model` 规定任何必要前提 UNKNOWN 即不得 VALIDATED（p04 全部 INCONCLUSIVE）。评测口径需给这类单列一档（如"前提外置型"），否则这类真实缺陷永远计 0。
2. **服务端健壮性缺陷 ×2（建议报给项目）**：
   - `agents.rs` 中 AUDITOR 的 `context.execute("AUDITOR", ...).await?` 直接上抛：**单个单元的协议校验失败 = 整轮中止**。本轮实测到的三类错误：`missing field audited_unit_ids`（p06 漏洞包）、`证据的行范围或引用文本无效`（p03 首轮漏洞包、p06 修复包首轮）、`invalid type: sequence, expected a str`（p04）。对比 VERIFIER 循环是显式 catch。
   - REVIEWER 把带 UNKNOWN 前提的候选判 VALIDATED 被 `validate_model` 正确拒绝后，同样整轮中止（p06 修复包重跑）。
   - 影响面：p03 首轮漏洞包 1 个任务失败 → 0/7 单元、整轮零产出，被记录为"未覆盖"而非"检不出"。
3. **运行间方差**：同输入两轮结果可不同（p03 修复包首轮 0 条 VALIDATED、重跑 2 条）。**单轮结果不能下死结论**；结果文档与判据都要留两轮口径。
4. **"修复包零命中"的证据强度受覆盖率限制**：p01 修复包 1/91、p06 修复包 2/19、p01 漏洞包 19/91。表里的 PASS 必须以"覆盖缺口备注"形式带上，不能写成"修复版安全"。
5. **本轮截断说明（基建，非能力）**：17:51:05–20 三个在跑的漏洞包 run 被 CancelRun（p05/p01/p02），17:51:30–32 三个驱动各自启动修复包 run，17:53–54 全部实例（5 server + 5 executor）被整体关停，p05/p02 的修复包因此连接失败。批次原样保留，不重跑、不改写。

## 5. 用量（实测可核算）

| 批次 | 对 / 包 | 状态 | 调用 | token | 未知用量 |
| --- | --- | --- | ---: | ---: | ---: |
| c1-p04 | p04 vuln / fixed | PARTIAL / COMPLETED | 102 / 105 | 470,019 / 544,473 | 0 / 0 |
| stage1-p03 | p03 vuln / fixed | PARTIAL（失败） / COMPLETED | 7 / 79 | 30,894 / 318,288 | 0 / 0 |
| stage1-p03-rerun1 | p03 vuln / fixed | COMPLETED / COMPLETED | 74 / 69 | 383,616 / 326,854 | 0 / 0 |
| stage1-p08 | p08 vuln / fixed | COMPLETED / COMPLETED | 51 / 59 | 186,626 / 244,895 | 0 / 0 |
| stage1-p09 | p09 vuln / fixed | PARTIAL / COMPLETED | 94 / 136 | 468,126 / 584,799 | 0 / 0 |
| stage2-p05 | p05 vuln | CANCELLED | 217 | 1,357,645 | 1 |
| stage2-p06 | p06 vuln / fixed | PARTIAL / PARTIAL（失败） | 148 / 8 | 893,186 / 53,289 | 0 / 0 |
| stage2-p06-fixed-rerun1 | p06 fixed | PARTIAL | 59 | 322,951 | 0 |
| stage2-p07 | p07 vuln / fixed | PARTIAL / PARTIAL | 73 / 100 | 441,686 / 485,519 | 0 / 0 |
| stage3-p01 | p01 vuln / fixed | CANCELLED / PARTIAL | 207 / 25 | 1,172,508 / 143,236 | 1 / 0 |
| stage3-p02 | p02 vuln | CANCELLED | 111 | 848,004 | 1 |
| **合计** | | | **1,724** | **9,276,614** | **3** |

不含本轮之外的批次（如 `audit-live-20260910-230138` 夹具批次的 107 次调用 / 321,049 token）。

## 6. 结论与限制

- **能力结论**：在"钉死单文件"的输入构造下，语义审计通道能在真实开源代码上定位并复核成立真实缺陷——9 对里 7 对可判，其中 **4 对直接命中改动点或类别**（p01/p03/p06/p07），**2 对发现上游修复不彻底**（p03/p07），**2 对找到同文件其它真实 bug**（p08/p09），**2 对 PASS**（p01/p06）。
- **口径限制**：只测语义通道；ts/tsx 源码通道不支持 → harness H1–H6 不进本池（H1 漏洞版已单独验证可构建可启动，见 `Docs/安全修复提交扩池调研.md` §6 与 `.data/security-pool/harness-startup-evidence.txt`）。
- **判定限制**：未覆盖 ≠ 安全；`COMPLETED` ≠ 安全；`CANCELLED` 批次按"有候选未成立"记录而非"安全"；单轮结果受运行方差影响。
- 本文件是**对照池评测**结果，不改变"六项正式软件验收 0/6"的结论。

## 7. 复现

```bash
# 离线复判任意批次（读 *-audit.json + git diff 改动行；不连服务、不花钱）
py -3 scripts/check_pair_pool.py --rejudge .data/verification/pair-pool/stage3-p01

# 复判记录（本次全量）
cat .data/verification/pair-pool/rejudge-20260911.txt

# 原始证据
ls .data/verification/pair-pool/{c1-p04,stage1-p03,stage1-p03-rerun1,stage1-p08,stage1-p09,stage2-p06,stage2-p06-fixed-rerun1,stage2-p07,stage2-p05,stage3-p01,stage3-p02}/
```
