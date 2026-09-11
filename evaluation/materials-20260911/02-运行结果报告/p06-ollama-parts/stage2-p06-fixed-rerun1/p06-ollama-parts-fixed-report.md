# AegisAudit 分析报告

项目：对照池评测 20260911-093601

任务：d73387b7-cca6-4c53-a135-ab7717316cf5

状态：Partial

目标 SHA-256：1c49987949af5726ac1ddf397986b4dcee265eaed1db1082e4685377d660c923

结果快照 · 数据截至 2026-09-11T09:40:33.997Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：PARTIAL；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| MarshalJSON | server/download.go | L73–L80 | PARSED |
| Name | server/download.go | L102–L106 | PARSED |
| Prepare | server/download.go | L125–L177 | PARSED |
| Run | server/download.go | L179–L182 | PARSED |
| StartsAt | server/download.go | L108–L110 | PARSED |
| StopsAt | server/download.go | L112–L114 | PARSED |
| UnmarshalJSON | server/download.go | L82–L94 | PARSED |
| Wait | server/download.go | L432–L452 | PARSED |
| Write | server/download.go | L116–L123 | PARSED |
| acquire | server/download.go | L422–L424 | PARSED |
| downloadBlob | server/download.go | L462–L499 | PARSED |
| downloadChunk | server/download.go | L325–L384 | PARSED |
| newBackoff | server/download.go | L184–L208 | PARSED |
| newPart | server/download.go | L386–L394 | PARSED |
| readPart | server/download.go | L396–L410 | PARSED |
| release | server/download.go | L426–L430 | PARSED |
| run | server/download.go | L210–L323 | PARSED |
| server/download.go | server/download.go | L1–L499 | PARSED |
| writePart | server/download.go | L412–L420 | PARSED |

## 审计策略与优先级

基于 catalog 与已读取的 server/download.go 关键区间（Prepare/run 等 125-323 行）做优先级编排：先看外部 HTTP 输入与响应头解析（Content-Length、redirect 目标 URL），再看文件路径拼接、分片偏移/索引运算与切片索引，最后看 JSON 反序列化、并发同步与错误处理。只能定位优先审计单元，不给出漏洞结论；调用图不完整、无构建/运行与 semgrep 结果，动态派发与真实部署行为为未决缺口。

1. u\_02ef1cd5ea9af7b0311a0ea490d01934：疑似下载入口 downloadBlob，接收外部 URL/digest，是外部输入与信任边界起点，需确认请求来源、URL 构造与下游传参。
2. u\_8266a6a9409ffb808b5117bf52f038d9：Prepare 解析 HTTP 响应头 Content-Length（151 行 ParseInt 错误被忽略），并用除法/循环计算分片大小与偏移（153-172 行）；需核对 Total 为 0、负数、超大值及分片数上限导致的整数与循环边界问题。
3. u\_6286155c5e73870ea5713cb8ac2511bf：run 是核心逻辑：214/318 行以 b.Name 拼接文件路径做 OpenFile/Rename，234-248 行自定义重定向策略（同主机才跟随），271-301 行 errgroup 并发与重试；需审计路径可控性、redirect/SSRF 边界与并发写同一文件的竞争。
4. u\_bcf71adf8ca0cc026660a56d1b8beb21：downloadChunk 处理网络返回数据并写入分片，是外部数据进入本地文件的关键点；需检查 Content-Range/长度校验、部分写入、offset 计算与内存/索引操作。
5. u\_442bb29d281cdc42699263cc390b7cb6：readPart 解析已有分片文件（路径来自 filepath.Glob），属于本地持久化数据的信任边界；需检查对文件内字段的校验、错误处理与大小/偏移是否被信任。
6. u\_c3f63c67856f7024f2acb34ee990daf5：writePart 写分片文件，需与 readPart、readPart 的序列化格式及路径命名一致，检查是否可被外部影响造成越界写或覆盖。
7. u\_a5aac29f4a3765501975c4b9439fa2aa：UnmarshalJSON 反序列化外部 JSON，需确认字段是否被用于路径/偏移/大小且缺少校验，属于典型语义信任边界（无词法线索也需审查）。
8. u\_d4beb47bddb0e14e9f0196ba8aa483b9：MarshalJSON 序列化分片状态，需与 UnmarshalJSON 对称，确认是否有字段被隐式信任或泄露敏感信息。
9. u\_263a1ee415c04c2b8493cf6bff1d7721：Wait 含内存/索引操作，管理并发完成状态；需核对 channel/计数同步是否正确，是否存在死锁或提前读已写入数据的竞争。
10. u\_58e0c1b910fbab784a69d2a0bc6f0266：newPart 依据 offset/size 构造分片，需核对参数来源与是否校验非负、上限，避免后续切片/索引运算越界。
11. u\_4bbd1fa3ffbb90796ef3ba07e195bf01：Write 是分片写接口的薄封装，需看是否与 OffsetWriter 组合导致偏移错位或绕过大小校验。
12. u\_a8e7235a0b52161582d7a310e7dc0c29：acquire 类似并发控制（信号量/锁），需核对是否所有路径都正确持有，避免并发写同一分片。
13. u\_ddfcf7c623effd46db9cc89a6d462c89：release 与 acquire 配对使用，需检查异常路径是否释放，防止死锁或并发窗口。
14. u\_a56283c0cb5c3efe8eca2d1bcbd250df：newBackoff 影响重试节奏与截止时间，需确认其与 ctx 超时、重试上限的组合不会被外部触发长时间占用（资源耗尽）。
15. u\_228924630659af4433ebeb46d1148144：Run 是 run 的入口封装，含 defer close\(done\)，需核对错误传播与 done 关闭语义（nil err 判定）。
16. u\_1d25409e64b4705652125da859241229：Name 提供下载目标路径/名称来源，需追溯其取值是否受外部 digest 或用户输入影响，作为路径审计的输入。
17. u\_515ae32a5ca0cbcabda82be8ee7e9ad4：StartsAt 计算分片起始偏移，与 U0006/U0012 联合审计整数与索引边界。
18. u\_2fa9784425aa5120750b2e66ec8992e0：StopsAt 计算分片结束偏移，需与实际写入范围核对，避免超写或切片越界。
19. u\_a912e139b87805c17477f16126e7dbcf：模块级线索为文件与路径边界、内存或索引操作；作为整体审计上下文，用于确认常量（numDownloadParts、min/maxDownloadPartSize、maxRetries）与包导入，并定位未在 catalog 中出现的调用点。

规划限制：工具调用预算已用尽（剩余 0），仅读取了 U0001 的 125-323 行；其余函数体（如 U0012/U0019/U0003 等）未逐行核验，优先级基于 catalog 元数据与局部证据，非结论。

规划限制：analysis\_scope 为 STRUCTURE\_ANALYSIS，call\_graph\_complete=false 且未提供调用图/数据流结果；跨函数传播（如 digest→Name→文件路径）需在审计阶段用 query\_graph/search\_code 补证，动态派发与接口实现仍需人工确认。

规划限制：未识别到构建系统、main 入口与依赖清单，target\_executed=false、verification=NOT\_RUN、vulnerability\_audit=NOT\_RUN，semgrep 状态 UNSUPPORTED，因此没有构建/运行/规则扫描证据，不能断言可利用性。

规划限制：无 recovery 信息，不能主张存在壳/混淆/解密；若后续需要防护评估，应基于实际二进制元数据而非本源码目录。

规划限制：human\_annotations 为空且本身不是证据，本计划未采信任何未验证的注释性断言。

## 发现与复核

静态结论范围：COMPONENT

### 未校验长度的 digest 直接用于切片索引，可触发数组越界 panic

CWE-129 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：downloadOpts.digest（downloadBlob 参数，源自下载任务/注册表元数据）

危险操作：opts.digest\[7:19\] 字符串切片（同一模式在 Prepare 内第 174 行 b.Digest\[7:19\]、第 291/370/443 行重复出现）

防护缺口：缺少 digest 格式与最小长度校验（例如按 &#39;sha256:&#39;+64 位十六进制的正则/长度断言），切片前未做 len\(opts.digest\) &gt;= 19 判断

前提：本地 blob 文件已存在（走 os.Stat 命中分支）且传入 digest 长度小于 19；或任何调用方在 Prepare/Run 路径传入过短 digest

影响：触发越界 panic；若该调用不在 HTTP 中间件的 recover 覆盖范围内（例如独立 goroutine 或后台任务），可导致进程崩溃，造成可用性损失

修复：在 downloadBlob 入口集中校验 digest 格式（长度、字符集、算法前缀），校验失败直接返回错误；切片处先做长度判断，或改用安全的摘要截断辅助函数

- 证据：server/download.go L475–475 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：			Status:    fmt.Sprintf\(&quot;pulling %s&quot;, opts.digest\[7:19\]\),
- 证据：server/download.go L462–466 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：func downloadBlob\(ctx context.Context, opts downloadOpts\) \(cacheHit bool, \_ error\) { 	fp, err := GetBlobsPath\(opts.digest\) 	if err \!= nil { 		return false, err 	}
- 证据：server/download.go L174–174 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：		slog.Info\(fmt.Sprintf\(&quot;downloading %s in %d %s part\(s\)&quot;, b.Digest\[7:19\], len\(b.Parts\), format.HumanBytes\(b.Parts\[0\].Size\)\)\)

复核 v2（MODEL，INCONCLUSIVE）：切片本身确实存在且局部无长度校验：U0019 第475行在 os.Stat 命中分支内直接用 opts.digest\[7:19\]，U0008 第174行在 b.Parts 非空的 else 分支用 b.Digest\[7:19\]；Go 字符串切片下标越界会 panic，语义成立。但到达这两个 sink 都需要同一 digest 派生的本地产物已存在（blob 文件存在才进 default 分支；part 文件存在才进 Prepare 的 else 分支），而正常摘要 sha256:+64位十六进制长度为71，不可能触发；只有被伪造的短摘要且同时在内容寻址目录中已存在对应文件才会触发，这属于 stated component input（函数参数）之外的文件系统状态，快照内无证据。此外切片之前存在一次前置守卫 GetBlobsPath\(opts.digest\) 并检查其返回错误（第463-466行），该函数定义不在本快照中（search\_code 查不到定义），无法判断其是否强制 sha256: 前缀/最小长度，因此该局部缺陷是否真能被短摘要触达仍缺证。

反证：第462-466行在切片前调用 GetBlobsPath\(opts.digest\) 并对 err 提前返回，说明存在一处摘要→路径转换校验点（其体未提供，无法评估强度）；第468-482行的 switch 使第475行只在本地 blob 已存在时执行，第144/173行使第174行只在已加载到 part 文件时执行；常规摘要（sha256:+64 hex，长71）长度远超19，不构成越界条件。

待补信息：1\) GetBlobsPath 的实现及其是否校验摘要前缀/长度/字符集；2\) downloadBlob 的调用方与上游（注册表 manifest、模型名解析）是否已用 digest.Parse 之类校验摘要；3\) Run 内第291/370/443行切片语句所在分支条件（是否有无需本地文件即可在新下载流程中执行的路径）；4\) 短摘要与已存在 blob/partial 文件能否在正常调用契约下同时出现。
静态结论范围：COMPONENT

### digest 未校验即用于本地文件路径与注册表 URL 拼接（路径穿越/SSRF 信任边界）

CWE-22 · UNKNOWN · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：downloadOpts.digest 与 opts.mp（manifest/registry 客户端，BaseURL/GetNamespaceRepository）

危险操作：GetBlobsPath\(opts.digest\) 生成本地文件路径（第 463 行），以及 requestURL.JoinPath\(&quot;v2&quot;, ..., &quot;blobs&quot;, opts.digest\) 构造远端 URL（第 488 行）

防护缺口：本单元未对 digest 做格式/字符白名单校验，也未在拼接后校验结果路径仍位于 blob 存储根目录内（GetBlobsPath 内部实现未知）

前提：上层调用方（HTTP 处理器或后端 API）允许将未充分校验的 digest 传入 downloadBlob；若 digest 可含 &#39;..&#39;、绝对路径前缀或 URL 特殊字符则成立

影响：若 GetBlobsPath 未净化，可能导致缓存路径逃逸、读取/写入预期目录外的文件；URL 拼接侧可能改变请求目标（越权访问其他仓库路径或非预期主机路径）

修复：在 downloadBlob 入口统一做 digest 白名单校验；GetBlobsPath 内部应使用 filepath.Clean 并断言结果位于 blobs 根目录下；URL 侧显式校验 digest 段不包含 &#39;/&#39;、&#39;..&#39;、&#39;@&#39; 等字符

- 证据：server/download.go L463–463 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：	fp, err := GetBlobsPath\(opts.digest\)
- 证据：server/download.go L487–488 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：		requestURL := opts.mp.BaseURL\(\) 		requestURL = requestURL.JoinPath\(&quot;v2&quot;, opts.mp.GetNamespaceRepository\(\), &quot;blobs&quot;, opts.digest\)
- 证据：server/download.go L484–485 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：	data, ok := blobDownloadManager.LoadOrStore\(opts.digest, &amp;blobDownload{Name: fp, Digest: opts.digest}\) 	download := data.\(\*blobDownload\)

复核 v2（MODEL，INCONCLUSIVE）：在组件 U0019 内，符号参数 opts.digest 确实同时进入两个被指称的汇聚点：第 463 行 GetBlobsPath\(opts.digest\) 用于生成本地缓存文件路径，第 488 行 requestURL.JoinPath\(&quot;v2&quot;, opts.mp.GetNamespaceRepository\(\), &quot;blobs&quot;, opts.digest\) 用于拼接注册表请求 URL；第 484 行还把同一 digest 作为 blobDownloadManager 的键。组件内没有任何针对 digest 的字符白名单、filepath.Clean 或“结果仍在 blobs 根目录下”的断言，因此本地边界的输入确实未被净化。但本快照不包含 GetBlobsPath 的实现（search\_code 仅命中第 463 行的调用点，无函数定义）、也不包含 ModelPath.BaseURL/GetNamespaceRepository 的实现，无法判断是否已在被调函数内部完成 digest 格式校验或路径归一化；若净化存在，则本地路径穿越与 URL 侧越权均被阻断。因此关键防御证据缺失，按未完成验证记为 INCONCLUSIVE，而非确认漏洞。

反证：1\) 组件内存在错误传播：GetBlobsPath 返回 err 时立即 return（第 463-466 行），说明该函数可能自带校验/存在性检查，具体行为未知。2\) URL 侧使用 net/url 的 \(\*URL\).JoinPath（已 import &quot;net/url&quot;，第 13 行），JoinPath 以 path.Join 语义拼接并对每个元素做转义，对 &quot;..&quot; 有规范化作用，可在一定程度上抑制路径回溯。3\) 组件中 opts.digest\[7:19\] 的切片用法（第 475、443 行）暗示 digest 预期为 &quot;sha256:&lt;hex&gt;&quot; 定长格式，实际部署中的上游可能已按该格式校验——但这不在本快照内，不能作为已证实的防御。

待补信息：GetBlobsPath 的原始实现（是否校验 digest 字符集/拒绝 &#39;..&#39;、绝对路径前缀、路径分隔符，是否用 filepath.Clean 并断言位于 blobs 根目录）；ModelPath.BaseURL 与 GetNamespaceRepository 的实现（是否已对 repository 做规范化）；以及上游 HTTP 处理器/后端 API 是否把远端可控 digest 直接传给 downloadBlob（第 462 行的调用方不在快照中）。
静态结论范围：COMPONENT

### Prepare 忽略 strconv.ParseInt 错误，未校验的 Content-Length 直接充当下载总量

CWE-252 · MEDIUM · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：HTTP HEAD 响应头 Content-Length（registry 端可控），经 makeRequestWithRetry 返回的 resp.Header.Get 进入本函数

危险操作：strconv.ParseInt\(resp.Header.Get\(&quot;Content-Length&quot;\), 10, 64\) 的返回值被赋给 b.Total，解析错误用 \_ 丢弃；随后 line 153 用 b.Total/numDownloadParts 计算分片大小、line 162 的 for offset &lt; b.Total 决定是否创建分片

防护缺口：缺少对 ParseInt 错误的判断，也缺少 b.Total &lt;= 0（缺失头、0、负值或非数字）的显式校验/报错；缺失 Content-Length 时 b.Total=0，分片循环被跳过且不返回错误，表现为静默的空下载状态

前提：远端 registry（或中间代理）返回 HEAD 响应无 Content-Length、值为非数字或负值；且本地不存在 -partial-\* 残片（len\(b.Parts\)==0）才会走到 line 145-151

影响：b.Total 被设为 0 或负值，分片规划与后续 run\(\) 中的 file.Truncate\(b.Total\)/偏移写入依赖该值，可能导致下载静默完成但文件为空、写入长度与真实内容不一致，或在后续整数/偏移运算中出现异常行为；同时掩盖了上游协议错误

修复：检查 ParseInt 的 err 并显式拒绝，校验 b.Total &gt; 0（并考虑上限），对缺失/异常 Content-Length 返回明确错误而非继续分片规划

- 证据：server/download.go L151–151 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：		b.Total, \_ = strconv.ParseInt\(resp.Header.Get\(&quot;Content-Length&quot;\), 10, 64\)
- 证据：server/download.go L153–153 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：		size := b.Total / numDownloadParts
- 证据：server/download.go L162–162 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：		for offset &lt; b.Total {
静态结论范围：COMPONENT

### Prepare 日志分支对 Digest 做固定下标切片，未校验长度可能越界 panic

CWE-125 · LOW · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：b.Digest（由 NewBlobDownload 使用 opts.digest 构造，digest 源自拉取请求/registry 元数据）

危险操作：b.Digest\[7:19\] 的固定区间切片用于日志格式化

防护缺口：切片前未校验 len\(b.Digest\) &gt;= 19，也未对 digest 做格式/长度校验（同模式还在同文件 line 291、370、443、475 出现，属调用方与本函数共担的校验缺口）

前提：b.Parts 非空（磁盘上已存在 b.Name+&quot;-partial-\*&quot; 残片，line 126-142 聚合成功），且 b.Digest 长度小于 19

影响：Go 运行时 slice bounds out of range panic，使下载路径崩溃（若在服务进程内可能造成 DoS 或请求中 upstream 处理中断），并阻断后续恢复逻辑

修复：对 digest 先做长度/格式校验（或改为截断到安全长度、使用 strings 前缀辅助函数），并把该校验前移到 digest 进入 blobDownload 的位置以覆盖 line 291/370/443/475 等同类切片

- 证据：server/download.go L174–174 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：		slog.Info\(fmt.Sprintf\(&quot;downloading %s in %d %s part\(s\)&quot;, b.Digest\[7:19\], len\(b.Parts\), format.HumanBytes\(b.Parts\[0\].Size\)\)\)
- 证据：server/download.go L126–126 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：	partFilePaths, err := filepath.Glob\(b.Name + &quot;-partial-\*&quot;\)
- 证据：server/download.go L144–144 ；产物 e3245831-dd7d-46c0-9f16-91e7b7b4f641；引用：	if len\(b.Parts\) == 0 {

## 覆盖与错误

```json
{
  "audit_config": {
    "max_model_calls": 400,
    "max_output_tokens": 0,
    "max_tool_rounds": 12,
    "max_units": 40,
    "model_timeout_seconds": 900,
    "reasoning_effort": "high",
    "timeout_seconds": 3600
  },
  "audit_coverage_gap": "共 19 个可读单元，完成 2 个单元的语义审计；其余未审计",
  "audited_unit_count": 2,
  "edge_count": 159,
  "eligible_unit_count": 19,
  "exclusions": [],
  "files": [
    {
      "language": "go",
      "path": "server/download.go",
      "reason": "",
      "status": "PARSED",
      "unit_count": 19
    }
  ],
  "finding_count": 4,
  "function_count": 18,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "PARTIAL",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 18,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "1c49987949af5726ac1ddf397986b4dcee265eaed1db1082e4685377d660c923",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 59,
    "cost_cny": null,
    "measured_tokens": 322951,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "e3245831-dd7d-46c0-9f16-91e7b7b4f641",
  "reviewed_finding_count": 2,
  "structure_partial": false,
  "tools": [
    {
      "command": [],
      "details": {
        "execution": "IN_PROCESS",
        "max_source_bytes": 2097152,
        "per_file_timeout_ms": 1000
      },
      "exit_code": null,
      "finished_at": "2026-09-11T09:36:03.315Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T09:36:03.302Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 19,
  "unresolved_calls": 158,
  "verification": "NOT_RUN",
  "vulnerability_audit": "PARTIAL",
  "warnings": []
}
```

任务错误：智能体响应再次未通过校验：存在未知或被反证的必要攻击条件，不能判为 VALIDATED；请使用 INCONCLUSIVE 或 REJECTED

## 证据产物

- aegis-report-d73387b7-cca6-4c53-a135-ab7717316cf5.html；ID：73cb97e0-0f76-4721-bb43-ee03cb3361dd；SHA-256：cb28529c474cf6d31c56b00566f63fdce989677dfcc39647864da8ae7a031a8d
- aegis-report-d73387b7-cca6-4c53-a135-ab7717316cf5.json；ID：77c74b51-a41c-4d50-8f53-03032832e825；SHA-256：0bd6eb46960576bf400e6d04f06766b5ed2cc04f1e952abae3e5720d0a555e4a
- agent-AUDITOR-960362f7-4c6e-45c2-bc30-5404cf789fa2.json；ID：59a110a8-7643-47ca-aa6c-0d031474cdef；SHA-256：94bee1fdc0f83be9b0755fe9fc8ddb1d4d6fb6d5ab251ce8e14958850ea419aa
- agent-AUDITOR-dcb6759a-59ae-4ade-b1e5-affe02450dd9.json；ID：48cfb95a-1f53-4496-9865-6dcd628e1720；SHA-256：b00e693f0d72f609f120aff372a1f6f2364e6a95961e91266127c7ff7886d406
- agent-PLANNER-068c9c63-994e-4011-a2e8-6725f97032f8.json；ID：48955f80-4d63-44a2-8d46-a461f6f0674f；SHA-256：dad5d79d2590231eda8c75a0c839481e0a89b1698daf1fb20f3cdaf65ba9b90c
- agent-REVIEWER-5ad6bcae-3177-45a2-9aba-f5bc448bfb63.json；ID：a47e8861-2914-46de-98da-aba5c1b1bac9；SHA-256：48e3d7e2d2df1dcecee150401a09b2c16f7bb54fffaa523565c7b05ff978b273
- agent-REVIEWER-fb4c3c67-b9b7-48ce-822c-756b5c93c02a.json；ID：46470b88-a1b3-4a0f-ae6b-88ec82e8d4ee；SHA-256：a67be2adac630b9210af15b423daf58f81461caad20299001780df5e243e544e
- analysis-result.json；ID：e3245831-dd7d-46c0-9f16-91e7b7b4f641；SHA-256：3398c8cd60d6163dad83e2dd7ca608275f755bb07b297a6e27ee56576ecef51a
- model-request-0858ab24-a799-4598-a4ab-d9386bec2637.json；ID：68c7c6ff-f0a3-45fa-852c-4020915d8c52；SHA-256：bd53098eebc9ca178e06e70e541c73bb78a96285ffc38687471c9e733a99db6b
- model-request-0f0854cd-dce5-423c-b050-13397d36316d.json；ID：4c53aa38-ecb7-44bb-8d38-6c37711e4f9b；SHA-256：540cc00d146b27bb1b8ccdb66a1f7ba61557e0dc0692c6ec9449102b9fb8afbb
- model-request-15afe018-38f8-4bb3-823c-29dc90df1c47.json；ID：a9be271a-f739-4095-80c7-cdf038f76d95；SHA-256：1e9768346ea490e3dbc104796e613ee5e2e0a2a2eb28db52dc069271afb6c651
- model-request-1b8bac91-f006-4e87-8ead-7c82878492d6.json；ID：2dca6f68-bf33-4797-8de3-8a2c89c4f7ff；SHA-256：9d77c0ab36f0d3790f5789913083ad6e2906fdbe4007e7bb6d8ce0e485c7fba4
- model-request-1ce51192-f482-44ba-b927-a9c898affae6.json；ID：b9bd8fce-9f7f-4557-a6bd-79e35b48d7be；SHA-256：cc8289b4e6ca43aa8c396fedeb5d8f143b1af8f06ac2ee2f83eb1a4b4bc82d26
- model-request-2117ce06-1e0f-4ba2-8830-9e8767bd3a7e.json；ID：db4ab919-b8ce-44f1-9236-2ee290876a24；SHA-256：5e01c094cc998b34312fe15530fcb5ed9082d4e15574a1ff2b0a523add5b1d78
- model-request-302eef15-ff09-4569-b0ec-52704c1330d9.json；ID：fafe88d4-859e-434c-9b70-44c0f3b8220f；SHA-256：dde1863530e75e4fec94c8cf66f1d1b88b33ea99ec18e6eaf1f2c08cd2cf875c
- model-request-4d3c211b-4cfe-4349-ba63-ae13ded7295c.json；ID：28196820-c258-4337-8d13-666869c98a90；SHA-256：305cae3862370b736563920d6535ccaac04d424b3741752f3aa0d67c9b81166d
- model-request-4d724279-3893-4f7f-9926-8f96c63bc016.json；ID：db1cf16b-5cff-4c4e-b819-cfda88e69906；SHA-256：c5c160b976412aa6a12ea836e3f5bb7c2d282f4704235e5d56263fee40c9362b
- model-request-4f38b15c-95b0-4a01-9a64-6291a0ecb657.json；ID：18b4ae42-8bb2-4231-8db0-72f293029e95；SHA-256：52cdf45360dab0bcecde34504093d9d1f4cc56803bfd42a147ce5e7526be3e5b
- model-request-5144c59c-3bc7-444f-9f3c-a7bc1b1d01d7.json；ID：6c647b78-7242-43ed-8c23-ee0bbac0bea2；SHA-256：5ebebfddf25e04e198623c3250bb5c45dd47f3769775805d5b1210f36132cd57
- model-request-53bd455e-5959-48f5-a58d-cca193b00f6f.json；ID：b5a37725-485b-47c3-a660-a28e8ab28dad；SHA-256：8a9c7ad5a91cdeb53903cccaba87f1909d3c24d196d98d9b7e530f9fd06266de
- model-request-55a263f7-5040-4a93-b28c-7e3aeab808b7.json；ID：38ca3b32-0aab-44ee-89e3-99d89b5187dd；SHA-256：e3c76413dcfb6ba92444de28fdf28dd574fa8eec71cfeaa8ea89d4f1cbb967fe
- model-request-61f99a3b-4657-4fee-ad50-64febb967e17.json；ID：4cb08bfa-c6f4-4ffb-988e-a3ebff7afcf8；SHA-256：b7fa9a91d89d3756bf80176da5dec40ec9b799c6aa20e57c531eff8ddc265f40
- model-request-66314f22-e577-4e64-bb58-f8020ab93781.json；ID：54ee4fd1-6fd1-4e9b-92ae-8a8e0de5812e；SHA-256：ff78f7e904894f8663a612b248cf380ad2d282023bb0639ec427a89798ac0a3a
- model-request-6cac751d-a295-41f3-9be0-05d5d3129289.json；ID：a2fa3989-a777-4d09-83d5-5d4818b30fcd；SHA-256：1fba8ce3b9c1c950fd32f8662ae3c0b60bd0d8b9790ce40f29a0a84d22262133
- model-request-70056783-de1b-4929-9d7d-81d6afbdf156.json；ID：bf6f7029-5db3-42df-a405-7518e1630db3；SHA-256：3cca685985e6d75b6a94ac66756a178af1cb8e4276055cfd9d2596881d746ae3
- model-request-728fee48-2eda-4510-920a-11eec25176f0.json；ID：5b03737c-e766-4af9-aa17-aef7dfeecbe3；SHA-256：e286abe88bca3fd145680c569d27121e28d2f3a51a2f23fcb00ae91f9c4fb98d
- model-request-7a97706d-7685-410e-b3b4-2baa74859ec8.json；ID：fe90d6e2-652e-44cf-93c4-5462b40cf96f；SHA-256：aa486848d7c2cf85c9af54bb6239d41ff43eec4b66ed419f77e2a8225f02f967
- model-request-81cefe90-46e3-4e48-802c-54a4c8ed813f.json；ID：44d5b5d3-363a-4d04-ae86-c09843db184a；SHA-256：0772b7d98195e8f26596a3dfcb4a011abcbf2e26b0b3c5c7c9f573a0430824e5
- model-request-82898fde-9724-42ca-8600-dd2b20ae88cd.json；ID：ad2a5a37-ef89-4789-98b4-4a4375713248；SHA-256：8e978fc12649217c6fb7f984d266bf3b2daa9ef7be8129d1d7070b61b267f72d
- model-request-8574ccba-24c4-472f-b510-ff4acfefcfb9.json；ID：a6fed9fc-c515-414b-9706-9bf47c2350be；SHA-256：14794691a2595e7b913ccbca586374c7af35f915940b59551b40c62151fd2511
- model-request-8a9fe292-e44a-47c4-bd47-7d919d3f1361.json；ID：a4c16a99-dd97-443b-aa99-b08852ea47b0；SHA-256：9fcada7fe468cbc79730a459bc6fcdce959d192e9cc886933a66461ec9816860
- model-request-904d7447-29ef-422e-b38d-dc349f0a84d9.json；ID：8fe31131-8407-42a3-8c75-397524d0a24f；SHA-256：32cd5355b48ac42b7cf2a5a21ad98fc6df39113be5c10778b13500c3e384e889
- model-request-9764cc03-1667-455b-8fca-0ab3701d89d0.json；ID：5364f52b-88bf-47e1-95d5-f5533555f696；SHA-256：b1f93766cad63d76168469b2299057bd9b0d68655a71d35ba45d2c7559568980
- model-request-9cba984e-f239-43dd-a36a-f2f47e17cf11.json；ID：82590b90-4ca9-452e-9920-b075b5915a5c；SHA-256：55e7e9878f351b9c9261d4433510c7682c26651d0068fdbf87a6768b9a4f048f
- model-request-a0ae95b6-26cd-4779-a497-749ab5515ab6.json；ID：ffce0d6f-642f-4d9b-a16a-f3881ddfa70f；SHA-256：736a940699f763fbb5074e096dfc19583a25a408e1bc3f361adda0989e5f5a7d
- model-request-a4ea5868-dcc1-4ff2-83e4-d3acd7c1f86a.json；ID：826b2e0b-9fe5-4345-a486-5bb91c31bd30；SHA-256：8297d9782a9c9c8efd4f102e8dab3d4a24adb3c5fe37a166d93dd8b5b141a1e9
- model-request-a5cd2dcc-e4f6-4273-b6c9-bd245049967a.json；ID：8e3f1229-b1d7-478c-a6d9-ef8ada509977；SHA-256：154e9ace3473e1e326227e390de82f8ac8626b6b67c7817ac8f58acd8416a99c
- model-request-a68a97f1-b35c-46b2-8125-de29b00664dc.json；ID：726f1cd9-30aa-467d-9b8f-fd28f01ff971；SHA-256：0c41a7e3da18bbdc3cd43631c5d1ae64849ea775ef1c0e4f4f0de18a938f0590
- model-request-a9f71157-5664-40fa-8a34-465dc3a62436.json；ID：ef0b3687-add9-4e9d-b443-7cc64ddd5abf；SHA-256：bdb6de812840352cbc87fb6e0f45d46d9c5d770b18cd74cd59af0754009600c3
- model-request-ac7e7b72-8739-40dd-8cde-34f11c91b7f6.json；ID：5eaedaa4-a431-46ef-8706-d381520b4f7a；SHA-256：5c0bda0993f6d1b0a5472c9a10adc4b8a72bc6a723a9fc36a5e92c8ca14a9672
- model-request-add7cbbf-6709-453e-ade8-e3dfcbf40b76.json；ID：7aaa8e8e-ae05-49a9-8988-eea70ce43a87；SHA-256：84a8b4921a31ceaf696f88b726ee5e8c986d055e274a382c61ae22075edf18cf
- model-request-ae074a65-bd1b-427a-b063-d82007e416b0.json；ID：9f2b7358-2814-4ebe-942e-5a4ad430b39c；SHA-256：1991900d80a3bf62074983b5aa1a8a4b6f6db83bf5e8f0b8145448cff836812c
- model-request-b04fb5cc-79b4-4f6b-a196-97908ad51b32.json；ID：d669ae2d-4dd5-4671-8eff-de631826c4ca；SHA-256：585faa9167f5411380ad46789fb9f185ac3c22b20165bc6bf1a17e1895d71556
- model-request-b59040a3-2a5c-448c-8c87-bb355a8c734f.json；ID：6bff1d4b-9ba5-43bb-9b04-85538998fa97；SHA-256：d64ebde3b71973e4f1b2e214696525c577932fe4188678290584d8f6905e925d
- model-request-b7a88ba4-0c07-4e21-9086-abbe5c4c0ec3.json；ID：09431d7f-7995-4241-98bb-b6bf493924b2；SHA-256：fbf0e742faae4c80874116699fe98e5d02dbb735bd177c7b0ffdcb2d80c43ca9
- model-request-bb19e09d-f5dd-4393-a407-ef0e66712048.json；ID：e875bca6-daad-4567-9a46-5d32ef087ca6；SHA-256：5b774e27846cb30328cca55d5bf30f5ea5fc2305f2a0d0714d923f92a461c247
- model-request-bb3ca249-477f-4ebf-9d13-4974ea2fa9cd.json；ID：df5e4119-8bb9-469c-9929-3bcae4f5929e；SHA-256：2cbc9cd4b818077ae5c9b3ea40a3f919d678a96f6fb598ba64d252bd9e355455
- model-request-c59bd0f0-b7ad-4761-8254-53859b681722.json；ID：ba848354-d4e7-4b12-84b7-af6285145c33；SHA-256：d01ca600413327b254a8d6cfc5b6846faf5642ce34613848bc32b87af1d10173
- model-request-c7407874-a93a-44cb-b0f6-770e261c8777.json；ID：c18d6536-0c2a-4bde-9b9e-34e79e55d83e；SHA-256：de8feb8ac748acee6d2755e18fea48f2f1f775acd3c3479b42d1602c80dfeac5
- model-request-c9776a7a-eb2e-431a-8a15-161a2b739b30.json；ID：ccbabae4-ba31-47cc-90df-8b4d193cabd4；SHA-256：fee596026532764e3d51194de5233b2c02abc3ab73f34f012f3de0207a187f7c
- model-request-d614e5ae-c688-4d07-8af1-fa70bc8dc012.json；ID：b18eed57-5021-4fac-9005-28153b38314b；SHA-256：0aaa93708285b3f8142bf6e14d15fd7466515c83575bc23c1f4754860646aee0
- model-request-da993ebd-491c-4210-a93d-8efcd38ec8a0.json；ID：44b43a2b-f165-4a92-a9cb-b4b40b9cb602；SHA-256：1c950ab2b800abdd18fcfad18bd51483a0a20fccd95eeaf1753c3eaf732f709d
- model-request-dafaf702-bda1-4c6c-a53a-66c51beddfc4.json；ID：4a5f309b-9658-433e-b9b4-7e1d7391101b；SHA-256：989be61e4a939d49cea22ee42480a8024a4ddc5fcfd4cbbfd50b5136c86a9569
- model-request-df4669bc-a052-418e-b2c9-d4542783563d.json；ID：cf870eef-86c5-4fce-a100-5072f6ed5049；SHA-256：702ac4190f77794bffbc4052deec81dac085af1a0cbc2e9c0b46dd0d3fe736f1
- model-request-e2ee154b-3175-4bab-a0f9-235c87c797b9.json；ID：6d371dba-97ec-4991-b30b-d05e2e1c4557；SHA-256：cab01ba6d154e42b006384fc8a2c828733df9eae438168f356b5ba149fb8d831
- model-request-e31e9c14-144e-4c2e-8d96-2ca1a3e4dfa8.json；ID：2ef6017e-cc7a-4e4d-8b0e-561641ccc114；SHA-256：9c1f8f4a428d0bf42d8881af8aba79bf1e4c4866fe8fbd818a44485eb946d65c
- model-request-e3c5addd-858a-467c-a5a7-31c321d3e383.json；ID：2a1f3aa4-8159-4917-9545-1180d370d078；SHA-256：d12f2b38f6fa4c27dd3657119db4ec09a1a4a294e825ec045c33def19e5ef9d1
- model-request-e560eb6d-5a86-48df-a3cf-4345e630ac4a.json；ID：e3ea5634-ca27-4621-b58d-5c33346efd96；SHA-256：0c93e95fb14df14947e97a73518d22c330c5bf27db02cbd972e333ff1dddc2bd
- model-request-e58a10af-eccd-4b7e-9e3c-a55bc95ab861.json；ID：cc0c914a-bea0-4a71-803f-870a0748570d；SHA-256：046ba2446c361ba6768d0207f8f1df6e3943f049fd4c114ed644140232fffb7e
- model-request-e5cbab2e-bd11-45ca-bce7-9cf7b995e5d6.json；ID：8662f0f0-1cee-480e-802a-7ca7297d7b61；SHA-256：48dcd3eaaf1a75e51b7a88647c977c77e99fa581543f05479748f866a2170855
- model-request-e60c431c-7692-4a0c-ae5d-e39c05dc9127.json；ID：02bd16e2-b7e2-42bc-87bb-6b6c311e35d1；SHA-256：0a75dd56bd8bf1cc9f52fde66e52c5d97e61d43f9e9792a846f1082ec5dc0ff3
- model-request-e8204a2b-b680-4093-9a8a-b91436a01443.json；ID：8209e093-8623-4117-a699-7a536a3bb800；SHA-256：1b3e8e10816a7a1459b1f0736942044135e759107852aae2e677bc6557aaf1ef
- model-request-e9f1433d-0e16-438a-9df0-9e4aa9cfa062.json；ID：47a46642-8970-4f12-923d-4c7670146e5e；SHA-256：fd71358308822271628f218af33abf5c5acb9f419a8b70de04c190291faf6404
- model-request-ef3e53fc-046a-463d-b5e1-4c55cce0508d.json；ID：75d7d8fa-8708-4ec6-8966-cebcb6b58561；SHA-256：494959b48edb3f3d599cf99c09ceff8dd7557b885dc3060c3ed53387544bd16c
- model-request-f07fbf50-cc05-405c-9b2e-a476d421143a.json；ID：3951b718-248a-43b3-b676-83e9743a2ccb；SHA-256：54fbea0bf1b7dcee61435beb3eb0765d96d611669c0a7d116a7a2dea8e412068
- model-request-f1290461-4e1a-44da-b964-0833e1795d02.json；ID：9ad9e362-aa85-4223-aa0a-331db15581f7；SHA-256：33adbb7b6b62424878ab19c5c4d31b99b367f792ce41f996588164d32443e0fa
- model-request-f6f88ff7-ba6e-47ab-b4a9-72062431b186.json；ID：42d4cc6e-6014-46ad-a47e-343c30062768；SHA-256：395c8c77476b4924b10b4616ee429d6c9bc554a94434cb7c8db7a947028d067a
- model-response-06922f31-bbd7-4443-96d7-da9f5bc72f63.json；ID：a462ac29-29e2-413a-893a-ab0085d89315；SHA-256：6149303a3cd70576403e1b3eb5d21ac0b9c07b801d7550ac438bc5ed046e3332
- model-response-079aff96-c346-475e-b5c9-dbdc508efb79.json；ID：7828698c-e0d5-4a60-8d65-acf4cf5ef42d；SHA-256：e3477990ac2d6eb492046f80c48a2191476d7b7f517f7b00d355cff24bdacff6
- model-response-0962dbae-d556-43f4-9a5f-3f75f4d332a5.json；ID：dd962880-efe2-49ac-bd80-fda413df149e；SHA-256：381de422e7079a1021b51cb9d18fbfd25bd900a4d61979272558f78576bd0107
- model-response-09a73503-5749-426f-97ba-db38e68055c3.json；ID：f26ba689-a719-46d6-baf0-c79176d5eb22；SHA-256：fa79cdd88e546a9beea09f786f8d7016bf62ad1ef5bab3fd1d6f0299f013e50f
- model-response-10ef33c0-4c06-4e7f-a83d-6f308423723e.json；ID：09333162-3418-496c-a197-4677cb1df09c；SHA-256：5fd144b91441bcb78f63feb7b9dac5be07203acec917662feed8ba91563dded7
- model-response-2d947ba2-398b-4fec-a84e-53d14d3c4b28.json；ID：dada0cf5-2786-4841-83b1-813f9b084d0a；SHA-256：e28b55541dc624d40ab2545bccbfb025d0d33e41cb7049ad1d2b7064c6513c71
- model-response-2dd48caa-1010-4172-a78f-531e11ce14a5.json；ID：7047de49-56a4-4ae0-a191-86cbe6d2c444；SHA-256：a8d177678eb100c0db8c3cd0f4927f8576c54a9f10e89fff6946889dffbbc9c7
- model-response-3c14ed82-c5b7-4915-b15a-783084a4d8c5.json；ID：eab3bbc5-4426-4912-ad01-c72726f2e67d；SHA-256：2fb62fbe1bab268e7066c3dfd89cd4562212b44187f17b30d213274b15e3d1c4
- model-response-3ecbe40a-80f5-4570-a426-05bc3bd7ea9c.json；ID：a564a205-8f80-4b68-a8dd-c620f619db03；SHA-256：eb7def55e73c54592ce27a48e0e9b7070f30d5a06d118b5f0c5b9aab94d6d867
- model-response-407afe64-3601-4cf5-86e8-cb518fa7ef49.json；ID：d7933c72-6390-4e64-83f2-be787c72f89c；SHA-256：6a40c1bf4b144e462ab07186e63018747ddf8ec9398329c11666ba973324e059
- model-response-42cd51e3-245f-44c9-9c7a-74acb98e1bec.json；ID：eacae100-0121-4623-8cf8-037d44e57858；SHA-256：6bec1cc1145698716fd92355d3a0a41a6452fc23b731aefd0c95b9f48edecd90
- model-response-49cad1e3-103d-41ca-9615-d580f9ec14bd.json；ID：d2695319-5cf8-4d81-b9a3-684a390bfcc3；SHA-256：ce438e9e073517e31ee06d903330026ac82fe144302be453fca11e13b7ed9dae
- model-response-53db60a3-5f53-4c46-96f2-3aa99829c477.json；ID：dd7dd3ec-4ad6-4345-8495-bab3c11eaac6；SHA-256：68edcff1fd04b4ba428b5b39138192d809bc4602ce2208344a2a7fbee7420cb5
- model-response-542ac4dd-d23d-42d9-a664-1ce56b5bdf86.json；ID：daecba33-a08a-4bcd-846a-ffa2adead8b2；SHA-256：3f8bb4aa4fb0b923ea5a3fbc67a9adc94748619ef6112ea84736b00107a6ee6a
- model-response-55e7ae45-0f42-417e-b00a-e2b6c176014b.json；ID：e8815d69-6ca3-4a82-b16b-86f098332975；SHA-256：93dd72209b222c066b6113aa80cc75f67bbe6a5a3d0327438c0835ffedded02a
- model-response-5641bd86-6f70-48c6-82d2-af0b61b430f7.json；ID：1ab23bb2-6a6a-44cc-a7e2-dac56cc239ea；SHA-256：43617ec7522710274c1ab19e92e90da4a638d77de5f6760daee5266c03e21d5d
- model-response-5cc74e30-134e-4e1f-9639-386dc22d7452.json；ID：c9e612f3-33c9-4bec-821a-fc71497a8e8e；SHA-256：e81b6f48ce7c8cdea711ed6a67d3795e8f195fdbacc8f51d62ba306df74aac1c
- model-response-62daec50-7874-4a5f-90de-261611affb62.json；ID：4770deab-9da0-46a7-8e81-3edbac279a45；SHA-256：ac0717a69af62f9590e7edc236b58fbf3cf18715287ce5bec305793f81534db6
- model-response-6aa23be5-69e2-4e27-9d7e-b95289503444.json；ID：6599d0c7-1a72-477b-8639-fe3d3dcd86bd；SHA-256：ae9d649d8426d1c6b25a1fc766239fa24a30e85aa187addb28084fb3d67bc37b
- model-response-72e6f1e0-25ff-4efe-8186-83ee4fc9d77c.json；ID：fa0999fa-6b98-4859-b2b0-676c1cb52692；SHA-256：f5f208324980d49a3b644f0c0e86d334de622e1c62eb95e7f6196c8269dc9990
- model-response-76289eb2-bbea-470e-9ef0-ac0a912d7751.json；ID：a8722cd4-ed4f-4b40-9b89-ce94e440ce4a；SHA-256：ac3ec3002e158c0dfee93a0e4cb8fecabb1d7bdd10eb6355d1147c228c4f01b4
- model-response-7cd3b838-595e-45f5-9918-0b838864f657.json；ID：230777dc-2e9a-42cc-88c0-40af94ae0196；SHA-256：51068569edbc69b29d0d9460bd20fa471cacdc38b3c14bcbe2257c9f19bcf3db
- model-response-7fbc3dbe-1218-4f3e-a0ac-f235b2f0acaf.json；ID：978963b7-0a17-4daf-8f89-e916d300bad3；SHA-256：3cd2300d9b6aa8e4e4a7d4f61e827da520af5c8590223db50a8ae833ea6f9d74
- model-response-80daf683-7ab3-4e69-a8f6-b82844e44dd3.json；ID：993cd83e-135c-4196-83b4-dd214dbb98da；SHA-256：afe3e3747be57fb38879b217c0db49d3ea60f843bc04be6bb5b987cc330e3ed4
- model-response-8d300fb8-b0ec-4c08-a44e-09ede26945fa.json；ID：a31a9b6f-e0ed-49ad-9cbf-fc891e2b3198；SHA-256：922e243a085e887539b2fd3cb61ca5e666343f0f1c3d2ac6b19882544f81c0b7
- model-response-95dcb1d1-ef51-48c0-9346-02c13bc01b68.json；ID：51066d53-2b8a-4b54-920b-5f9e20a4cf11；SHA-256：4a1f320e7364ac44015031843a546d4217fa91b86f859f724069d435c3d133aa
- model-response-965e26dc-0aaf-49f6-8267-9bc83e66036b.json；ID：1120f3ab-2c70-4752-83bc-74eabd38f364；SHA-256：2be79b62f35a9575b0882fbe3e6f2da4d0192b6f559f399d9b1542d88971cfc6
- model-response-a47ad61a-10dc-4e96-bcdf-ec7c1e9da792.json；ID：fe69af86-3d96-44f0-a325-0240d6fe8e28；SHA-256：96c9f0b3b1c68afebf76b598f9cf08d77e6789f46a0a6e01638737230a383994
- model-response-a5b060c6-5ae3-429a-a9a6-0a3ba1285d78.json；ID：f7fa04d8-8e99-4531-9f24-d9ba6abecb8c；SHA-256：e93ac63418cdabf62696ccf7d0647b45d9f0e791181020a57d501ce43d5c9ace
- model-response-a9ba0725-1223-4691-ac06-573aab9c282c.json；ID：a41b73ec-35ba-412d-b315-11b4fbc3f8ec；SHA-256：5400cf3490c9d4b393323801a5251b9d1d5bf3ceb6ff235aa97ed316b2f3c5ba
- model-response-abe05731-0b9e-4cdd-9d02-a30daca2f1f4.json；ID：ff367080-8c36-471f-9126-f21e292cf20a；SHA-256：df920c7c856a95796dae6a4a23b313a3b690be96b36ec701708a5729641d9008
- model-response-ad9a4118-f177-4140-9056-145dda833e11.json；ID：4184a033-3693-4d6b-a9be-2fcdd50cb3a1；SHA-256：c837ce3b3da915d5a77dc58692f92d7a3e8a82434e744cbf36446edc97f20f9f
- model-response-ae7cfdbe-31b2-4da5-a2b7-a660d2bd5a56.json；ID：44b41c8a-a66f-472f-9033-475cdebd5a77；SHA-256：cdaec4ca53e1a7516589617081171e02bda431e50ffebe892f1777b124e2bbd8
- model-response-b48e8799-e882-4430-8d7f-7c4d87fc2494.json；ID：5b6f2dcf-4229-445a-958a-a04f292bb758；SHA-256：803cc7be5b4e168152decae0e795e0c8791392a4ed8cf4af539a4e501d81d052
- model-response-b5584856-205e-4676-86fd-063d7eb58871.json；ID：2ea8a570-b246-4c77-93fe-53de390faf1d；SHA-256：9632ce5e43f01e8a7ece7cb9d501f4f9b88419a2a0f2746ba2bc4c67c1425b24
- model-response-b7bd0632-dcd0-4dd1-80ab-05c86f20c568.json；ID：0637d503-c5cd-4af8-929d-feb2e062a17e；SHA-256：36eb6bf88eb68bc925518cb58659e748d53ccec5bcb2e3c199e2640849b4bac6
- model-response-b951d241-0d70-43f1-b522-cfa79e6a4062.json；ID：c7c96590-5437-497f-b8c7-80c02d5cb1c9；SHA-256：f7be3b64ac79f84014d052d6e7da6afa3229400ba090001264a4de5619feca1c
- model-response-be9b0c9c-8265-4872-9707-bc9a44fb82e7.json；ID：3aa47182-4567-441b-835e-da5757945938；SHA-256：3e6e7797ac9010f72380c12e9e7b7fd882a942fea7b201e3c26452d4dfdd6a28
- model-response-c140a687-94d1-4cf8-a084-1c2c508db885.json；ID：ea81f297-2557-4105-b1b7-e88ee2a1f161；SHA-256：da7f24cf53ada80989f05bf0b8307b36ebd486e3223f8b106a6b542a7329f485
- model-response-c2aae650-82c1-4d15-979b-e9fae7a3ba5e.json；ID：0e238d62-7c5d-48de-a8c9-cc60ad824ecc；SHA-256：2ad45a73099dba027c049e6d19104d5563bf2153ea2a00a86abd7c8a8618e990
- model-response-c37a265e-1b80-420c-adb2-e7382dbc4279.json；ID：4f978ed8-a776-452a-9b37-b5b9f99187fd；SHA-256：fc45dc8ab15d2f0bc4b1b876a339ebe83b2d97baab5bd94ed973e5d780602667
- model-response-c5ee61a8-f341-47a3-9f4e-17be168b6068.json；ID：570d90b6-67ae-44fc-8000-791518c2e53a；SHA-256：8e7f4c1a914ab090c7993772802dd5cb5221dd37cd8ca1aa46617620d8d13d4a
- model-response-c95b1c0b-8256-4b03-8ffd-06f7296aaba2.json；ID：14ebcb9b-f381-4840-8dca-79c00b53e731；SHA-256：87a172fffe08563623371634fdb222f75b47c7c406ae35963c2a089a67b43ac1
- model-response-d0ca28e3-1abb-41f6-8ca7-607869fb7f05.json；ID：89d2c388-b272-4444-bc1e-40d11ce8745f；SHA-256：bbee5cc2404469040a03d94561cc8b0e206a44e0cd2d0480b1e1c745871fc637
- model-response-d7621ca4-fa9a-43a7-b721-f08855286d3a.json；ID：d6370ac9-2f8d-4c27-b39e-a7a6935bb278；SHA-256：504174f3fc1050e0ab0ebbd79befe29b3a44f06c9196536662dd1ba66c558b93
- model-response-d7b6396f-56cf-4a5e-bcae-a29c9f280a47.json；ID：9df2991b-d796-49c6-bba7-d83e8e3dc41c；SHA-256：e1839346511b2be8ff610302f1beeebc9bc76086d5178b519742234a1a9c94c6
- model-response-d871cfa3-501a-4bd2-b592-843ca2ffbd52.json；ID：d69cf448-22a0-4394-b3d5-99af604b5bed；SHA-256：3854bf3f83892c3031583bf8c2a145cc4b2a857444dbbf0f782e19ee99d9d15e
- model-response-e09c62bb-3bea-4a98-ae8d-de1075253756.json；ID：29e166f3-6187-43fd-9413-3521e6b74406；SHA-256：9e260919b60f41b3c634f689ebf0c81cc9fac254806b392f287113395c46d8bf
- model-response-e1f469a4-e576-4724-b846-2987ce63e614.json；ID：69cdb8aa-21a5-48ef-8c48-ca04ff5c9a0b；SHA-256：67d29057572f2a5155de2301ab1f30d90be9541499afd12deae3c8a2e48439ea
- model-response-e4666a4d-1c93-49f9-adf6-f8d86e8e20d7.json；ID：1849376c-03ab-412a-8f9d-a2f1fb2e290b；SHA-256：3b4d12eb2d7e0f9851dd3df1268359ce50dcd49e3490cb2c1a1148585b2e05a8
- model-response-eca2a1e4-2636-4138-8ab7-3c5781e8ecba.json；ID：6b76883e-5e88-45fc-8622-89d353a9991d；SHA-256：ef9c865911d780a6fb2ac00ee4b7ca6f508d09ad7ad6a6d677a8e3ba257a861b
- model-response-f19f8873-5806-42cd-8248-e641ff834424.json；ID：691d1f90-cd89-4b0e-b4b7-5ba1a724f043；SHA-256：d5723e023688f181aad0f2c0e813c48a044482c36d92e1a14b9b210db6ad864d
- model-response-f1af452a-33f4-417c-92ed-eb970d4d9c7e.json；ID：f884f8c8-1568-47ee-a193-923c57d6f334；SHA-256：317305c5a874e46753984c5306b962e983f5aa73f70edb272d29a9f265f8d8e0
- model-response-f1c5aa2d-4690-45e2-a890-32e92fe8a819.json；ID：8db1585d-ad7d-4c47-997b-2da0a7de88f4；SHA-256：9775a6d16c70e19131b0447aef767189dfa3c18e3d14893dd24e1b1f163833f2
- model-response-f1f44a7c-7f3d-43c4-b48c-2af819a0f423.json；ID：06984832-d320-4a2d-9459-d541744472fa；SHA-256：c74a20eecd39ed5bfe44fa48285ac8f4eb1926e3989db6e92891be5569526701
- model-response-f35980f9-2431-4189-8bae-3955a0257d4b.json；ID：e591c3ff-cfe8-4732-ac62-497f0e53f3b4；SHA-256：b03052204f4db1ac317048d2dc5c06d24c4f82353e0fe37bf67580df89014370
- model-response-f8828c88-65b6-41b1-81c8-fe34c3edaaf8.json；ID：82c38a08-8eeb-4a8c-8c0c-0417051cf0ec；SHA-256：cac48f107f7aa00c4708c6e643d47a2d7630f3d3defa79189bad312b60850fec
- model-response-fca46e71-a44c-40bc-b383-fa617e435447.json；ID：1bd383cd-100c-45c2-8c63-82a93a9312e6；SHA-256：ef8dea926a16b85e424ffe81f584359582b95439b33c64fbae4a496007ee7690
- model-response-ff651c76-30a6-4cdc-b013-5ce21e623902.json；ID：972cf707-4a23-4684-9c71-496a0551b3d8；SHA-256：48d2cc35fd4b4344398471ed2256901ac53056bfd5d6cd6162595391bb358f25
- p06-ollama-parts-fixed.zip；ID：4797662a-b59d-4641-bf4a-f37489fb8d28；SHA-256：7a3817e846ac433ba12751441e2b58a207016e34c97fda1394fbef6193d73480
- snapshot-manifest.json；ID：cc5d8c64-8637-478f-9e5f-7c616658033b；SHA-256：8ba2137001cea6f14be5013b8f307d3a4fe826decbc39107ff8a76c8e31f296e
- source-snapshot.zip；ID：fb1ee4e2-0c76-4a1a-8308-b5bd8cf53ea3；SHA-256：1c49987949af5726ac1ddf397986b4dcee265eaed1db1082e4685377d660c923
