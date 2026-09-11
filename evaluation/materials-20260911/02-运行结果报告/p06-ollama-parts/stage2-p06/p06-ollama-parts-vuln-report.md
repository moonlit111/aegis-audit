# AegisAudit 分析报告

项目：对照池评测 20260911-074524

任务：4b5d2ae3-1313-41e0-9006-d9afd4be1010

状态：Partial

目标 SHA-256：e316cdcaa567cccf22240d0900bc223b488431137330ea2cdc42a2f7fe1cfa48

结果快照 · 数据截至 2026-09-11T07:58:41.699Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：COMPLETED；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

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

在结构分析范围内先梳理 server/download.go 的对外输入面（registry 请求 URL、重定向 Location、HTTP 响应头、已存在的 \*-partial-\* 文件、镜像 Digest）与其派生出的文件路径（b.Name、-partial、-partial-N、file.Name\(\)+索引）以及并发/重试逻辑。优先核对路径拼接、长度/偏移计算、重定向信任策略与错误处理，再扩展到序列化与写入辅助函数。仅依据已读取的原始行（U0001 第 125-323 行）与目录元数据排定优先级，候选点本身不是结论。

1. u\_07e495d3dd6aa8b27e49e12642c95c39：外部入口准备阶段：filepath.Glob\(b.Name+&quot;-partial-\*&quot;\) 使用由 Digest 派生的文件名；解析响应头 Content-Length 得到 b.Total 并据此计算分片 size 与 offset（min/maxDownloadPartSize 比较、offset+size&gt;b.Total 分支）。需核查路径来源可控性、Content-Length 缺失/负值/超界时的整数与循环边界。
2. u\_12b3431c0431f7e754d3ce2f3e153495：核心执行逻辑（已见第 210-323 行）：重定向信任边界最集中处——CheckRedirect 仅比较 req.URL.Hostname\(\) 与 requestURL.Hostname\(\) 且 via&gt;10 才拒绝；返回 resp.Location\(\) 作为 directURL 直接用于后续分片下载；os.OpenFile\(b.Name+&quot;-partial&quot;\)、Truncate\(b.Total\)、os.Remove\(file.Name\(\)+&quot;-&quot;+i\)、os.Rename\(file.Name\(\), b.Name\)。需审计同主机名判定是否覆盖端口/子域/协议降级、Location 未再校验、失败路径清理与错误聚合。
3. u\_ba1b2f47a840cca214954b4fd02d9a77：downloadChunk 是网络数据写入磁盘的落点（io.NewOffsetWriter\(file, part.StartsAt\(\)\) 与重试路径在 run 中可见），需核查偏移/长度越界、短读、内容与 Digest 校验缺失等信任边界问题。
4. u\_c3eaba28de20a888ebaaa4e4013239ce：newPart\(offset,size\) 由外部推导的 b.Total/size 直接构造分片元数据，是整数与偏移计算的汇聚点。
5. u\_aeb09878b7a44df4adf7963e52d7e184：readPart 标有“文件与路径边界”线索，且被 Prepare 用 Glob 结果调用，属未受信本地路径输入进入解析流程的边界。
6. u\_eb6e244fa0d176983723edb6563b14dd：writePart 与分片持久化相关，需确认写入目标路径来源及是否可被外部命名影响。
7. u\_b286648720017324b2783c4c1d07e104：Name\(\) 决定所有派生文件路径（b.Name、-partial、-partial-N）的基础，是路径注入/遍历能否成立的关键上游。
8. u\_7809217b8259d8726307cd39a8cc470e：downloadBlob 属于被识别为 HTTP 入口文件的关键顶层函数，负责串接 Prepare/Run 与参数来源，需确认其输入是否直接来自外部请求。
9. u\_0a4c0f74cacea31ad31932e3e9755d45：MarshalJSON 与 Digest 序列化相关，影响 b.Name 生成所用字符串的来源与规范性。
10. u\_9b5c5b3ba5596e87dc0aaf2154872ff2：UnmarshalJSON 是外部数据进入 Digest 字段的解析点（与 MarshalJSON 第 73-94 行相邻），需核查解析严格性与长度/字符校验。
11. u\_3143315b65867b8302b27304a205d63e：Write 与下载目标写入相关，需确认写入范围与调用者提供的偏移/长度。
12. u\_229bcde3412227517461f68ad219d583：newBackoff 使用 rand.Float64 生成退避时长并叠加 n\*n 上限，关注并发下全局随机/计时器行为及与上下文取消的交互（非安全定论）。
13. u\_fff7fff7e119a76f21db8797224b6a81：Wait 参与分片完成/同步语义，需确认与并发下载、文件截断之间的可见性与竞态边界。
14. u\_1160ffe3141802983336dc5e3a246f6f：StartsAt/StopsAt（U0005、U0006）提供分片偏移到 OffsetWriter 的输入，是越界写入判定的直接依据。
15. u\_29fae45bd4aefe74b7296ee21b1d9403：StopsAt 与 StartsAt 成对使用，需一并核对其计算是否与写入长度一致。
16. u\_ecea19517d243e14b31f761b541160ec：acquire 用于并发配额控制，影响资源耗尽与服务可用性边界。
17. u\_c8c8c9dc026eb02f027825b1351a4575：release 与 acquire 配对的正确性影响并发上限失效风险。
18. u\_9e739a1ddd76dc2dd9abac58aeb14b7b：Run 包装 run 并 defer close\(b.done\)，涉及错误传播与等待语义，作为 U0011 的调用者需交叉核对。

规划限制：仅执行了 1 次读取（U0001 的第 125-323 行），U0002-U0007、U0012-U0019 等函数体未在本角色中直接核验，优先级基于目录元数据与已见调用关系，不构成漏洞结论。

规划限制：call\_graph\_complete=false，动态分发（如接口方法、errgroup 闭包内的调用）可能存在未记录的调用边。

规划限制：semgrep 状态为 UNSUPPORTED（Windows 原生 Semgrep 未就绪），未使用规则匹配结果；无 recovery 元数据，未发生也未声称任何解包/反混淆转换。

规划限制：构建与运行均未执行（build\_executed=false、target\_executed=false），未识别到构建系统、启动入口与依赖清单，部署形态（对外暴露方式、鉴权前置代理）未知。

规划限制：vulnerability\_audit 与 verification 均为 NOT\_RUN；人类注释为空，无外部参考可交叉验证。

规划限制：未做 CVE/版本比对，未确认具体实现缺陷是否可被实际触发；分片大小常量、Digest 校验方式、makeRequestWithRetry 等外部符号定义不在本文件可读范围内，属显式缺口。

## 发现与复核

静态结论范围：COMPONENT

### HEAD 响应 Content-Length 未校验导致 Parts 为空并越界索引 panic

CWE-129 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：registry 的 HTTP HEAD 响应头 Content-Length（line 151 经 resp.Header.Get 读取），以及第 162 行循环条件所依赖的 b.Total

危险操作：line 175 对 b.Parts\[0\].Size 的无保护下标访问（以及为日志计算分支）

防护缺口：line 151 使用 strconv.ParseInt 时以 \`\_\` 丢弃解析错误，且未校验 b.Total &gt; 0；当 b.Total==0（缺失/非法/负值 Content-Length）时，line 162 的 \`for offset &lt; b.Total\` 一次都不执行，b.Parts 保持空切片，随后 line 175 直接取 b.Parts\[0\] 触发 index out of range。缺少 len\(b.Parts\)==0 或 b.Total&lt;=0 的前置拒绝/报错分支。

前提：走无本地 partial 文件的分支（line 144），HEAD 请求成功返回 2xx 但 Content-Length 为空、不可解析或 &lt;=0。

影响：下载准备阶段 panic，拉取流程被中断，可被反复触发形成拒绝服务。

修复：在 line 151 后检查解析错误并显式校验 b.Total 为正值；若 b.Total&lt;=0 或切分后 len\(b.Parts\)==0，返回明确错误而非继续；line 175 记录日志前增加空切片防御。

- 证据：server/download.go L175–175 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	slog.Info\(fmt.Sprintf\(&quot;downloading %s in %d %s part\(s\)&quot;, b.Digest\[7:19\], len\(b.Parts\), format.HumanBytes\(b.Parts\[0\].Size\)\)\)
- 证据：server/download.go L151–151 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：		b.Total, \_ = strconv.ParseInt\(resp.Header.Get\(&quot;Content-Length&quot;\), 10, 64\)
- 证据：server/download.go L161–172 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：		var offset int64 		for offset &lt; b.Total { 			if offset+size &gt; b.Total { 				size = b.Total - offset 			}  			if err := b.newPart\(offset, size\); err \!= nil { 				return err 			}  			offset += size 		}

复核 v2（MODEL，VALIDATED）：在 len\(b.Parts\)==0 分支（U0008 line 144）中，b.Total 被 line 151 用 strconv.ParseInt 赋值且以 \`\_\` 丢弃解析错误。当 HEAD 响应缺少可解析且为正的 Content-Length 时，b.Total 为 0（空串/非法串返回 0；&#39;0&#39; 返回 0；负值返回负）。此时 line 153 的 size 虽被钳制为 minDownloadPartSize，但 line 162 的 \`for offset &lt; b.Total\`（offset 从 0 起）在 b.Total&lt;=0 时一次都不执行，b.newPart 从未被调用，b.Parts 仍为空切片。随后 line 175 无条件访问 b.Parts\[0\].Size 计算日志，对空切片取下标触发 index out of range panic。整条路径无任何 len\(b.Parts\)==0 或 b.Total&lt;=0 的拒绝分支，崩溃可由远端镜像源响应头直接决定，属于组件接口内可证明的边界缺陷。

反证：已检查的防御：line 167-169 会对 newPart 的错误返回；line 126-129 处理 glob 错误；line 134-137 处理 readPart 错误。但这些都在 parts 非空或循环体内，无法阻止空 Parts 路径。line 153-159 只钳制 size，不校验 b.Total。代码中没有对 b.Total 正值的校验，也没有对 len\(b.Parts\) 的判空。

待补信息：完整部署中的调用者与路由未提供，但组件层面不依赖它们：崩溃条件仅需 requestURL 指向的 registry 返回成功但 Content-Length 缺失/非法/非正。上游 makeRequestWithRetry 的实现不在本快照中，无法确认它是否会在响应头异常时提前报错；若它会因缺少 Content-Length 而报错，则该路径不可达——这是唯一未确认的条件。
静态结论范围：COMPONENT

### 未校验的 Digest 长度导致切片越界 panic（可被短摘要/损坏元数据触发）

CWE-129 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：b.Digest（由 downloadBlob 中 opts.digest 设置，来自注册表清单/调用方传入的摘要字符串）

危险操作：b.Digest\[7:19\] 固定偏移切片（日志格式化参数）

防护缺口：缺少对 digest 格式/长度（例如是否满足 &quot;sha256:&quot; + 12 位十六进制、len&gt;=19）的前置校验或安全截断，使用硬编码偏移直接切片

前提：存在一条使 b.Digest 长度小于 19 的调用路径（例如受损或被篡改的清单/摘要、或被污染的本地进度元数据）且未在更外层被拒绝；GetBlobsPath 是否校验摘要格式在本快照内不可见

影响：下载 goroutine panic，整个进程崩溃（可用性丧失）；同一模式在其它单元（例如进度上报处）重复出现，会放大影响面

修复：在生成 blobDownload 前对 digest 做严格格式校验（前缀与十六进制长度），或在日志与命名处使用带长度检查的辅助函数做安全截断，避免固定偏移下标；同时在下载 goroutine 内加入 recover+错误上报，使单个分片异常不致终止进程

- 证据：server/download.go L291–291 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：					slog.Info\(fmt.Sprintf\(&quot;%s part %d attempt %d failed: %v, retrying in %s&quot;, b.Digest\[7:19\], part.N, try, err, sleep\)\)
- 证据：server/download.go L279–281 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：			for try := 0; try &lt; maxRetries; try++ { 				w := io.NewOffsetWriter\(file, part.StartsAt\(\)\) 				err = b.downloadChunk\(inner, directURL, w, part\)
- 证据：server/download.go L484–484 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	data, ok := blobDownloadManager.LoadOrStore\(opts.digest, &amp;blobDownload{Name: fp, Digest: opts.digest}\)

复核 v2（MODEL，INCONCLUSIVE）：代码事实成立：Go 中字符串切片 s\[7:19\] 要求 len\(s\)&gt;=19，否则运行时 panic；U0011 第291行的 b.Digest\[7:19\] 位于 g.Go\(...\) 派生的 errgroup goroutine 内（第277-300行），未被 recover 的 goroutine panic 会终止进程。数据流也成立：downloadBlob 的调用方参数 opts.digest 未经本组件任何长度检查，直接写入 blobDownload 的 Digest 字段（U0019 第484行），随后由 run 使用（U0011 第211、291行），同一硬编码偏移还出现在 U0019 第475行与下载路径其它日志处。但关键前置条件无法在本快照内证实：U0019 在访问该字段前先调用 GetBlobsPath\(opts.digest\)（第463行）并在出错时直接返回（第464-466行），而 GetBlobsPath 的定义不在提供的证据中（对 &quot;GetBlobsPath&quot;/&quot;func GetBlobsPath&quot; 的检索只命中调用点），因此无法判断它（或第489行的 blobDownload.Prepare / 清单解析）是否已拒绝格式或长度不合法（例如 len&lt;19）的 digest。若上游/该函数已强制摘要格式，则短摘要永远到不了切片处，该声明被该检查反驳；若仅校验前缀与十六进制而不管长度，则缺陷成立。故本组件内缺少本地长度检查是可确认的代码形态，但『短摘要可达』这一必要条件是缺失证据，不能升格为 VALIDATED。

反证：\(1\) U0019 第463-466行：进入切片之前先经 GetBlobsPath 且错误被立即返回，是最可能的既有格式校验点，仅因源码不在快照内无法判定；\(2\) 第475行同样使用 opts.digest\[7:19\] 却无保护，说明代码库整体假设 digest 已规范化，属于既定契约而非逐点校验；\(3\) 本组件内确实没有任何显式 len\(digest\)&gt;=19 检查，也没有局部 recover，故并未被本地防御完全反驳。

待补信息：GetBlobsPath 的实现（是否用正则/前缀+固定长度校验 digest 格式）不在提供证据中；blobDownload.Prepare 与注册表清单解析是否校验 / 规范化 digest 未知；opts.digest 在该 COMPONENT 之外的上游是否可能为攻击者影响的短字符串（例如被篡改的清单或本地进度元数据）未知。
静态结论范围：COMPONENT

### 重定向信任策略仅比较主机名（忽略协议与端口），且分片下载未复用该策略

UNKNOWN · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：注册表返回的 HTTP 重定向 Location（resp.Location\(\)，第262行）与 requestURL.Hostname\(\)

危险操作：CheckRedirect 中的主机名比较与放行判定：req.URL.Hostname\(\) == requestURL.Hostname\(\) 返回 nil（允许继续跟随）

防护缺口：未比较 scheme 与端口（Hostname\(\) 忽略二者），也未在放行时校验目标是否为受信任的原始来源；同时解析直链后真正下载分片时并未复用该重定向策略（分片请求走默认客户端，跨主机重定向不受此限制）

前提：攻击者能影响注册表响应头/重定向链（恶意或被攻陷的 registry、镜像代理）；或目标主机名上存在攻击者可控的其它端口服务

影响：携带注册表认证信息的请求被转发到非预期的协议或同主机名的其它端口服务，造成凭据/令牌暴露风险；下载内容的实际来源脱离原始信任边界，削弱内容来源可信性

修复：重定向判定应同时比较 scheme、host 与 port，默认只允许 https 且拒绝降级；对跨主机重定向应显式剥离敏感请求头并停止跟随；分片下载应复用同一受限的重定向策略与自定义客户端，而非默认客户端

- 证据：server/download.go L240–240 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：				if req.URL.Hostname\(\) == requestURL.Hostname\(\) {
- 证据：server/download.go L234–237 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：			newOpts.CheckRedirect = func\(req \*http.Request, via \[\]\*http.Request\) error { 				if len\(via\) &gt; 10 { 					return errors.New\(&quot;maximum redirects exceeded \(10\) for directURL&quot;\) 				}
- 证据：server/download.go L250–250 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：			resp, err := makeRequestWithRetry\(ctx, http.MethodGet, requestURL, nil, nil, newOpts\)
- 证据：server/download.go L262–262 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：			return resp.Location\(\)

复核 v2（MODEL，INCONCLUSIVE）：组件确实仅以 Hostname\(\) 比较重定向目标（U0011:240），忽略 scheme 与端口，并在 U0011:262 直接以 resp.Location\(\) 作为 directURL，随后 U0012 的分片下载使用 http.DefaultClient（U0012:333）而不再套用该 CheckRedirect 策略，因此代码属性描述属实。但候选声称的‘凭据/令牌被转发到非预期协议或同端口主机’这一危险操作，其触发输入来自注册表的 HTTP 响应重定向（resp.Location\(\)），而不是本组件调用者传入的参数；要让该响应变为恶意，需要额外攻击者能力（攻陷/劫持注册表或同主机名上存在攻击者可控的其它端口服务），这些前提在组件内部代码中未被证明，也无法从本边界推断。输入控制与额外前提均不确定，故不能判定为可辩护的既定漏洞，也不足以否定代码属性，属于证据不足。

反证：同主机名比较本身是一种有意收紧的策略：跨主机重定向返回 http.ErrUseLastResponse（U0011:247），默认不会自动跟随到外部主机；分片下载路径仅设置 Range 头（U0012:332），未见携带注册表 Authorization/令牌，故‘分片下载泄露凭据’在现有源码中缺乏证据；makeRequestWithRetry 及 opts 中是否植入认证头的代码不在本单元内，无法确认凭据确实随重定向转发。

待补信息：1\) 注册表响应/重定向链是否可被攻击者影响（恶意注册表、镜像代理或 TLS 层篡改），源码未示；2\) 同一主机名的其它端口是否驻留攻击者可控服务，未示；3\) makeRequestWithRetry 与 registryOptions 是否注入 Authorization/令牌并在跟随重定向时被 Go 客户端上报（相关实现不在本快照单元内）；4\) Go 客户端对同主机名 scheme 变更时是否复制敏感头，需运行时/标准库行为佐证，本审阅不作断言。
静态结论范围：COMPONENT

### 分块下载使用 http.DefaultClient 发起 GET，绕过 run\(\) 中的重定向同源限制与注册表客户端配置

CWE-918 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：run\(\) 传入的 directURL（U0011:281 调用本函数），其值来自注册表 HTTP 响应的 Location 头（U0011:262 resp.Location\(\)）

危险操作：http.DefaultClient.Do\(req\) 对 directURL 发起带 Range 的分块 GET，并跟随其后的任意重定向

防护缺口：未复用 run\(\) 中设置的 CheckRedirect（仅允许同主机跳转，U0011:234-248），也未使用带凭据/超时的注册表客户端，未对最终连接主机做任何校验

前提：攻击者能控制或影响注册表响应（含伪造镜像源、Location 污染、中间人）；客户端按用户配置的 BaseURL 拉取镜像

影响：分块请求可被重定向到任意主机，泄露请求元数据（Range、User-Agent、预签名查询串），并可能被引导读取非预期内容写入本地 blob（后续依赖摘要校验），构成 SSRF 类信任边界问题

修复：在downloadChunk 中复用受控的 http.Client（含 CheckRedirect 与超时），或显式校验 directURL 主机/协议与注册表主机关系；对最终响应强制校验摘要

- 证据：server/download.go L333–333 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：		resp, err := http.DefaultClient.Do\(req\)
- 证据：server/download.go L234–248 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：			newOpts.CheckRedirect = func\(req \*http.Request, via \[\]\*http.Request\) error { 				if len\(via\) &gt; 10 { 					return errors.New\(&quot;maximum redirects exceeded \(10\) for directURL&quot;\) 				}  				// if the hostname is the same, allow the redirect 				if req.URL.Hostname\(\) == requestURL.Hostname\(\) { 					return nil 				}  				// stop at the first redirect that is not 				// the same hostname as the original 				// request. 				return http.ErrUseLastResponse 			}
- 证据：server/download.go L281–281 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：				err = b.downloadChunk\(inner, directURL, w, part\)

复核 v2（MODEL，VALIDATED）：复核原始代码（U0012:325-333）：downloadChunk 的取数入口就是调用方传入的 requestURL（\*url.URL），第 328 行以 requestURL.String\(\) 直接构造带 Range 头的 GET，第 333 行用共享的 http.DefaultClient 发送，参数值未被改写、未做协议/主机校验。http.DefaultClient 采用 Go 默认重定向策略（跨主机最多跟随 10 跳），本单元没有 CheckRedirect、超时或主机白名单，因此分块 GET 会跟随远端返回的任意 3xx 到攻击者指定的主机，属“服务器侧对远端可控 URL 取数并可再跳转”的 SSRF 形状信任边界缺陷；参数到 sink 之间无分支或守卫，组件级可达性成立，函数参数即为该边界的符号化输入。两点需修正：其一，U0011:234-248 的 CheckRedirect 建在 newOpts 上、仅服务于 U0011:250 的 makeRequestWithRetry，其语义是“不跟随首个跨主机跳转、把该 Location 当作直链返回”（U0011:262），直链本就设计为跨主机，故“绕过同源限制”表述不精确，真正缺失的是本函数对直链及其后续跳转的主机约束；其二，Go 跨域重定向会剥离 Authorization/Cookie 等敏感头且不会把原 URL 查询串带过去，故“预签名查询串泄露”不成立，可确认的外泄仅限 Range/User-Agent 一类非敏感头，主要影响是无凭据的盲 SSRF 探测与跨主机流量引导。

反证：1\) run\(\) 的同行名限制通过 http.ErrUseLastResponse 结束跟随并返回 Location（U0011:240-247、262），说明直链跨主机是预期行为，该检查并非直链白名单，不能据此断言安全控制被绕过；2\) 本单元不携带注册表凭据，使用 http.DefaultClient 恰好避免把凭据带给第三方主机，这解释了为何此处不复用注册表客户端；3\) Go 跨域重定向去敏感头、不继承原查询串，削弱了元数据泄露的申报口径；4\) 响应体经 io.TeeReader 送入 part 并随后 writePart（U0012:339-348），若下游存在摘要校验可抑制内容投毒，但本单元未见校验源码，故不据此排除该发现。

待补信息：1\) 实际调用链是否把注册表 Location 原样传入（当前可见证据仅 U0011:262 的 resp.Location\(\)，中转调用点未逐行核实）；2\) 部署中注册表/镜像源/CDN 是否可被攻击者控制或存在中间人；3\) 下载后是否有摘要校验（part 是否为摘要计算器）及失败处理；4\) 结论仅覆盖 downloadChunk 组件边界，不代表完整部署的服务端 SSRF 已被利用。
静态结论范围：COMPONENT

### 日志中按固定下标切分 Digest（b.Digest\[7:19\]），缺少长度校验

CWE-129 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：b.Digest（downloadBlob 由 opts.digest 赋值：U0001:484，最终源自注册表模型清单中的摘要字符串）

危险操作：fmt.Sprintf\(msg, b.Digest\[7:19\], part.N\) 中的固定下标切片

防护缺口：本函数未校验 Digest 长度/格式；同文件其它日志与进度输出同样假定长度&gt;=19（U0001:175/291/443/475）

前提：Digest 为非校验来源且长度小于 19（例如畸形清单、上游校验被绕过或被替换）

影响：分块监控 goroutine 中 panic，导致进程崩溃（Go 中 goroutine panic 不可恢复），可被远端畸形元数据触发拒绝服务

修复：统一使用 Digest 截断辅助函数（长度不足时安全截断），或在 downloadBlob/GetBlobsPath 入口强校验 sha256:&lt;64hex&gt; 格式后再入库

- 证据：server/download.go L370–370 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：					slog.Info\(fmt.Sprintf\(msg, b.Digest\[7:19\], part.N\)\)
- 证据：server/download.go L484–484 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	data, ok := blobDownloadManager.LoadOrStore\(opts.digest, &amp;blobDownload{Name: fp, Digest: opts.digest}\)

复核 v2（MODEL，INCONCLUSIVE）：U0012:370 的确对 b.Digest 使用固定下标切片 b.Digest\[7:19\]，函数内无长度校验；该值来自 U0001:484 的 opts.digest。但同一代码流程中会更早执行相同的固定下标切片：downloadBlob 在 U0001:475 使用 opts.digest\[7:19\]，Prepare 在 U0001:175 使用 b.Digest\[7:19\]，而 Prepare 在 U0001:489 先于 download.Run\(U0001:495\) 被调用，且失败返回会阻断后续。因此当 len\(Digest\)&lt;19 时 panic 会先发生在 175/475，U0012:370 只有在 len\(Digest\)≥19 时才可达；这既削弱了以 370 为确切触发点的描述，也说明真正的边界问题位于更早的切片点。更关键的是，U0011:463 调用的 GetBlobsPath 定义不在本快照内，无法确认其是否已对 digest 做 sha256:&lt;64hex&gt; 之类的格式/长度校验；在缺少该证据时，无法判定『短 Digest 能进入该组件』这一前提是否成立，故整体结论为不确定。

反证：已考虑并核对：U0001:175 与 U0001:475 在流程中先于 U0012:370 执行同样的固定下标切片，构成对 370 作为触发点的顺序性反证；U0001:463 的 GetBlobsPath 可能已做摘要格式校验（定义缺失，未能确认）；Go 字符串越界切片产生 panic 而非内存破坏，且本组件未见 unsafe/cgo 注入路径。

待补信息：GetBlobsPath 的实现及其对 digest 的校验逻辑；downloadBlob 的实际调用方是否会把非标准/短摘要传入；能否通过畸形清单或上游校验被绕过注入长度&lt;19 的 Digest（缺少调用方与路由证据，不主张已观测）。
静态结论范围：COMPONENT

### 分块长度/偏移由磁盘 partial 元数据直接计算，缺少 0&lt;=Completed&lt;=Size 一致性校验

CWE-190 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：part 元数据（Size/Completed/Offset）由 Prepare 从磁盘 glob 的 \*-partial-\* 文件经 readPart 反序列化得到（U0001:126、U0001:404），可被本地文件篡改或异常中断写入污染

危险操作：io.CopyN\(w, io.TeeReader\(resp.Body, part\), part.Size-part.Completed.Load\(\)\) 的拷贝长度，以及同源派生的 Range 头 bytes=StartsAt-StopsAt-1

防护缺口：未校验 part.Offset/Completed/Size 的取值关系（Completed&lt;=Size、StopsAt&gt;StartsAt、Offset+Completed 不超过 b.Total），也未校验服务端返回长度与请求区间一致

前提：本地 partial 元数据文件被篡改/损坏，或先前写入产生 Completed&gt;Size；随后触发带重试的续传分支

影响：可能出现负长度拷贝导致静默 0 字节下载被当作成功，或 Range 头区间倒置使服务端返回 416/错误内容，最终 b.Name 被重命名成貌似完整但内容错误的 blob（依赖上层摘要校验兜底）

修复：在 Prepare/readPart 与 downloadChunk 两侧校验元数据不变量（0&lt;=Completed&lt;=Size、Offset&gt;=0、Offset+Size&lt;=Total），对非法值丢弃或重启分块；对服务端响应校验 Content-Range 与请求区间一致

- 证据：server/download.go L339–339 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：		n, err := io.CopyN\(w, io.TeeReader\(resp.Body, part\), part.Size-part.Completed.Load\(\)\)
- 证据：server/download.go L332–332 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：		req.Header.Set\(&quot;Range&quot;, fmt.Sprintf\(&quot;bytes=%d-%d&quot;, part.StartsAt\(\), part.StopsAt\(\)-1\)\)
- 证据：server/download.go L404–404 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	if err := json.NewDecoder\(partFile\).Decode\(&amp;part\); err \!= nil {
- 证据：server/download.go L126–126 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	partFilePaths, err := filepath.Glob\(b.Name + &quot;-partial-\*&quot;\)

复核 v2（MODEL，INCONCLUSIVE）：组件内部静态行为与候选描述一致：downloadChunk 在第339行以 part.Size-part.Completed.Load\(\) 作为 io.CopyN 的拷贝长度（U0012:339），第332行由 part.StartsAt\(\)/StopsAt\(\) 直接派生 Range 头（U0012:332）。part 的 Offset/Size/Completed 仅经 readPart 的 json.Decode 反序列化得到（U0001:404-406），UnmarshalJSON 也不做取值域校验（U0001:82-94）；Prepare 通过 filepath.Glob 读取本地 \*-partial-\* 文件后求和（U0001:132-142）。若 Completed&gt;Size，则 part.Size-part.Completed 为负，Go 的 io.CopyN 对负 n 经 LimitReader（N&lt;=0 立即返回 EOF）得到 written=0 且 err=nil，本函数返回 nil，run 只跳过 Completed==Size（U0001:273-275），故该 part 被当作完成并最终 os.Rename 成 b.Name。因此“缺少不变量校验、负长度静默成功”这一组件级静态缺陷成立。但正常路径不会产生 Completed&gt;Size：CopyN 受 Size-Completed 限制，写入量必然 &lt;=Size，无自然溢出路径；触发该缺陷必须让磁盘上的分块元数据被改成合法 JSON 且 Completed&gt;Size。该额外能力属于本地文件系统篡改/并发写入，本快照无证据，故整体结论为 INCONCLUSIVE 而非 VALIDATED。

反证：第273行跳过仅在 Completed==Size 时生效，无法拦住 Completed&gt;Size；组件内无 0&lt;=Completed&lt;=Size、Offset&gt;=0、Offset+Size&lt;=Total 或响应长度一致性校验。反向证据：正常执行流中 io.CopyN 的 n 由 LimitReader 以 Size-Completed 为上限，part.Completed 每次 Add\(n\) 后不可能超过 Size，因此不变量不会自然被破坏，必须依赖外部元数据被篡改/损坏或并发写入这一额外前提。上层摘要校验（候选所述兜底）不在本组件范围内，故不能据此直接 REJECTED。

待补信息：是否具备可写入/篡改本地 blobs 目录下 \*-partial-\* 元数据文件的攻击者能力（或被中断写入造成合法 JSON 且 Completed&gt;Size）；是否存在跨进程并发 Prepare/run 导致 writePart 截断-写入竞争；上层摘要校验是否会在重命名后拒绝该 blob。这些均未在本快照中得到证据。
静态结论范围：COMPONENT

### 部件文件名由注册表可控的 digest 派生，写入时以 O\_TRUNC 打开，缺少可见的路径与 digest 校验

CWE-22 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：registry 响应中的镜像 digest（downloadBlob 中 opts.digest → GetBlobsPath\(opts.digest\) → blobDownload{Name: fp}，见 U0019 第 463、484 行），最终经 newPart 传给 part.Name\(\)

危险操作：os.OpenFile\(partName, os.O\_CREATE\|os.O\_RDWR\|os.O\_TRUNC, 0o644\)（U0015 第 413 行）

防护缺口：在 U0013/U0004/U0015 中未见对 digest 的格式白名单、对拼接后路径的 filepath.Clean/前缀包含校验，也未见确保最终路径仍位于 blobs 目录内的检查；part 名仅是 &quot;&lt;Name&gt;-partial-&lt;N&gt;&quot; 的裸字符串拼接。

前提：攻击者能控制/劫持 registry 响应或 digest 值，使其包含路径分隔符或 ../ 等字符；且 GetBlobsPath 未做充分的规范化与目录约束（该函数本次未读取，属显式缺口）。

影响：若 digest 未被约束，写入/截断可能越出预期的 blobs 目录，覆盖或创建任意可写路径下的文件（0o644、O\_TRUNC 会清空既有内容），或以服务进程权限造成数据破坏。

修复：对 digest 施加强格式校验（如 sha256:&lt;64 位十六进制&gt;），在派生文件路径后使用 filepath.Clean 并校验其位于预期目录前缀内；部件名不应由外部字符串直接参与路径拼接。

- 证据：server/download.go L413–413 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	partFile, err := os.OpenFile\(partName, os.O\_CREATE\|os.O\_RDWR\|os.O\_TRUNC, 0o644\)
- 证据：server/download.go L103–105 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	return strings.Join\(\[\]string{ 		p.blobDownload.Name, &quot;partial&quot;, strconv.Itoa\(p.N\), 	}, &quot;-&quot;\)
- 证据：server/download.go L463–463 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	fp, err := GetBlobsPath\(opts.digest\)
- 证据：server/download.go L484–484 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	data, ok := blobDownloadManager.LoadOrStore\(opts.digest, &amp;blobDownload{Name: fp, Digest: opts.digest}\)
- 证据：server/download.go L387–388 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	part := blobDownloadPart{blobDownload: b, Offset: offset, Size: size, N: len\(b.Parts\)} 	if err := b.writePart\(part.Name\(\), &amp;part\); err \!= nil {

复核 v2（MODEL，INCONCLUSIVE）：在组件边界内，downloadBlob 的入参 opts.digest 确实经 GetBlobsPath 得到 fp，再作为 blobDownload.Name 传入 newPart→part.Name\(\)→writePart 的 partName，最终进入 os.OpenFile\(partName, O\_CREATE\|O\_RDWR\|O\_TRUNC, 0o644\)（U0019:463、U0019:484、U0013:387-388、U0015:412-413）。因此“外部字符串抵达文件创建/截断操作”这一局部链条成立。但是否构成路径穿越完全取决于未提供的 GetBlobsPath：快照中只有 server/download.go 一个文件，search\_code 对该符号仅返回调用点，未包含其定义或任何规范化/白名单/前缀校验代码，无法判断 digest 中的分隔符或 ../ 是否被剥离或拒绝。候选描述本身也承认该函数未读取属于显式缺口。在关键净化环节缺失证据时，不能把“未见的校验”等同于“校验不存在”，故不能确证 CWE-22。

反证：已确认的反面/待证证据：（1）writePart 仅做裸字符串拼接（U0013:387-388 用 part.Name\(\)，U0004:103-105 拼 &#39;&lt;Name&gt;-partial-&lt;N&gt;&#39;），本身不含净化；（2）但 Name 的来源是 fp，而 fp 由 GetBlobsPath\(opts.digest\) 返回，该函数的实现不在本次快照内，可能已包含 digest 格式限制（如仅接受 sha256:&lt;hex&gt;）与目录约束；（3）downloadBlob 中另有 os.Stat\(fp\) 与 URL 拼接使用同一 digest（U0019:468、U0019:488），未见独立二次净化代码。

待补信息：GetBlobsPath 的实现与所在文件；digest 在进入 downloadBlob 之前是否已被 manifest 解析层校验；blobDownloadManager 键与 Name 的实际取值来源；部署中 opts.digest 是否可能来自不可信 registry/中间人响应。
静态结论范围：COMPONENT

### 部件编号取自内存切片长度，重复编号会以 O\_TRUNC 覆盖已有部件文件

CWE-362 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：newPart\(offset, size\) 的调用方（本次未读取）与 b.Parts 内存状态

危险操作：writePart\(part.Name\(\), &amp;part\) 中 os.OpenFile 的 O\_CREATE\|os.O\_RDWR\|os.O\_TRUNC（U0015 第 413 行）

防护缺口：未见对 len\(b.Parts\) 作为编号唯一性的保护（如计数单调递增、检查文件是否已存在），也未见写入前对目标文件归属的确认。

前提：并发或重试路径中 b.Parts 被缩减/重置，或同一 offset 被重复申请部件，使两部件得到相同 N 与相同文件名。

影响：部件文件被截断重写，造成断点续传数据不一致、校验失败或读取到不完整 JSON。

修复：使用单调递增的部件序号或依据 offset/size 生成唯一名，并在创建前检测既有文件；避免对进行中的部件文件使用 O\_TRUNC。

- 证据：server/download.go L387–387 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	part := blobDownloadPart{blobDownload: b, Offset: offset, Size: size, N: len\(b.Parts\)}
- 证据：server/download.go L413–413 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	partFile, err := os.OpenFile\(partName, os.O\_CREATE\|os.O\_RDWR\|os.O\_TRUNC, 0o644\)

复核 v2（MODEL，INCONCLUSIVE）：在部件边界内，newPart 的编号 N 来自 len\(b.Parts\)（U0013:387），且紧接着就以 append 增长切片（U0013:392），因此对同一个 blobDownload 的连续调用会得到 0,1,2… 互不相同的 N，Name\(\) 拼出的文件名也随之不同（U0004:102-106），组件自身不产生重名。唯一调用点 Prepare 在单次顺序循环中调用 newPart 并逐次 append（U0008:162-172），且仅当 len\(b.Parts\)==0 时才创建新部件（U0008:144），既有部件是从磁盘读入的。因此候选所述「同一 offset 重复申请 / 编号重复导致同名文件被 O\_TRUNC 截断」需要 b.Parts 被缩减、重置，或同一 blobDownload 被并发调用等外部状态变化，而整个可见切片中只有两处对 b.Parts 的 append（U0008:141、U0013:392），没有任何删除/重置代码，也没有并发访问证据。该额外前置条件是缺失证据的真实未知项，故不能判定 VALIDATED，也无反面源码可完全否定。

反证：同一对象的连续调用因 append 单调增长而不会重号（U0013:387、392）；Prepare 仅在无既有部件时创建并顺序编号（U0008:144-172）；已有部件通过 readPart 从磁盘载入（U0008:134、U0014:396-410），不会与新建部件争夺编号；可见代码中不存在 Parts 缩减/重置路径。

待补信息：是否存在会缩减或重置 b.Parts 的清理逻辑、同一 blobDownload/同一文件名是否可能被并发 Prepare 或重试调用（单次工具额度内未读到直接调用方之外的并发调度代码），以及这些条件是否可由组件参数之外的因素触发。
静态结论范围：COMPONENT

### 分片状态 JSON 反序列化后未做范围/一致性校验即用于下载偏移与文件长度计算

CWE-1284 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：磁盘上已有的 &lt;b.Name&gt;-partial-\* JSON 文件，由 U0008（Prepare, 第126行 filepath.Glob\(b.Name+&quot;-partial-\*&quot;\)）枚举后逐个传入 readPart；blobDownloadPart 的字段通过自定义 UnmarshalJSON（U0001, 第82-94行）从该文件填充。

危险操作：readPart 中的 json.NewDecoder\(partFile\).Decode\(&amp;part\)（第404行）将文件内容直接反序列化为 blobDownloadPart 并随后 part.blobDownload = b 返回使用。

防护缺口：未校验 Offset &gt;= 0、Size &gt; 0、Completed 的范围（0&lt;=Completed&lt;=Size）、N 与文件名后缀索引的一致性，也未校验 Offset+Size 不超过 HTTP Content-Length 得到的 b.Total；解码成功后无任何再校验或拒绝分支。

前提：攻击者/异常状态能在模型 blobs 目录中放置或残留可写的 &lt;name&gt;-partial-\* 文件（例如中断的下载、被篡改的本地状态），随后触发 blobDownload.Prepare。

影响：b.Total 与 part.Offset/Size（U0008 第139-141行累加）受外部数据控制，进而影响 run 中的 file.Truncate\(b.Total\)（第221行）、io.NewOffsetWriter\(file, part.StartsAt\(\)\)（第280行）以及 Range 请求与进度统计，可产生异常大的稀疏文件、错误/负偏移写入、分片长度下溢或下载永久失败。

修复：在 readPart 解码后（或 UnmarshalJSON 内）统一校验数值范围与一致性（Offset&gt;=0、Size&gt;0、0&lt;=Completed&lt;=Size、Offset+Size&lt;=b.Total、N 与文件名一致），不满足时忽略或删除该状态文件并继续，而非直接采用。

- 证据：server/download.go L404–404 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	if err := json.NewDecoder\(partFile\).Decode\(&amp;part\); err \!= nil {
- 证据：server/download.go L82–94 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：func \(p \*blobDownloadPart\) UnmarshalJSON\(b \[\]byte\) error { 	var j jsonBlobDownloadPart 	if err := json.Unmarshal\(b, &amp;j\); err \!= nil { 		return err 	} 	\*p = blobDownloadPart{ 		N:      j.N, 		Offset: j.Offset, 		Size:   j.Size, 	} 	p.Completed.Store\(j.Completed\) 	return nil }
- 证据：server/download.go L126–126 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：	partFilePaths, err := filepath.Glob\(b.Name + &quot;-partial-\*&quot;\)
- 证据：server/download.go L139–141 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：		b.Total += part.Size 		b.Completed.Add\(part.Completed.Load\(\)\) 		b.Parts = append\(b.Parts, part\)
- 证据：server/download.go L220–221 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用： 	\_ = file.Truncate\(b.Total\)
- 证据：server/download.go L280–280 ；产物 d4547985-73f0-4f8a-8a04-c6e6aa1698db；引用：				w := io.NewOffsetWriter\(file, part.StartsAt\(\)\)

复核 v2（MODEL，INCONCLUSIVE）：已逐行复核原始代码：U0014 第404行 json.Unmarshal 把 &lt;name&gt;-partial-\* 文件内容直接解出 Offset/Size/Completed，U0001 第82-94行的 UnmarshalJSON 与 U0008 第133-142行的循环均无任何范围或一致性校验；解出的值随后经 StartsAt\(\)（U0001 第108-109行 = Offset+Completed）、b.Total 求和进入 run 的 file.Truncate\(b.Total\)（U0001 第221行）与 io.NewOffsetWriter\(file, part.StartsAt\(\)\)（U0001 第280行）。因此在 readPart 边界上，‘未校验的反序列化状态直接影响偏移/长度/截断’这一组件级缺陷在代码中是成立的，且不存在能强制该性质的守卫。但触发该缺陷要求这些 &lt;name&gt;-partial-\* 状态文件的内容本身是可控/被篡改的，而它们由本机下载流程自身通过 writePart 写出、位于模型 blobs 目录，属于服务端管理的文件；攻击者能写入或替换该目录下 JSON 这一额外能力在本组件输入边界内无任何证据，属于 UNKNOWN 的额外前提，故不能升级为 VALIDATED。

反证：检查了是否存在范围校验或拒绝分支：readPart（U0014 第398-409行、U0001 第396-397行）在 decode 后仅设置 part.blobDownload=b 即返回，无校验；UnmarshalJSON（U0001 第82-94行）只做类型转换；Prepare（U0008 第125-176行）对已存在的分片直接累加 Size/Completed 并 append，无一致性检查。文件路径由 U0008 第126行的 filepath.Glob\(b.Name+&quot;-partial-\*&quot;\) 生成，受 b.Name 约束，但内容并无来源验证。

待补信息：1\) 是否存在攻击者能在模型 blobs 目录写入或替换 &lt;name&gt;-partial-\* JSON 文件的能力（本地写权限、共享/挂载目录、先前被篡改的中断状态、并发进程）；2\) 上层是否有在调用 Prepare 前清理或信任这些状态文件的逻辑；3\) 这些值是否有其它未在此快照中出现的校验点。在缺少这些证据前，无法判定攻击者对该状态数据有控制权。

## 关键逻辑与人工修订

- u\_12b3431c0431f7e754d3ce2f3e153495 · AUTHENTICATION · v1（MODEL）：该处通过浅拷贝 newOpts 携带注册表认证配置发起元数据请求，是本单元内唯一与认证凭据传递相关的操作点；其安全性取决于上层 opts.Token 的来源与重定向策略（见对应 finding），此处仅作认证逻辑标注，不单独判定为漏洞。
  - 原文：server/download.go L250-L250；			resp, err := makeRequestWithRetry\(ctx, http.MethodGet, requestURL, nil, nil, newOpts\)
- u\_5db702eb8ba6c7f2a3dfb0f0838d7e4f · AUTHENTICATION · v1（MODEL）：注册表请求通过 registryOptions 携带凭据并与重定向策略绑定时，CheckRedirect 只允许与原始请求同主机名的跳转（req.URL.Hostname\(\)==requestURL.Hostname\(\)，第240-242行），异源重定向以 http.ErrUseLastResponse 终止（第247行），并对 via 长度设限（第235-237行），因此跟随重定向时不会自动把凭据转发到其它主机；此为现有信任边界控制，非缺陷标注。
  - 原文：server/download.go L234-L242；			newOpts.CheckRedirect = func\(req \*http.Request, via \[\]\*http.Request\) error { 				if len\(via\) &gt; 10 { 					return errors.New\(&quot;maximum redirects exceeded \(10\) for directURL&quot;\) 				}  				// if the hostname is the same, allow the redirect 				if req.URL.Hostname\(\) == requestURL.Hostname\(\) { 					return nil 				}
  - 原文：server/download.go L244-L248；				// stop at the first redirect that is not 				// the same hostname as the original 				// request. 				return http.ErrUseLastResponse 			}

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
  "audit_coverage_gap": "共 19 个可读单元，完成 5 个单元的语义审计；其余未审计",
  "audited_unit_count": 5,
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
  "finding_count": 9,
  "function_count": 18,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "COMPLETED",
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
    "target_sha256": "e316cdcaa567cccf22240d0900bc223b488431137330ea2cdc42a2f7fe1cfa48",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 148,
    "cost_cny": null,
    "measured_tokens": 893186,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "d4547985-73f0-4f8a-8a04-c6e6aa1698db",
  "reviewed_finding_count": 9,
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
      "finished_at": "2026-09-11T07:45:26.873Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:45:26.859Z",
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

任务错误：智能体响应再次未通过校验：智能体结果结构无效：missing field \`audited\_unit\_ids\`

## 证据产物

- aegis-report-4b5d2ae3-1313-41e0-9006-d9afd4be1010.html；ID：c48938da-f5df-431b-b3a6-85c51a07535f；SHA-256：5b83c5a3ce7d7d4c86ebca0f9d78496f7cc3a43123091a04aa776713ea736123
- aegis-report-4b5d2ae3-1313-41e0-9006-d9afd4be1010.json；ID：5e752d3d-575f-4af1-89cf-3aa9b7c9a07c；SHA-256：dc5cd719fbe5edb0e73fdbb4bd267afc678b3c63c2c5ef5b43cc3f2abfe9c32f
- agent-AUDITOR-22e906a4-0f65-4a4f-aa8b-1783b3eaf93b.json；ID：1b7586ac-f72e-4e8a-a5d9-0aad303abbaf；SHA-256：2c9f45a5f560ca6bb14e3fe08e2869062a1e2c5ff7bab1d44d9da97b6b2b2975
- agent-AUDITOR-299e23f9-06f4-4922-8a33-472670ca5cb5.json；ID：cf2ceec9-7783-40ca-a918-0479a3200f39；SHA-256：55578dbd9cefba9dc75c09091ed58dc2861103e9d084f5a5d742b3a40816a8e6
- agent-AUDITOR-40d11cfd-489f-48e3-8edc-230d1e1f685e.json；ID：bb023688-714f-47d2-9da1-c3ea3b5d5fcf；SHA-256：e72f02ebc6842992ffbb07c3bf88d79614a3656f21afd075110c5f1211590130
- agent-AUDITOR-90ef5ccc-da71-4d78-abea-1f14691b4efe.json；ID：63795541-8d0a-44c7-8bb2-76cf65d38168；SHA-256：0bfdf987f1cf5e8a12c30032b718a0b266077946163e0f6e5fa300c1318db473
- agent-AUDITOR-d73cfd7e-e52b-4c88-87cc-67c1594f01c7.json；ID：b501b41e-bf93-4ad9-8e04-2ac27a6c87ec；SHA-256：5d0848363fffcc76995e1b7b0daefcdd08b2759b71a0d81cb31a3f5eca2fbb94
- agent-PLANNER-f266a03b-d41d-4396-9392-ce00e624ca60.json；ID：1876b442-fc35-4426-851c-e5dbdeeaa9f1；SHA-256：55dd1ef628488c885a14cf69fdd09cc3f9566bf31c9b2741fbe46249af3d6515
- agent-REVIEWER-3b89a7db-ce8b-47e7-9cf3-ef85d0428bbb.json；ID：780883e4-3e92-41b3-92d5-c6fb2d5ae334；SHA-256：c07ebdf7316cf3252865cbe37fbf2c4958f88dab6446a8ae7baa9b64965553ce
- agent-REVIEWER-3dd28822-17d0-478c-a8f0-6547cbe15a6d.json；ID：e11e42a6-2509-4c65-bdce-e97976256a14；SHA-256：f973d63c5d289dc3203cab431b85ecea7f46c95c2e2059570ebdee1b3f84b4a4
- agent-REVIEWER-703df022-ae04-4b71-b7eb-baf84247e7cc.json；ID：e43d7395-9e47-4d01-911d-afc337e97477；SHA-256：891b9ac4de7b196bb6972cfc58d7c6381e66030f467d738f9982c5c6f5838af1
- agent-REVIEWER-7422648e-cc2f-4e17-b048-7de633eb6553.json；ID：42193f92-11cf-4f41-ab2e-ae25d9183bde；SHA-256：3600393bf34e2dbc34d7fbc278ae69b5b215d0559a40029be80ea46796aa547b
- agent-REVIEWER-752cd7e7-553a-4da1-81c7-7973dcc86c83.json；ID：2af30277-9979-4b43-a7fc-51d322987921；SHA-256：96986589ad77fdbde350df1190f60714e552162d63be9235e74c3727abf23739
- agent-REVIEWER-81e0dda9-399e-48af-a81c-a9cb804a8b36.json；ID：864c7eed-64a5-4e3c-b7b3-9b75b486afd0；SHA-256：e6c3a8fa7d810aa7374600f79d18e5cc7f8b06c2750c822428ee7bb09b0ead5f
- agent-REVIEWER-8e54b2a0-2637-42d8-8f54-dffa2ea41eda.json；ID：57badb7b-bb69-4b17-ae1f-fe0ba01d1f9a；SHA-256：98342fb65b55a93b184df066e859e3f6026c07f0966ced33975b52c5d511d6b0
- agent-REVIEWER-94c979df-28db-441c-ac96-3317369b0e21.json；ID：770bcc61-b9d1-412f-a8ad-582a65a489cb；SHA-256：83e635ef8b4e705f5156b876cbb1884d12c068d9b15f54bf8701f46940961d67
- agent-REVIEWER-c75509b1-90b5-484f-9c88-ce3ad6eb3671.json；ID：fb623c34-6cce-4736-ae48-c43855abfe65；SHA-256：f427535b62d417e1bbb5dd9f6c1ee42f2197cc3000fdbd1c7c6e8f9fd2621f49
- analysis-result.json；ID：d4547985-73f0-4f8a-8a04-c6e6aa1698db；SHA-256：87bcc66d17527b310f258ab4c1200a56bccab203ee29fd86085a279b72fc1d57
- model-request-006bc29b-15fe-460e-a896-802dc654d1fd.json；ID：68749ddd-c642-4e59-b813-0b7d5ec3cb0f；SHA-256：8e509d77308046b02074737f2f1da4f8df36771c04760555f8c4d78465ae6a90
- model-request-01982837-9898-43ac-87c2-287650390167.json；ID：241d65e8-2758-46f9-ba7b-a4da363fd0e8；SHA-256：70b634299eb226bd309a38ef8524ccbfef6e2aabe127359a30863cf272501fd1
- model-request-0326c20f-dc83-4225-a334-bc0601f2bb67.json；ID：27b45fdb-38d8-4961-8060-989d330eaf96；SHA-256：698098f3fd5c89d2261e7457bee6f661b00a98217c5745c8afce3c3ca4be95e8
- model-request-06946065-924e-49a6-a35a-091738a9040c.json；ID：02cd8ef3-6828-4bfc-8495-9b2425caeefd；SHA-256：090e5dfc55f5e049875844f66af1489136d9fed58c997dc9ea23d7665d8b0cae
- model-request-06e509da-d43a-4894-be38-e727c3ee0654.json；ID：7da880aa-6b03-4ec0-a80e-dfa2b5afbed9；SHA-256：7e944bcce718a60cfa70e90228c39b8828143399fe88f7761503bccba1feff12
- model-request-0a56caa3-6b56-4df6-9113-bc6ff5623094.json；ID：72f74de1-74bd-4181-9458-f022ca07d799；SHA-256：04c5d61bdd1170d88d11b389e4f6241a485e2a204cac0ee2c4d030e9588e730c
- model-request-0abb061e-58ed-4055-a0d5-8f3b24b7f8cc.json；ID：225e2cdd-00ed-4f56-99aa-6c44e5d1efe7；SHA-256：dffa804d63c09a542c2ea629338ca86eab6904de0aa7f6afa43165b3f17c037b
- model-request-0fac0144-5d4d-482a-9c61-ef3c7e373d64.json；ID：c19f1755-c653-4e4a-b99b-725be4e9784d；SHA-256：10b1ca5afd6bc89b8e151be8cd65f289480b0fcf37e26d32b0ba5c51437f57b2
- model-request-13ea5071-e6f6-4b8d-b032-f401c053939e.json；ID：0bd47917-10ca-463b-bba7-a2d7b18b3275；SHA-256：b160f5af9827d0ce81e53d09e022bee5b1a64e48767ba5963a2ab1a01d07b8c9
- model-request-14c3cda4-1117-4403-93f0-e63029ddd74f.json；ID：4fa658de-f168-4434-9449-de7b45cce3d3；SHA-256：445c42936f51dee9063ded2998b18e4ab4aa72a9bf10b3d85dfb942d5d9486ca
- model-request-15e16a45-362e-4cc9-9aca-7a3576789e18.json；ID：38ea35d8-1d6e-4909-bfa4-04bc9bbb6041；SHA-256：8e16ab9a48808564c21282f0d81df3bffc704405860992e116675e6ff2530121
- model-request-173ffe98-7f42-4d6f-bf6e-73113389a3bd.json；ID：74bf466f-40dd-4b2b-b0f0-fc9a1dcc4ae5；SHA-256：944bd5b44f1d47f55b20c6caf8ac7c50402fe4971d78b2cc6cdb9da0c93c6fc5
- model-request-177ef8a0-0eae-4b20-8594-ea567ae42ebf.json；ID：7cf3fb84-6a9f-4e97-aeef-b23e671ec0ee；SHA-256：8d2a8fb7aca33d68b19aa24d05c47625c826ffe9ef21d402083958c76c3e6a79
- model-request-1a57f29f-6034-407f-890c-fd6c145aaf8c.json；ID：84f97e13-8f52-4790-980e-b39cd153b612；SHA-256：6628eeb2105263afadc5354cc34d605e092a045755d99e88980d9cd249da9249
- model-request-1afc087c-12ba-4d4b-97a9-e99f258c9596.json；ID：6f133de8-0581-4f89-a3ad-9e65cc9b06b1；SHA-256：d652e885967eb377c7923a551a699e5ee94742c43f42b288761921ed35056bf7
- model-request-1c7dce6a-7f8e-4491-bb13-86c83c40ffa8.json；ID：19a94aa6-f67c-4639-8ab0-0e69acaa942f；SHA-256：11d44198a7c463e2185cdd8e940cf898585b60585f8d422b348e3567f2537695
- model-request-1d8562e3-70be-44b7-9631-6c7d643b2425.json；ID：9dc0217f-156d-4717-8001-826cffce7c67；SHA-256：ac50f8f0b9386d0394b23f785e2b2b3fdfda815d48e670c70f539e05a2b423a4
- model-request-1dabe0fe-51cf-4148-96e3-3c645e9717cf.json；ID：570c530a-c566-428e-a301-6db671a818ab；SHA-256：76811505dc431c0d38080fdbe77eead13bec4e7bb39e9ae8d37ca7ea41841d93
- model-request-202863bd-51aa-4918-bf1d-db47132755d1.json；ID：2377f630-a132-4ae7-904d-435840191349；SHA-256：27794fd0c87827236092ff32317c749db1fa1fb2eb276f537a83f1666897ed0f
- model-request-20b5a9d2-7e00-470e-8e84-65859597c594.json；ID：60408f7a-9202-4801-8e30-3199817cfd83；SHA-256：82b7616d2af5bf2f997168c4898411dd58b81217cd00e3a4c28b04fb04a97457
- model-request-222e6d21-401f-4eec-ab6d-001ffcb99c7b.json；ID：768d7651-3e7e-488e-9693-3c18cc810b4c；SHA-256：e68702fae2f8b8a2f75365e099d6ecb763cce38217aa2ff0226b14c79f0e0d7b
- model-request-254f78a2-c1c4-41e5-b694-c2a76def227f.json；ID：463ba156-3127-4827-9141-9d566a6a0b2b；SHA-256：0b08fa411be88fa0b23ee6f0f2f5bbeed02f5a98586f3120540bb4d5bf2ce015
- model-request-25e31947-106c-43d6-9baf-c0a5ae085872.json；ID：180523bd-cbce-454f-b9e3-e9c3b4485ca4；SHA-256：32efcff80d1409d2e3fdf38d612fded58876bb7cbc978df45e9415c49457a93e
- model-request-26e64bb4-2ad3-4993-85e1-e6c2d43a77f0.json；ID：412ae30c-1a7c-44f5-abc7-b1fd5636f962；SHA-256：3bc0cba1e0797c6c878fbb1b709fc8d2356a984ff770a52ec086c9555dd0e8b6
- model-request-277c02aa-bb9b-4739-9639-4e7efb34d767.json；ID：134213a6-edc3-4ef2-8702-0968bc983ed7；SHA-256：8d6a2c8a4c40786c669f08bb34a4aae0b060d8537c464bbdf56a38c889369e1f
- model-request-284c3997-de85-448b-b91c-4ca2cc2e609a.json；ID：f4472746-6590-4702-ad3d-af934f9850cd；SHA-256：608893f4efc1ff4b6daaeb3670133a04e972735d23b9c7ebe43ba033fa3df752
- model-request-28aee3c2-07bf-467d-9511-38fd51526688.json；ID：913dfe3c-2bde-4528-a661-4dd73229b4a0；SHA-256：c3ddee4f3610ae836b253edf546a9d96237fe313da19b9602ffccc1460b16033
- model-request-28e92930-b890-4b03-89fe-17f4acca21a4.json；ID：970cefe6-7f81-4560-995f-cb8a3c955084；SHA-256：edfd58c06ed51628b2647ce214eeb6aeb9587a89d68cd06f7dada899d5efddc8
- model-request-28fd45b0-6c77-4fcb-9488-4090105bb7af.json；ID：64606a43-eec4-4089-bff1-f80ec88cc0e2；SHA-256：f79d9dc1eb0f25e6e4ce82c43fdf6629f33804ea5cba9087e6224892eca7df3f
- model-request-2b8d8ff2-161c-43ca-b939-524b28005a31.json；ID：936ac8eb-217b-44ce-af21-75d4ef5a3058；SHA-256：d708c3e753e4a72d5418e5f83cbbfc10ae121cca1a6bc98bc979dc8bb09fce52
- model-request-2be71da2-5c2d-435d-add1-29c614656eee.json；ID：0b4660c8-f28e-4506-ace9-70de8c7db9d9；SHA-256：8fd5f72ce4cc3e023233f668b4186e5f30baf42ee2cc4e426ad8673fbe1e95d8
- model-request-2d8b612e-8628-40b4-9f7d-3b787ad2f759.json；ID：6a9c7fef-4fed-4393-a71b-e7b1626f07e8；SHA-256：0255404f116d644f73b7826dbb858bd5f6494fb007c20cbf8c3cc8f969bfa792
- model-request-2e2f7f1a-f40f-475e-a68e-5d3c566bbf5e.json；ID：1e7cc172-ff17-4a09-ad26-fcfa97e48cf8；SHA-256：030fe548cd3ec7b4bdb44760359ccd709388f18cf1e17005963a7965699f3576
- model-request-2e683244-216d-446f-9adf-56b1ba311931.json；ID：986c7b3b-9aac-4454-9755-e6976dc34847；SHA-256：72219ce7c98dffea493b6347a23e0532cf95a910e7e9054bcf47e7baf9c279cf
- model-request-30ca8d00-a56e-4e03-a72e-0b4cf7d3490c.json；ID：3dc1dcfa-4b92-451b-9764-95298afac0f5；SHA-256：fc8b2561dd22d1d3d1ee756c8c8018dd9e70c9e82c63bfebb86318df59050207
- model-request-339288e6-bed8-4ee2-ac2f-3d937ca59d91.json；ID：26c2954f-8bb4-4f6a-acff-d00d21325b8d；SHA-256：81256ff910bafa5b91da8e295d1cac0ba9ae3c0fc079272372003a48758f0792
- model-request-3483dd0f-b619-4263-ab7b-c1ff04a418ca.json；ID：98d9d809-b3ec-469e-8b73-a246fc98e1a4；SHA-256：c3ed4129b62f3461f22dfd6f2c6d685d630f25f7264d7a85cbd49d6440d02f23
- model-request-371ef368-dac6-4997-a615-3b2c9f5cb2cd.json；ID：805795ec-0b0d-4711-830b-799b8457aabf；SHA-256：bb4f64f7aa70f9bc494baab315d4ca0d00381781c2f97d1509b2b9d663cb6f99
- model-request-3879508c-6373-4ab4-bc8a-8711ad2426de.json；ID：e8d03ee2-6f0b-4e5c-b1c1-da1af5066c22；SHA-256：a367f1f94bf219caf3f74fc1c8061cb68b9f05d877b8983f26dccfb0266c6cb3
- model-request-3b471867-023f-476d-bd9a-d54f1069617f.json；ID：f9a63fe1-bdaa-436e-9b76-ae8076fb74e0；SHA-256：0e4f66420b9f033bffb28706658866dd2eaa4d8f686e762ef1b6cf069509f517
- model-request-3bbf80a4-9b70-4fa4-92b9-fd34b566d7e6.json；ID：d460264d-ad33-4624-a533-653d1ec14cc6；SHA-256：a951170f605dc7171c5f06064c80e954599be836b90ea2c7f4eb218096817d58
- model-request-3d3781b9-0a42-447c-ab60-3b8cd81ef491.json；ID：fc112613-4c6a-4088-9a1d-ef834d3f796e；SHA-256：ed84cbb76104e39702c3e47d5a8a9fbb0b0b9433068a8aec45cd8eb0ef5b48bd
- model-request-3ef9dcb7-34bf-480f-8057-c64212014a7e.json；ID：a53c4eff-3e41-45aa-8cec-a9830835af38；SHA-256：f9e46cc0d7700e423e4fab6276a60be2acb173dbf19f645dab2a4aa0e8d4ef08
- model-request-41a54df7-e599-4c03-a69b-ef97e3058624.json；ID：c9ebecbd-c01a-4289-9b6b-f77bd9d848fd；SHA-256：5120d72914e96d63079a0981500a247119d86dd221615904b0c63f1fc3108ce9
- model-request-43d6fa57-48d5-45f4-9616-102567267f34.json；ID：9ae45274-0a05-47fd-8ff2-19a698f67ac5；SHA-256：bf72772a489cddafc51d8e55287dcaf879fdeb4e6b39112096b6fe2d74fc70f9
- model-request-46e5ccb9-0150-4553-9fc2-a27695b1b44c.json；ID：a4beb844-2dfe-498a-8a32-f4146136ee80；SHA-256：dafdfa6e88c79e48ab3cd1bf3da108906c91f0d4b61446d097c31d9adff6e31f
- model-request-4d9fa8b9-505e-467f-b28f-d438c79e673e.json；ID：098f6b77-237a-48d4-aff9-494c529cc44e；SHA-256：3d34d08130969086b6bd8963cd42c6fdd22c6b9df3e73ba247c87f49fb3744d0
- model-request-4f54235e-599a-41af-81d1-4701795ae513.json；ID：40db0f91-6854-4a35-8be7-4c0f91563652；SHA-256：3b40a90172cb05e58079bc6e206aa87039fb313c5fb284737d54681be8379335
- model-request-4f8db551-37c0-46e4-8497-83658c18fd72.json；ID：33a403b6-0344-42c7-ba0c-386d6ff69760；SHA-256：f13b0475e8c8231ad4475866699d82b794498846966c52584f67c3df194bb94f
- model-request-4fed9fe1-342d-47bc-8171-01050ec77462.json；ID：4b33caad-c901-4164-9d78-ac8e646fd117；SHA-256：67d269d69086bc5ff06be8614683656d232c2c8815a0d7ff2d25a71a95a2419b
- model-request-4ff041e7-3a8a-4e58-a84a-5643502b4790.json；ID：a9cd97d9-dbb6-49cb-ab81-80e62fa5ee91；SHA-256：f34570a4edfe406fbd37abe988cf0a4fb3f7354f011981f533c7cfbdcc7bf06c
- model-request-533bbf1c-8b8c-43dd-8a7e-db8d049f767a.json；ID：6f161155-f40f-4957-ba14-e611d1a63d01；SHA-256：1450a402c3a6dd8e43bd3ce81de71e6c036262a0a8815c211e776be8f9253034
- model-request-592a8a33-994a-4f01-9701-af37e256e0fb.json；ID：b4073ba5-bf7d-4f9f-9c1d-d242703a4117；SHA-256：8ca3cf78d4a74859f7de6f3f47f744e724ebdc95857d8e063a196633db4647d6
- model-request-5b03ac83-d017-4c42-8f6c-945b639a8e89.json；ID：0fb4e919-42e7-4368-b5a8-680abe09a498；SHA-256：a781cb6292fd09522171828c28e564b38946d58af75eb198fbc786295d33cd59
- model-request-5b382735-4e71-45da-80a5-2e8b01289de3.json；ID：a234d267-0287-4cd1-97a0-6b20741622eb；SHA-256：6e998c8a0f5187a93e4b3a5a62d04cf67108e01a1a921b74aef25fd82724814a
- model-request-5b389579-f69d-45f7-80b6-2fe8ff6e6076.json；ID：28bf9fe3-e59d-4580-acd1-d37b1ec7ba7a；SHA-256：ae120b68d00fc6a7fcea0696319659307bfe2463a6bec53ca0f6020e9be22915
- model-request-5c6f4887-5abc-43e9-9809-e97a0f1a444d.json；ID：9b6d1413-e40b-48b2-b435-cbc10ceeb694；SHA-256：323b7c61102efe0a16765f92631c119ac0c8aa1a3555b1c9c149cd8cb8eb292a
- model-request-5d648c68-a5ea-4109-9a5f-94fc8a93460b.json；ID：9486d76e-3335-4386-a882-0e54ada27b99；SHA-256：d1141e88b1d725158ddefc17dc35e8b68cca23cae7214e15fa6936294d231878
- model-request-5f2b4f8e-138b-45a4-a0ae-cb7a48d7e7af.json；ID：17fa4421-f100-49bd-8801-7f1b4361d46f；SHA-256：24d6c7be88214f461ede149bf8a6ae7164ed4a526e5e2fc3f16e2b38bdd54a58
- model-request-5fa5481e-95a3-4c86-b1e6-006a9c6179e1.json；ID：c799d071-4b6f-448f-aed0-0702884ee340；SHA-256：a698260e2547976752110c53a82801d3a9810bdc90b93d4a70b47ea6d0213f60
- model-request-6098f52c-bacc-4de0-b625-36902c23ea24.json；ID：de1a8aa5-8283-41d0-9c80-90d4f747716f；SHA-256：2b677103bf4dc0a5782b8922b7cd9dd3d50cc3c294f77729b10978e7993d3bbe
- model-request-63e9cc2d-d1a3-4526-a80e-c0732d366fd8.json；ID：c63240b8-a5d0-4b26-ac43-584cc55f2d6d；SHA-256：2e677a055afbd24dc3fd6cb456e42377ff305b0ea9d8407c8bce0788680d5d3b
- model-request-65fb84b2-2cbc-4e53-a706-7f4761f9fd67.json；ID：d4c9222c-1e94-447c-8d0e-9fa3a1550f59；SHA-256：62358a6ac14c0d4dfa299ac0bbdf0e95f58fd27498414008f99732574e40f293
- model-request-67638a83-b5c8-48d4-8292-ec0c261b446a.json；ID：42d2f110-37f4-4c97-b801-d6c7977f01e7；SHA-256：f15126182b18b80903f3c8f14a4d3f5533f68dec05a1732e7691c295d6b83799
- model-request-69aad420-e103-4eae-97e9-7fe34298489b.json；ID：748b5980-410c-4093-ad18-9f5c5f95bf6e；SHA-256：d1c2dba09b6ebf2ee859b6e87bf3e8ef9a60f4be1f4c0dbec55750a76cf2b16f
- model-request-7004ffaa-c4e8-4929-bbe9-6beae3f53be9.json；ID：ee067b57-d444-4716-bfb7-38a543320986；SHA-256：cba8e69ee8d2cc2ea7e3ea90665545ff83c905b7c197a27241f6ae4b12c4954f
- model-request-703df261-04c9-4602-9c12-a88371c28a6a.json；ID：e3f1c298-6327-406d-968e-a261c2fa70aa；SHA-256：ea80d6ae9fa2f17e56a35214c1d16da4104ca2be6a2a16f87712b6ac9cc3d215
- model-request-709f41b9-4d66-4f90-a5a4-35f334cad8a9.json；ID：cbbc2fec-acb3-43ce-82e4-0082b8e27d3f；SHA-256：10e37985f1c5b1e860f55b95788bbbb31e6af139d052a4f3ecce7dcdc7efa7b7
- model-request-72144d13-9315-4ec3-a3ce-ac8832f4d945.json；ID：9c1bede2-7ceb-4395-9adb-dbe1359157ca；SHA-256：49e6102a0f9aeaae3109ebaa59a936b5365bd0c0339f4951653e84f12b25a19d
- model-request-76d312df-56bf-42f6-a372-079bc9a34173.json；ID：a0d48312-4c92-47f2-b2bf-2c1943584d8f；SHA-256：6e3f38b0c4d82c433c33958bd2900f9fa7845ec1c2cb08d27ab2d087a034a9dd
- model-request-78f8036c-22cb-47c6-8080-a53e52ea3495.json；ID：418ee8d5-1b86-4d68-ae73-fad312a17ee7；SHA-256：4ef52c7730eae2559e0fbb54e2b473a6ec37994fb5bad99ef1ab7b28992152d9
- model-request-7a7a0809-bfa0-439c-b3df-68b00bc62844.json；ID：4a5b5720-760d-43e9-92fe-1e35bdb3ded6；SHA-256：5f4c7d7c301f907c585f6c700992c26df2bed6015003e68a13d17fee47aa8760
- model-request-7c017f7b-3335-4505-924b-b556a5422aba.json；ID：8744f63d-3bfe-47b5-8099-3dffb1941cf5；SHA-256：d8176cfb6620300067e18f59b134740637d50cbcdf1531d180707e467859aa4a
- model-request-7dcc8d32-d9ad-4771-9338-b6feed85b3f2.json；ID：aec889a1-a1e4-4759-a1a6-42250ccd4bbb；SHA-256：af52f2f6556d829df68e10736067a494493308845f9b37c2ca38d3651f838d71
- model-request-7f306cae-7c86-4091-a064-8e830ef43900.json；ID：637ee33e-15c1-4399-ab53-be5299bc7284；SHA-256：18b73339b86b549f0a67706afc020c1bbd6f48da9cfa858b862bb4f683dfa8c7
- model-request-7ffc2a7f-2507-4ea2-be0a-72f473b60dfd.json；ID：9204ba58-de5a-497b-9e8b-9bf59c890a7f；SHA-256：a4663d54f255eb40eeb97e4b029a3b6986323c1525a9a260c06b66bd7c29f511
- model-request-85beb43d-eb19-464d-a086-8a7e83938615.json；ID：8787e29b-5b59-4ac9-9fae-164ee03bb282；SHA-256：bf29f2f6af794b00e01569043bea6da1b395af2e3878b47d8ef8b5552578d55c
- model-request-87450174-b918-4360-9c8f-0176d500af7f.json；ID：397eeae7-8f30-45eb-8911-9fe870b3ce20；SHA-256：76fa9de2018b0bc254663429bb3b1eb08dec0ba61547911b1ac602f0ece5188d
- model-request-87f19f83-9450-4d7d-be65-625ff6742f59.json；ID：22d9679f-68a2-481b-889a-12a8bc90bdc8；SHA-256：e58e76beda2b901efe7141fae9d66f6ea073c0c02ca5b41c59333d95ff5efae3
- model-request-8913cd0a-5229-41a3-9ced-80dab452faba.json；ID：132e37e5-aef6-4900-9e26-055ef8ce816b；SHA-256：eb43afbb0b98155dd3df222534cbfb2977456ad972f86e3ae2f207cf459090e7
- model-request-8a759a45-c245-436a-9914-381f7389aebc.json；ID：d1d45ac3-762a-4103-bc0d-503cb91fd51c；SHA-256：d92bfabb06c31550ec182ab78241a1f7ebebfb0fd8fb9d08f9c9bc981371ce3f
- model-request-8a8bf667-6245-4365-9374-36070a738079.json；ID：44eb48af-f165-4757-b062-409f1cb58fc4；SHA-256：052d03bac4b69e95e16d3f15d761b40c7147f9d0b788b2b6ef84cbf0c963bdfb
- model-request-8b0616ec-4fe7-4fe7-84bf-060050bcbf4e.json；ID：6af95351-12ba-4b43-8423-e3fe16fad11f；SHA-256：9e41b55e52c56f1bcfe40725415b417542360fba5c90dc73ab98470d092e354d
- model-request-8c610d96-a175-4802-91dd-8cdf7b431630.json；ID：16a9b4a6-6e68-41e0-b5ed-61e5ec4208a7；SHA-256：d6c24e31e5b709880e16607f827a1ddd0612e3735b40ca6382e1a19de84d3981
- model-request-8c76084e-3535-448a-8f21-6396d43acfae.json；ID：12833453-2634-4b51-9703-808135e8b817；SHA-256：075f7f209f60a02a159adf635025393926ca3e59c98f6da87623f6a1e26cea74
- model-request-8d9ee8aa-4759-4be9-a82a-196f41e3ac28.json；ID：60ee0dc5-809f-4560-aa68-1aa3a2139b34；SHA-256：3eb28c9591cf82cf30873250b066601365e77d9315b258ddf7860f6b467f282c
- model-request-8e0095fc-c35d-45fb-a5c5-5ad89f5d6805.json；ID：872e18b3-679c-4d5c-8295-4b3b9e4fbfbc；SHA-256：26d59e11abc9c5971f92474002cc6d08e7ae5dda491f3b26c29ef2bdfac15f3d
- model-request-9062fb89-b1a6-4153-807b-054a7ed4b3d4.json；ID：55071acc-076a-434e-ab6e-fb97322f3576；SHA-256：5022c04e3bd11c4a9031ec2b7f8e485147686859792489ad84bf7a7bb0cfcab3
- model-request-9b19255d-2f49-41d6-92b3-c4d748aba1bc.json；ID：12f39e39-8dc0-486b-911c-cc13553863a3；SHA-256：6deece8d441ba6ffd20eff2145f082eebcfa9a1c78beee3ba91da2288f75ae83
- model-request-9b2b47e7-5f43-403a-a7cf-dfe7a4385f9e.json；ID：2745ef0a-70a2-4a7f-87aa-7c2bd5aef633；SHA-256：c2bce6ef7678e871f6a2bc4097179d33ea19252aad41ee1dbc1c37d698251dd4
- model-request-a002914c-3c02-4bcd-bd3f-cbda835f7e0a.json；ID：0dba6540-7ef5-49c4-b7ba-7cb5b1e3f2ac；SHA-256：ea2a9fab102d69717594b485377fd055065a302fb7e60a3dc966684b36df621b
- model-request-a290cf32-8223-4aa4-99cb-58488f382850.json；ID：b6d42de5-9d02-42e5-8476-7025a5744d31；SHA-256：30f687c418ab111d6607bee1a76979dce21a240458f5ee66b8f4c311ab5f6aae
- model-request-a4a67c27-2229-4f81-a664-a3d0640638ac.json；ID：682d3896-5630-4821-92c0-4fe20c497c3b；SHA-256：facca1ae25b59ddd9947acdaab71710ed22b1e4ce3286e44a9508ad9ccb879ab
- model-request-a7fa4edc-cdf0-4ed4-a05d-bc9b887d7329.json；ID：4e878423-bf04-4ad4-a634-d9ed666038ab；SHA-256：616827d071825e698bbd364f6e7388c02d6506acaff6bbf4ba054ae82ba7fcf5
- model-request-ab1f5d0d-3c16-4f68-8891-8f4e987864f1.json；ID：601fa1e5-271a-430f-96f5-9ae718823714；SHA-256：830cfe91c4230da28f4adfd5557677108649c10a09809a42214bc669f701ea1f
- model-request-ade346c1-2f08-4f6e-8d9a-2b7ead8f4a5c.json；ID：bca999c4-54e5-44f7-9b3c-29a6ff9c1166；SHA-256：51c8666f9d01458e9d828bfd6ce0d55170726ff0459d53c8702a7e63a42b4252
- model-request-b2026878-ae5f-415a-ae9c-038f545387f1.json；ID：b6d2140c-6592-4fb7-aa26-f3d0130c36a0；SHA-256：04d0d64bc291be45332ff8b55d2a918169fa931d8ff2bf41b20c335c1923d06a
- model-request-b2cb9737-b8f3-4b99-acea-9de663c93597.json；ID：0790457e-fcac-46bf-bad3-ccf91a316de8；SHA-256：b3c2b9fd80419c3d924251ae6ed9c57239a9712aea4fba64ace70564b61831a7
- model-request-b81af0ad-96e7-4d82-8d18-e4220f39f82b.json；ID：da9ff54c-764b-4465-bbd1-3b1e7c31484a；SHA-256：991d0c05fe0c71b2ea85900c31c715d8c429b00691f1edf01fb65d0468b6f75f
- model-request-bacb0cc8-03d4-4607-a24c-e1e8268d3b60.json；ID：e3017844-3676-4683-9afb-498639fae032；SHA-256：467520608c5412d2dd9e2324c46dba6ff262f0b4f39789d3f718a22dc4196c71
- model-request-bb35250e-c30e-4b52-b058-e72e7106f798.json；ID：f30989c2-87a8-491b-a587-88a0b10d0116；SHA-256：7d4dd8e2108fe9ac598a09d44e60b7d9c3687ce56e0039c79bf72182c2d4f1c1
- model-request-bbc6b52a-f2dc-4379-aed2-6f9e214fd6e8.json；ID：bc9ae2f1-b608-4c92-a2ac-f3082e090f7a；SHA-256：b6855d957b1f407eb51407b035a9f6c2c4697374aa17d746ed1b22df0e960e4f
- model-request-bcbd1f69-be71-4408-9163-ab771352a1b3.json；ID：f2c21f26-cf9e-4686-a131-79dd05f6dfec；SHA-256：bf9cf6fa92ec62ea5b9a11b469c696c4350cbf20d0848c3daffe65a339045fb7
- model-request-bd490054-6965-49b9-9f28-1643f55928b3.json；ID：45c6a46b-7890-4b38-8aac-84ceae9ceef2；SHA-256：df811039bf647231fa063e7bbf08a3686c765a32058470651d515e7b3943a428
- model-request-bda7dbfa-b295-4e43-91e3-0b6662ed8d3c.json；ID：12f2e606-8001-4903-9aac-a6acf5ecc227；SHA-256：578dd9d3b3b2bd8e7653ae9921d71cb06069c1e5a41c2ac1934a6a4f17637942
- model-request-bdb39f52-63e8-4aa3-af93-878dde3dbcf0.json；ID：b468923f-8191-40a9-91e7-a8143594f6d7；SHA-256：190b5fa2a9382a6af97c5dc7f491b3295f430bbfd8ca4438ad028205291549d5
- model-request-bf1f3830-431b-425b-9de2-a3aca8a14916.json；ID：53cb3340-2123-48f3-922c-11c153727e56；SHA-256：17e1cfd5b4f0ab7832db7079872352d1bfcf6dbac498859ac7e4637e08686df0
- model-request-c11e7f16-cc5e-4858-a0eb-42fa1882b8fc.json；ID：ee8af4fe-5bc5-4d6f-bb15-ccd0fcd8b974；SHA-256：9a6af2dbc1b7e60efcd834cc3b8c39b4eee382ba9b3b16115b47da4704d77135
- model-request-c29d2ee9-4098-42ed-ab08-a01176e10b50.json；ID：bbec5e79-9c27-467b-848d-72e5ce6189c4；SHA-256：8d7cad41bf885b47fa6a3da2fb712a9bc8cf1b24342b2fa7161aed9340ba1895
- model-request-c450f78f-fedd-4b5e-94df-b567190ceca2.json；ID：616b8983-6cc2-4a70-9ffb-504bef4ecf09；SHA-256：92d8de5b1cb87867479ac69c003ad1beebf8b4ac29f7083cb5d94070526dcfed
- model-request-c63c8b95-3ef7-4963-b6d5-f783010ab4da.json；ID：4d4e56be-048d-4ed3-8aaf-17f5269c51bd；SHA-256：82c3f6be2ab85937085e63b28d4ef6238df1c70cff5ead4e14455bc0387d9bb8
- model-request-c9aff710-c0f3-4f4a-97f0-663b6f4ea03f.json；ID：46784d5f-2d26-47ad-b25c-6ae2f947dd11；SHA-256：7dae01c275c85bcad6a4f49301df042aba1a07f2a542275deb87d88d89a4f60f
- model-request-ca4ecd2e-b95c-423b-b3a8-03824ff61ff8.json；ID：f05ff8e4-9fdf-42e5-8963-6aba8ee01810；SHA-256：db3695a2c028ebb30301ea4d55a52cdd05f4fd1694d620b83cdc3f3f5dc282d0
- model-request-cc95938d-f760-4429-a34c-4d5e9d26bc47.json；ID：cae72dac-b0d1-416e-ac0a-9be67186b2f9；SHA-256：54b0e8620f823cb9cd9e9081f098068f75a5986ebebd2325099b1fe7a05d27b9
- model-request-cc9a0d7b-5353-4338-be02-c4d0142a6dda.json；ID：b1591cd4-ab54-40dd-8b82-062bf7c0f7a8；SHA-256：8101c1ee4820695fd96c003e9e93eb51d2211cb34a496d758b28fb84f808577e
- model-request-cfe0995a-9878-4645-b0dc-06c3f81ece31.json；ID：43748ad3-151b-4004-acd5-e5c9f85eeeea；SHA-256：a6d400f93d34dec670d9596be31b467ef6a679b0ef0112beb8caa6fd19b73b10
- model-request-d0b6f567-9acd-43ee-8a20-9a7b1b891b8d.json；ID：7ffb4d15-c9b5-4dd6-847b-19a61fc28259；SHA-256：818831d80d4381c8d4e2f07cdb0678bab336a9f6d04d3425837ee0bf0d40e082
- model-request-d2878548-1ca8-438b-973b-5b73505f3f73.json；ID：4c4ed117-84d6-4e95-b255-f16cf8f9fadc；SHA-256：5a7de647dde63d0ca2c7a022cf0b62496e0ecb6b51120b85b3caa862227a460e
- model-request-d2d14fab-b4bc-4b17-9b4f-3774912f3279.json；ID：f0f9e608-02d8-45df-b5ef-aac27f7d5c41；SHA-256：c848dec8c1f4ef86743d51d21863bb6f902fbd3b627c64aceb2aec1387d8cb27
- model-request-d4ee3236-12ea-4485-bb6e-48d3c9d9407a.json；ID：a22afe09-dea0-4dc3-8a74-181f799712ca；SHA-256：80f8d9981d03ce434f156e89faa586245e34d0a5455b6a8b325d77e2e8c58b1d
- model-request-d65c8adf-b3ce-4a40-b524-bc37f0701395.json；ID：3da229d8-3345-4961-8ad4-d1a9f736253f；SHA-256：a9a25984d713ac75538a012a8e02ee3d9078a0d8baf25ab7fda9fc6e59b4edf9
- model-request-d66debed-73a5-4eb1-8dc9-39d407f0e321.json；ID：9fa2700f-e80f-4567-89f3-09954d0ef232；SHA-256：3011d36bedf0c3821be388a9d1b01d0fcd3a688b2597ff749faf2e2034dd421d
- model-request-d721f2e6-01d0-4c3a-88b2-256683bab233.json；ID：778a90c0-0334-4977-928f-ae8efe0f34cd；SHA-256：65ab09cb2b348a4fc04877dd17ed833fd11f045a0098c7433823ef57472917b4
- model-request-d8ac8c47-8663-4e1c-acee-22da9725dba7.json；ID：04426699-d580-402f-8476-d101e559b2d4；SHA-256：42b5fe920fd4274286070318cd9f9464785c511311db0bdfd7df7614b37758de
- model-request-de44ade6-4193-4c9b-a1e1-1e4a80ff3ddb.json；ID：76930501-a5f9-48d4-8b6d-806ae6779880；SHA-256：c26b203b6fffe07dd95c76161b1e002066e70e0232fa1b314b4aece0ed58d707
- model-request-de5593d5-d9c8-4471-be22-d71f25edb956.json；ID：5dee8c40-4d0f-4ad8-9d5e-06abcc966f11；SHA-256：bd0de7577dbc5366645ae4176e8fc008c257ee14dbabe12b148effd5ac2820a2
- model-request-e1e93812-d002-47d5-a3f7-18d9fc0cdb6f.json；ID：a77d7677-f53d-4e70-b0fe-b32d01bdb872；SHA-256：0ae2db6dcf9cd5a763a08e4bf521845e3454a1fb856109eb3a7f8e4b2637df68
- model-request-e3f28516-277f-4bc8-a3a9-2b2bdceb2639.json；ID：44837329-b20e-40d0-94e9-8e65de438dcf；SHA-256：932994518f809abfba535834746129b33ce7cfb5b9670fdc3df1d549a6377d89
- model-request-e4393d57-fb28-43a3-b68e-8b8ce7ac1a31.json；ID：5b332356-c36c-48da-b7b5-0c0620e76f3e；SHA-256：ebc7f8e0a337f3137be089b9d9df3c2bb5028a43cac982ad4ddf453bc018d347
- model-request-e513c876-8fb8-4a28-a965-027c21598001.json；ID：f02a671d-c76c-4259-b10a-340fb4a1cad2；SHA-256：127a79329731da88df541343ca36525ded5fb862e5b468d6a3b2fe1e20ad588d
- model-request-e606039b-0452-431b-afd8-7c8b541f26cd.json；ID：88bffae9-14bb-4808-ab3a-4bfd74fdee2a；SHA-256：e222de2f0723703b5f02c140a66eaead4e8bc4b0ea4ec33fe4fe34994b2dc4e1
- model-request-e619cc71-3b3b-40ff-ae02-02d1a31ee11c.json；ID：ba738ebd-5c0c-423d-ae93-52c60844fffe；SHA-256：ef5e8129e9925d97ebb11940c1f15107004af147997dbe1828b0ed2f966072b4
- model-request-eb73574e-c270-499c-a00e-1fa61340ae33.json；ID：0d3e364f-8da1-4f18-aa4e-09c70975be81；SHA-256：98486170dc3f32f28db02b8ba4724754ee63a4873afc3bb60f7440f6de2b9d83
- model-request-ed4cb944-88ca-470e-af29-125caa54ea99.json；ID：ddc1240a-7cfb-4815-8f1d-fb28ae2a5531；SHA-256：f708c5dea1685a3a5ca93fd33ac9d5d63c2ef5bdfb7ca3c277ae82189732b38e
- model-request-ee709553-4a59-4586-91e3-f3e1597298ff.json；ID：bd8ca8c9-7c08-4ba6-a578-88fda88d5d0a；SHA-256：eb4c88bcafeb6cafae656c11e5aafbd59bf969b061334fcd1e1c14288dba41a4
- model-request-ef99f3eb-53ca-43e4-881c-08d57cf19087.json；ID：ef3e8d0d-46b0-4e35-910c-ebbc53404209；SHA-256：751cffc4d6e163581cfae83c82358b7a40a3f9240a33d8718f61864a62163c07
- model-request-efd2ad86-ee69-4b96-a50a-d7c1d145fdc6.json；ID：17fec0d4-ac4b-4658-a256-82fc7d22b0d9；SHA-256：4055c2bd549dbceaec9de659a74de71800473ba757a5f8141327badd1d0654e4
- model-request-f0690944-e402-4084-96c2-d4595b7310e5.json；ID：93c9b455-bd17-469f-b402-c884a76f2f61；SHA-256：81ff1510031082d127e6daa114ccc9f2c1c8f554ae5e779e25cebd55b411c56a
- model-request-f2db7dd4-a032-48f3-b9b0-79178a85867f.json；ID：41029f8b-c0f7-479f-99ba-e95b8d9d64bd；SHA-256：c56fee5dc04fb94b232237bd9ba5fd01b43901bfb72cd45a87aa9b22abbcd1e2
- model-request-f3036c3b-959a-4557-b1e3-679fd002c84f.json；ID：58bce66c-1c82-4f1e-b5cf-c30e6359ddf2；SHA-256：39517716b7b767d9b1929d4c66d7ef2e733f5adb529f90c90ed3a4d5ddf1fe0a
- model-request-f51ffa1e-9531-4bd7-9953-f8b2d0d30ac3.json；ID：81db6059-810a-448d-a6e1-7451c9a2dce3；SHA-256：7c568f1c84aa6281705fe141068a0ac513bbb980e36b425862fed07655d1b6a9
- model-request-f6c6642e-555d-4758-afb7-138bfb6ae40f.json；ID：f578b224-0690-4abb-bea2-f7b5d4692373；SHA-256：5812b4c2bc347bf806df52290422231cf3a08eb9e301062809785b7fed84b18a
- model-request-f8405b22-007e-4c96-aaed-c9d78bfc6202.json；ID：cd2fb87d-e081-4a4e-b19d-ee8090803a75；SHA-256：6334bc9567ec9fbaf10706741dfce752a87cf7c7052e62dc59da153f14ef8ab0
- model-request-f849016f-fe38-4608-bfbe-529060830be9.json；ID：4a2b0df1-1d20-49ae-9353-405e7437f010；SHA-256：d32cb3de53f0279cfb101d0a1f713d74e8fc6f5221371832ec884c4a424c17cd
- model-request-f94493c0-5cec-44c8-846b-bd996893e7af.json；ID：6e8859f6-6847-4081-ad48-97ae3c91fb26；SHA-256：441ff408c2a875b09c6b67398f41232f35f52c89113095d98b60046285d21d2c
- model-request-f951a4dd-c60e-49c1-a1c8-ca8800d56f80.json；ID：037e31ee-4e6f-480c-8161-052a24b66456；SHA-256：4d63345e0a12fac4fbd6cd0844452521b3675b0945b2865de1c521ec4b853276
- model-request-ff7e5a4b-7d94-4a51-8802-2b897b66d00d.json；ID：7658d95f-6d6a-49e5-8700-39f34ceb4f96；SHA-256：27f0f9df159f48fb264a58108f58c891c47dd9589de488b6305d2cd114e09b3c
- model-request-ffc6ff82-8293-4461-a5b0-fb19db100544.json；ID：2e3fa91a-42cd-4567-bbdc-c0bf235bb69c；SHA-256：4154cb022dc6f053ef11df032e0c2f2791ea95b2d1c5b93edae578fb8226aa21
- model-response-005f211c-84dd-45d6-8506-dd3a91037d88.json；ID：4c1ba8f8-815e-428b-86dd-861ae60888ab；SHA-256：b6e01ef2749bd5b8d821c8e6f8b2d8e452c6b409bc363a35656d9a5adf563227
- model-response-00936653-8285-4214-96c4-1b37df3bae53.json；ID：86f0956b-a056-49ed-94a1-e8890c0036b4；SHA-256：943e9925a94fda28c7cb0a254164386050058e48ad522acf717b4823c40a1d26
- model-response-08f957c6-d784-49fc-a277-3a078b9986af.json；ID：f863ae93-09f1-436e-9b9e-b25c0d0b641c；SHA-256：c8098e46b7f6ab82f475e3d0c85c6608f52893115038efe980728748053f4e93
- model-response-0c237c60-b231-4f94-a515-ec46ac9910ad.json；ID：fac65272-b79a-4ac1-b86d-338eb5c21296；SHA-256：b64ad3362029826d2186f47d4e216695e35c11e5e96fd2fe3d5c0dbb2a60e888
- model-response-0eb5dc42-572a-473e-914c-5d521be75ab7.json；ID：5fd2fe3f-2694-4851-950b-dd3f1f7bf7ec；SHA-256：6aa46238281b5683b05d6b0180d6ae0706f91c8ae7696e7628948707628e4d8a
- model-response-1033ef5b-b2c0-4685-9059-cf5bd515a454.json；ID：d2628e03-833f-4eb3-8267-127f2949a263；SHA-256：2c3ffd5839d4134345120aed9a16848f36319e72f788ba2f9a312c4be9f166d4
- model-response-131708d9-d926-419a-9f8b-f254c1af6675.json；ID：5ec97aa4-2a80-4d90-aa2b-5d8eebb281c7；SHA-256：5ecd6db2eec3c97daeb125f62ff645e624023ea193b7a09944defcd17d413b5a
- model-response-1427e396-da61-4869-8914-8bca87d10da9.json；ID：446c5580-f7e6-48bd-8844-d0fccbeb8a6c；SHA-256：106f4cb07658cf23bfa28a464604a36dbf39fbe381ec04b7946925d308bbea4d
- model-response-146640af-bd17-4511-addc-0eb357e172b4.json；ID：8d885e35-ff24-4830-ae8e-912c12365585；SHA-256：794f27436360bb083f5a95f3612a6004cd42514cf95d0b411a0f7d9235076e68
- model-response-14c147f7-ca29-41f4-82aa-7f166f63722a.json；ID：b2387488-1cd1-44c1-9504-bd2ad2584cb4；SHA-256：7f59d3956eeb74bd97e0b0c2ab151c4bae7c6aae6c6145147029a583e8820ce1
- model-response-15e04959-a191-48c6-8647-37d63a035ba0.json；ID：06cb6a4b-3e22-4350-b498-ccbf47066dbf；SHA-256：8dd072b380f012fa78ac1b7b292c0b87477f0f3ae1c9a085cb7f35b194f2155e
- model-response-17862848-8ddc-450a-8685-4ca5ae12794f.json；ID：6336ed81-0a32-4906-855b-532748ce90ae；SHA-256：083a8da405b1fd34b9c6f7adb0b9e54fdc49328d0d3c26c98112fd6623195c87
- model-response-1b82daff-44ce-42e0-a557-9a2e8e7b2598.json；ID：83916f25-9a1a-43ad-bbef-03017cebd786；SHA-256：8a45392b7cd60fc2f16e728c21bea1447fcf5efc9cdcf93c6e192b615a3bacc8
- model-response-1d019935-b74a-4386-a7d0-4f5d297bc016.json；ID：3527e3d3-00ac-491c-9587-6542c158d1e7；SHA-256：0579c97334ce960bf9794fed09d3e7fbbbccd4a1f523ad58e04eaa2f4f24a1e5
- model-response-2358836e-6822-4390-ba66-25046aae4f93.json；ID：7412f348-95f8-44a2-ab4d-66e9982b0287；SHA-256：3ae2b8547d2954359db0b88b33f07eb30e4471130f5590780a03680618833bd6
- model-response-23639598-ac3c-499f-bbca-e240b8903faa.json；ID：4c245554-6b44-427d-b710-689623df41fe；SHA-256：6e32be5d9be48253840a9008dfe1e97917eae983ad8ad6766d11ea51add71442
- model-response-27c0afc2-3872-433b-955c-aa57e3b4423d.json；ID：43b6eca3-4155-4e3d-9343-2613c76313bb；SHA-256：6abc574721810ea3a4bd6d67c7e6782c2dce1df83bdea0d5cf179a162d7c7f57
- model-response-2a35bfc9-df7f-492b-881f-7d4d97c3cb62.json；ID：d189d5bb-1094-47b9-bdf2-2406bf0b917d；SHA-256：d4270fb9af17bf4ed44dc6735f06760d6503ed3f4a275246df9e701d8121c895
- model-response-2b5d5a5e-70e1-406b-bcd9-44a98e89a24f.json；ID：c66013b6-50b4-4eb9-b333-bd787e9a95b3；SHA-256：c6d6eb7e33ff58b377c9f24929325bd537be4672918e2e38ef45d1b84644ccc1
- model-response-2f613a61-aa30-48ba-98a7-ac6b21cbef3e.json；ID：6a24514f-d6dc-4bcd-bc27-09306405a2de；SHA-256：c93565fc1cf43ebdd9f53971c5acd11092c2ff65d04fd6407338b2c035b18a55
- model-response-30339183-f1ad-44ee-bcef-93e0fe552f5d.json；ID：024b4d70-27da-4207-8526-29d0793ff466；SHA-256：49180ca7d45396d8b72e6f1ba2700340b7f86a1fa7e98c7423e21094568d61ba
- model-response-33bdc1b1-ccf9-4e74-bae7-85786bac3edd.json；ID：318fc785-8ca3-407c-8c42-f1fc7c29e70e；SHA-256：7497f9cfa095cbe9dd10e312bf9983ea15a2a62e8ac927b9363011d6f587745f
- model-response-33ece043-ff31-4dbe-86c7-4eaea09d4dca.json；ID：54e2203a-60ea-40cd-ae5f-1908631bf087；SHA-256：decdc583011023c4ba03017893914f27dd14662e9881c7707f3a449be2e2459d
- model-response-35b7a752-2a07-4e33-938d-c13923e83874.json；ID：7c71e217-fcb8-4c2e-be1f-81d8da999f0d；SHA-256：62545aa06b2831100b0568b9d06452337bc3e62d7fa8aaa4074b8c57e6ed0b09
- model-response-3987f8ef-3405-4b64-a056-7ad7437f21fe.json；ID：06f49673-ff40-46d8-ad2f-7044caf9dba8；SHA-256：7cece69434db792a045d4bd49d104a14ae42b97e99de6cdea896270c628de3aa
- model-response-39919b33-c0a0-46fe-849c-fde421263403.json；ID：e5455a33-0026-478f-b480-10340db5280c；SHA-256：9f343083f75bf069a2108638982177023794fb8a7bb0c011af11b4504eddf979
- model-response-39eba489-ebf4-4029-930e-07e645dd9a2e.json；ID：ba0ccc25-4a4b-407d-89b6-898475ea82e4；SHA-256：59d322cf2c4ff703998c966ac1e65539012915a49d642fd68fd8d18f26b46c65
- model-response-3ada4226-b8ed-49d9-8225-c9ce66cda8ba.json；ID：7a5cc35c-5c29-4674-a849-4cd95ec292c4；SHA-256：39c7a8fe983c51cf6584b54c704246d19d2318ab8fe187ff43b411d42e9b0909
- model-response-3b2714b8-3415-4215-a596-cd7de00b2624.json；ID：6989b871-f593-4c61-8c45-78aec34bb15b；SHA-256：c81b0d2024b2381fb5486da4513eaef24c5f5846290927400964be27b4e587b2
- model-response-40738e41-3b45-457b-ac12-f6bec07add8e.json；ID：539c5238-8f4d-45f0-a7e5-e0f892162249；SHA-256：5438c27ee07dee9a359700ee69a8c0d8eb73ebe54f58434c66508b33afb95d51
- model-response-40d88414-8f61-4977-8911-5619aa75e80c.json；ID：f2412e98-1707-4cd5-9f64-e3982ffaea50；SHA-256：dd6674690318138a0298c537ff8b611bd0fd6301fb2efd1f8860e60c9f855007
- model-response-415cf69c-a6cf-4a93-aa3e-fd489df49d8c.json；ID：95c303e4-707b-4a64-b33b-c74274ded721；SHA-256：b571ffefabe621344b4842b399d5b6b4badb960722ce030e32b831ebab1a0799
- model-response-41a49ccc-6b87-4a12-85c5-edb93434f293.json；ID：ddb0afbd-5299-462e-89de-a4755cc9509e；SHA-256：1f01851b78f21a6cb89f13806b0b1aca2f4b2771273768aa522c983b63b85930
- model-response-42fa7da7-3534-401f-893a-33acffcef497.json；ID：31430c70-9c56-4854-b77a-6b514012aaed；SHA-256：02b22f04cb93b3ae50127e76b483670de31d4489fe06fa010c2552fc1c37fece
- model-response-4381e889-e192-490a-9796-fba85ac004fb.json；ID：fecb0da7-5ae4-4809-8ac5-7eb59a4e55fa；SHA-256：ec764c05c3f39344cf478c4d28293e12f56d9592356e687f3d3077322248a5ac
- model-response-46c67d40-52b9-421e-a194-6523af3f8d5d.json；ID：d51713e0-72fc-4411-830b-34bff199e943；SHA-256：f739c34f2474fcf709ba226834b5fd446231093a002c6189472d6eea88a39f74
- model-response-4970f0ac-1594-402b-9ab9-ff3e553dfb94.json；ID：3ec0a56b-06e3-4b44-8b20-c2ad95c83b58；SHA-256：6e05e3a93aedda41f6c61071f0bd61737c2b0ca0b67c23b45832e54aee59009a
- model-response-4a150140-b985-444d-9561-75d634229381.json；ID：f6051947-f47b-4201-a630-5d088dba50f3；SHA-256：384967e28da6622a8cebaeac6d65500f96bfd51f0ae57554129ddb1e849ce409
- model-response-4a2356a4-0c79-49e2-987e-1aaa29392b7b.json；ID：dfa4231b-fc45-4693-b961-d69c6002dec2；SHA-256：eb82ccaefac90f54bad9773d486627a88a19285dacc15247e702690081b677f5
- model-response-4aaad8f6-3a88-4de5-a436-fb1b8a6549ee.json；ID：72c3807d-ff4f-4e84-9162-eceb2c45b449；SHA-256：f7e18e992fc92dc541452d6bcad55f8f78af7ab6f64669829f7be7883b168fb1
- model-response-4adeb423-b640-445e-ba20-9b3ba3faae77.json；ID：44cc9b8b-0e4a-4a5f-bde5-d72e35476669；SHA-256：8c2380b898b6440106e3d4706931c92fa7b4b2c59f34dcec622553b12d2ff1f1
- model-response-4ae1ea2e-95db-4191-8583-635345abe032.json；ID：b23c57e2-2557-468e-9436-4541c56ed713；SHA-256：13b5f411c635baf7f87da053ef3cb8ead182249335590d487a8239c9407b8aae
- model-response-4ae56860-093d-47e6-bc2e-af19d643782e.json；ID：654cab1b-2ef7-4f81-bd3d-09a0f50756e0；SHA-256：766b3ff41b1adf29e48fd61d702eef2f17218986a7532d0faaca6cadd28abc68
- model-response-4be0ad81-a0a7-4f9c-8a75-e42d4d15a27d.json；ID：0ede59ec-2970-4709-b407-0f48870a0b50；SHA-256：fdd97dc7a7d85fea242367c0ba513fb11d3254982e1f6601c1dc6ee7dfae2632
- model-response-4f1d64aa-3cb1-4c02-aceb-4361aaf0aa1c.json；ID：81e37b47-a5f0-42bd-b400-b5ff84cd2a9f；SHA-256：1c7e9e6bd071dfb4fe233bbe4b43ae21f078783f8ad2f112fd084657aa833233
- model-response-5272ae77-c0a7-47c1-83f1-7b2245ab7f5a.json；ID：b4896e1e-26ab-41a5-a182-2fd33ddb9a38；SHA-256：fd8375ca294f6bc932b7e9f69c22a7af22b53f1ac7b9d33848689fe90afb74f9
- model-response-52d2a408-3a4e-4079-ab3f-bd3532756f32.json；ID：b87d43a9-042b-4ffd-84d1-8c55a76ba065；SHA-256：3b89b910fb23b272432227f2af93bcb4d8a7df8ab711f676be7451b29f5109bd
- model-response-52ff0eff-d8a6-4b0f-a8f1-8ec0aa46fb78.json；ID：ac038109-d757-499d-9394-93d79c1fc0ad；SHA-256：6a5c4ab1f24dcaeb0c7458a72fc3c16015cebfa2a3648e73baf8a48dbc3a2f45
- model-response-535c5185-46dd-4203-b33f-c84183106ba0.json；ID：27ad07a3-4f39-4699-aefe-4704b8c0dfce；SHA-256：3e94172ccba55e3cdfa6a1a1c18700651cb992504ca50c236cdd0e355d6ebfbd
- model-response-554eb758-2630-43cf-bb97-a55bc3168408.json；ID：ce70f9a4-995b-4770-8da9-cf6fbf4eb742；SHA-256：1bc5d0d5971812b9d8c04d4060aca3af8ebf305e6d03ef830174746a204f33ea
- model-response-58ec3ef6-0496-4dc4-b3d1-a01721d78b8d.json；ID：649a8849-2910-41ba-900e-0e4fd580a861；SHA-256：ede93f448d4f6d1b86eeb60acda96ef0a365a75e82f689efd5e525bd07bd8ba6
- model-response-5b4ddcae-e521-4961-aee9-f3356631671f.json；ID：2f436537-9ff7-4e28-9636-e6630beb73fd；SHA-256：dfb592b5c974aff652d9a122b3f75e228446c2817da05520743446c65b0b0788
- model-response-5b7028d0-b47c-4b60-bab5-595f4070c69c.json；ID：43c4c848-0141-4237-aab6-11be547b9948；SHA-256：516d035f6a6c7101bb8579832945d985d36f26d71e685ba59dd8e47f17619b1d
- model-response-5bb99959-4e2a-4e23-9f0a-15439fa6ed70.json；ID：27f65e4f-8904-4322-a8b9-3749892c2071；SHA-256：98aa93d0b13d4bd8ece5e70df4f7aa19090f4ff2e98c2c8b25581f366de36375
- model-response-5beb5ec1-e771-491e-8c2d-096ce26bed62.json；ID：c404f9de-eece-4161-8992-69e8a9cc0009；SHA-256：de235481feb155d5a50029a78324dac8cc7dd8d1fd07c1448f54f5eaa9a3e7a5
- model-response-5e24affd-853b-4203-8390-d461de9d0b7e.json；ID：9bc4e6c3-65ac-42e5-9ee7-ff1881221a7d；SHA-256：6b66c85d91529f4eee1a21bac0a4294743d989275911ce4049d5e8789c2f2d00
- model-response-63b8a3ed-72bf-4a72-ada7-38a27908e616.json；ID：b0ace5af-fab2-4c94-91be-857252cb1595；SHA-256：928a74e1384e46938f6c1f31fe8afed4d0cf0f8f3da7988be7daae30f67bdc13
- model-response-64ccabe4-dc8a-488a-9b93-d25974747e73.json；ID：f777d6cb-211e-433b-bc89-4a3cf9b35924；SHA-256：3d13e3ee5a3f03dbb14cf9c5984d3e07d8de10ce182aa0e9cdf42d7abd276edb
- model-response-653dcbad-9e88-4327-b730-17c6690d502a.json；ID：db221742-e50e-484e-a897-4536c2a0c445；SHA-256：419d984fddfe054f606bb07e49cc9ab544f95e7dc871ef57aa3ef6ebdf92dd03
- model-response-6606c4ea-62be-4075-9340-4e40f02aba3e.json；ID：4fd39422-ac2c-4445-b3d0-ed7749a24660；SHA-256：f1f01f5e6d8a9c45addb3b522649391662a62ac04daa24004f6987e28e5b59a7
- model-response-69791ff2-7fbe-49b0-83f5-a1d53ac9b249.json；ID：07ce0d2e-a093-4f17-b32d-c687a146256f；SHA-256：40c1de72d2de94fdfe2e04cfda2112dd292e3163bd87104a59d5c7a89e00148f
- model-response-6c35353a-e5c6-49cb-a37e-c5e8c67d2012.json；ID：dce2274b-1da1-40f8-a231-9812c2d70e25；SHA-256：a9824a7ee1f2fffd6807ea107a17a9cc6d4b6025c515c4c2031b09325bdc12ec
- model-response-6de32095-a616-48e5-9e8d-9778aab5a4d5.json；ID：4244c0ac-00ee-44c1-b9d6-12db4c00687d；SHA-256：3e60f80d5754407f3645fe74cc5d9c19aabbb91946432018e05b3f8ca5e88672
- model-response-6e3f0a7b-6ed9-43e1-944c-1b0edf028186.json；ID：0721c68a-c30f-4321-852e-b0d8048cfcd5；SHA-256：a50f52a9491dc4f5e738ff9cc679708ea4aa27db4b0f24c1e152cc4ea137dfa8
- model-response-6ee55774-3b20-407b-b981-2bce5e1344a5.json；ID：67d30752-7c34-4223-883e-30dfd8d45e67；SHA-256：ecf9c969f1dcd88db52020f7e32e9d3e9f7972013a94a5216e9d84acba44b516
- model-response-72a5517a-e571-48cc-82c5-343444a024ff.json；ID：13482be5-789d-4620-91b9-5cabd6002bc4；SHA-256：e4ca40623428f2c9c8367c1484fa932e59e8af6449aba683a8b43decaeb402a2
- model-response-73e692cd-a095-4047-9d35-2370e21fb886.json；ID：599d2c8c-392d-4bb4-b81c-2f0b01e90e30；SHA-256：56fc4b767b999d3fb9f3c22f49513844e51c5c56a7303c5c0cd3b54541029667
- model-response-74fa8a75-2e05-4217-98c4-705f3b0efb83.json；ID：5c602a24-1cc8-416f-a53b-c2600d145f67；SHA-256：4e4fa9cc71828056003ab916094d86313402c0053f92fa74610f5de75ac204ae
- model-response-74fdb112-84da-4281-8cab-271dd11d3d61.json；ID：e6dcfd7a-f88b-4e94-99f7-bb0ab33ecb28；SHA-256：f66cd463ace9341d1ebd42172fedca5edae3f9608464a3ba82cdacf5cf2fead5
- model-response-7570bea8-5c1b-457c-a0fc-18c432aa8387.json；ID：3d8b55ca-3412-4b61-9684-960aeac1b732；SHA-256：bc2432ffbf7765854c3a10bf2068aff57fffac6cf55499f68b2c45dd658f2a4b
- model-response-75cf3f7b-8735-4202-bf39-73a7d8acfc39.json；ID：0e9b82e1-8d7a-45b9-9a57-6fd638410832；SHA-256：b705f0bc15ef20dd153b64cfb304634e4ba7b88ee26e8c97a19c1ca2b6dfe80a
- model-response-76fd3bfb-b401-44f7-ab02-fddc2c2356a8.json；ID：a969dc5d-3dc9-4a6d-874b-d83cba26deb9；SHA-256：f06e0c63de64f286f77f3e978ff6f2e392a7c7f2dc314314365767a883e38506
- model-response-7771cb94-8e8a-497e-b06e-ededdb642ce1.json；ID：2b16d97b-650b-4943-ae78-5524d1a72d44；SHA-256：e2e7e031ae5891a3ef98f93c09578488ae3e8f1691224c5b243744ff229367f4
- model-response-7bc05439-4b90-4a60-a3a2-03739f59544d.json；ID：e5827bb7-8097-43fb-ba7e-1cc646ac93a5；SHA-256：ffe7868c1d60d1eeddfd16242e5b755d186a5baa3cb3f9662dbb68814c79ce9e
- model-response-7ccb8d8b-afc8-4d01-91c5-c92904b5567e.json；ID：d659abe9-515a-490d-9660-21c84033191d；SHA-256：84dcd9dbbdd8be1121f598f34308abd0da05b350e35f1039758e7ce788779f82
- model-response-7d754d6b-80f1-4eca-8eac-a5c69655e8d6.json；ID：c6989a53-25c7-4974-9284-3733802475c2；SHA-256：a9170838d98515f2e7cfc7a0c23805cf9ae824fd41d66d3e590b96600244d038
- model-response-7df4c74c-bb08-4cf3-b1c2-729914cdfa2e.json；ID：ad4d6d5d-7617-4826-81c4-70bb84e5a8b9；SHA-256：1286f03f9c5ed9452068be5bdb40564760b3e59ed6a1befdd653cf098144b8c4
- model-response-7e15b077-0ec4-4672-84de-b824646ddab5.json；ID：ceea3442-97ef-47c9-b589-dbef7da3d45e；SHA-256：980182bf7510d3453f069f996e49db657023ab64bd47269f588acf74b933f3bd
- model-response-7ebccd47-9ab1-4630-ac57-2744e58aedc2.json；ID：ef7dbd3d-5cdd-4938-b01e-474c7174578b；SHA-256：9bd652d12380e1394313cebe4ea1a16590b96c9caafd68d5e1776e583f6278ed
- model-response-7ec1feef-c789-4c4d-99d6-690917d7d036.json；ID：cdd17f30-24a2-4ba5-bec4-93a216190093；SHA-256：784e521b4735f3fde1a6fcf6508eb1b3e2fe02aead9300e651d3f0c84e20ee89
- model-response-83aea06a-03df-43c5-bed3-1eed1ae33131.json；ID：413eec0c-ea0b-4d0b-8361-919674ebffbf；SHA-256：4cd2e0a0d5c82a42807d728a92740158e6f760ec04075e5d6e29e2a616b56d4e
- model-response-84eecdb9-d3f2-4182-92c9-8459f80b8c94.json；ID：80a710c2-32e1-443c-aded-5629ca37dff6；SHA-256：2c0c13b25b8f96ee77bfdf616e599eac8e03ebe9dd85e9a6e3688a4ab56af3ae
- model-response-85bf33b4-48bd-49fc-820f-7d60dc3da07e.json；ID：f42da65a-ba86-43cf-91d0-44a6e4862cff；SHA-256：e7eaf6347fccedf44b9724d5c991bfbc782251a8ee79a1c4a7129be9f9b321b4
- model-response-86367b21-3dae-494c-b09b-c378679b94f9.json；ID：ea2266ab-9b47-4665-8782-64858bcf4485；SHA-256：ddfe1993b135557bb28f792dd65fabd6c59bd49af49ece7452d940183548fe50
- model-response-867bc9a7-a161-40e1-bc26-471b5428fb4f.json；ID：f6f7f75d-3fb7-4af5-83ce-6d1dee6e5676；SHA-256：6bb57a7cf8fe897e7987ee7b02a3867490fb11b85d7ee5a2db060e134e7694f6
- model-response-8832bd57-5394-4ddb-b37c-8eb9edb58d87.json；ID：9a1c03c0-8404-4f89-bb71-79cbceab6aff；SHA-256：a5048a797ab332ffcd3ffb3c075f449dd50e6d48c9f736c869f819245c63bdc4
- model-response-896f2fbc-cf97-4c38-99d3-cf30d080ef30.json；ID：d66f38d5-c4cc-4fdb-bd2b-5a199165f9cf；SHA-256：cef2f87f7772babaede632b87d66a3fdbe5f7808fb107033dd235a343df4ddcf
- model-response-8a7c3aca-4103-4e77-8d17-a13887b3258e.json；ID：ddfb9447-0e06-4c3e-97ce-9419b92ca8db；SHA-256：bf4892554c59000b6fd2699d212978709019607fcdfec2f44ca67f9fcbd7a261
- model-response-8a9d5584-f15d-4c48-928b-0133d3ca8fac.json；ID：5c19ff1d-dd70-484a-906f-7f1e7c7fdb1d；SHA-256：c266c945bd8cdcdacc9635aba909ceb911ac7413f72fb66fdce5d71826db76ef
- model-response-8d21c61c-a5ab-4b32-a71a-8c02fd59ad66.json；ID：6630701c-8b10-4038-9173-88468e88f5fa；SHA-256：0288180dca803295f8a088a39cd0e6a318b60509ac8dcfdfeff28a4eefc603eb
- model-response-90dc1194-2d3f-421e-9340-ff8803feb9bc.json；ID：d5074b62-4cae-4129-8e45-a03c8f0276c7；SHA-256：5573091ed3ee234db904b671ca227528081c837c0328a01ea093184d797f38b8
- model-response-91d5fe42-ee84-413f-9ebe-ee6ca505c666.json；ID：ddd7f270-e03a-4b15-b34a-50f8a021715e；SHA-256：d12f840f87adaa1bc444b42f155ad875044a761d77470e3e91aa52ae60c150d9
- model-response-94251cd1-0e51-4b41-8154-50cd479db6c0.json；ID：c6b209cd-cf64-4e39-b832-bf104ec898be；SHA-256：50e801fdfa4d08773a49d6c63ec1a10005f2f8b64a2de8e7f0c70c33a1e2a758
- model-response-94356086-e0a5-414c-bed1-e95800ca21f2.json；ID：78add058-251f-491a-8a7b-d9b049c0c7b3；SHA-256：e89e80e07978caeb4f140c84c8d120b5d47f35459c371544dc308ce5f4ec3ec3
- model-response-9638e8ac-0cfc-4d24-b8ee-20ce442c2895.json；ID：4693ff1e-e94b-450b-a476-957aff2b4174；SHA-256：ab889ec599704d3094d9ab33c2cd5f2f7a531133ad466774967b8526c0cb3601
- model-response-96b456f6-0cbb-4c4e-80cc-e24da74f9e1f.json；ID：08d3aa10-a7e6-41a1-9b2d-996a6aa85543；SHA-256：4c30476db15bff5c2fa4df0222f5091683f47966acd60c0bbbf4e0aa1f5d5d1b
- model-response-987e8704-a1e8-4f8a-bb0a-eea3bcec130f.json；ID：8778c734-483d-4962-9dbb-5fd8d09ac944；SHA-256：bb63e14bfc29e2733297566151af0793668bb4b725ad4137a01d15df6c1f0ff1
- model-response-9b6c4582-6b51-4a92-94f4-8119237bbf06.json；ID：be305702-235b-4392-9da2-a10b62c257af；SHA-256：16a44e26660a1ee02bbcae4167dedcf786811f02fde6792900a7fa03252ac5b3
- model-response-9d6b168c-a6bd-467c-a34d-03c352eb6150.json；ID：903d9139-bd34-4d85-8517-66042a43782c；SHA-256：af0b30f44d21f97712251bdde3f2dc40eb892fa9a0615cc5c54ef8822596cfc0
- model-response-9ec03be5-6c3b-47e5-8aac-37889492ff2f.json；ID：081a93cd-7b43-4a8d-9b1e-a38a179edb6a；SHA-256：2a6c169a9b79a083f2c3fcf347f7d345a0e9addfd413caedb61c9396ff76c78d
- model-response-a4295f04-035f-4fb9-bd3e-79f905ee0c4f.json；ID：8209578f-1cea-41fb-8588-89cedafdce1b；SHA-256：04ff9fb852b41d47dd2eb11f3d58e20aa8ce6dd6cfc53a5f9b65933dcef00287
- model-response-a48d4d02-5d13-44f5-b5af-dc94453edce0.json；ID：ca55589a-d8a2-4dc7-bcb8-106a6631da32；SHA-256：c9b76b0eb7d1f2f9ff553eac6294d97b52c97a59d22d03fa70879d150f02ef20
- model-response-a51d355a-7ae1-4925-b7fc-6eb4bf4cc6ad.json；ID：26d525f5-ab19-4525-9900-d32f51ffd7f9；SHA-256：dcd678e8d48bcf85231c53b372b1e36fb3298d3f06b38490b6ef4b663440a6c5
- model-response-a5a82a55-0f84-46a7-8b2c-14df42b3ea34.json；ID：2649e426-16d1-4fb1-99b5-43e930a16c26；SHA-256：7b1d4ec029480213caeae59b60312f6e77d17a5b5cf2eaa1e2d154d52a44c425
- model-response-a7d755f9-49db-42e0-8d9d-6f5565a8d25a.json；ID：edf6878a-02e9-4937-8613-2f2ac8f9ff48；SHA-256：13775346e9eab39705d952b3e0c6fdeedfa7c18ca961ce71a16c70508c5e6890
- model-response-aa875d55-8a8a-4e57-b3f1-c9383d994aa8.json；ID：6321cd5d-74f2-4e51-a906-949d23462776；SHA-256：cb15e02a8eda164cea3c7dc37d5df976514bc41e5b90a97570ea1776a2180aee
- model-response-ab5f6488-c9fa-4087-95e8-c08ae3c7f38e.json；ID：4578ae3e-93da-4a5c-b895-9c675c59376e；SHA-256：ac60806563a76725f64981fd86bb728edc96cf2597e26d57a630930f26c12e91
- model-response-abb8b0b3-5727-4227-ab98-8bd58dee3319.json；ID：5b389b90-3032-429d-9441-43d0db5435ec；SHA-256：c537e202b03b31e0f214553b7b00db47eb43ef85c096fd9b360715a35b041591
- model-response-ac2533b6-fdbe-420e-acc5-9acb64a6639e.json；ID：c78cfffb-699e-4538-b331-8e24e42dcc14；SHA-256：a1f3d6d554befcceaff51347263744e7ff6ae7ffbdb00456ca3b503853bed7d2
- model-response-ad5f0c48-78e6-4f8c-a303-3f765e3c692a.json；ID：24975748-25ff-44a7-b786-4de4d0d46d06；SHA-256：c50450a0b846cbd975e20cf4261347d8548cf6d28980fcbb184b3c94de713427
- model-response-aeeb8bc7-9643-404d-bfb1-bd7e9ce1b890.json；ID：ddf776b2-0b33-40f0-bcd3-3fd65126f6aa；SHA-256：fb293616a9ca8f014e8a1c9bce402a6ee00d46a289f0e1e774565bb5b19aeb54
- model-response-af158745-2fab-4cc1-ade1-ee5237943ba9.json；ID：ba501207-1728-4b9b-b436-d2c31ced567c；SHA-256：a38fd3834f8a4c2a77cdd1df1d6373a833d7ec33dcbc992e6d8fa573db7d05e5
- model-response-b20b9cbc-b987-424e-8310-3fb86591211c.json；ID：4984b45a-d666-4da0-b1ad-9d2617db03a3；SHA-256：047e75d61f6927979ed2ebebedbcf31c126bcd4005b919795ed7e9c7f0c15bcb
- model-response-b37fc21b-3896-4e39-ab53-5ef551c23675.json；ID：8e53f956-28f6-455b-902b-3f87835060fb；SHA-256：24d7fe99904cad11215428a0d7bd26c172576427bd4742580dafbba532fbc0d6
- model-response-b538e026-95c0-4e77-8b18-e5e1a6c3adf6.json；ID：8cb12098-f7c9-4f39-9251-e8d5750dfbc7；SHA-256：0248496c7d75a35719d228c9bba1306f04a70c9be9c551f878d4052415bf1b6c
- model-response-b69771cc-1175-483c-b747-228cbcc1ec8d.json；ID：c3d6d7c8-f814-4a45-ba61-2605998a9c55；SHA-256：1c6890130e6645894f04284c9794239b83fc2c6733981e4ba5f5c086b9e24dd5
- model-response-b79cf781-5f2d-4bb5-b282-dcb853b99607.json；ID：2abb3e89-5d42-4d24-bd8f-8768dded4956；SHA-256：dad9aefbb9637d30d5705dfb2aebe85c5cc34dc40d3e82daaa086093159ba3de
- model-response-b930108e-f48b-4ccf-909e-39951d353a36.json；ID：6088f607-a189-4e2c-b32a-91745c36e0b7；SHA-256：0a7e4729eec49a4d962e3e2e6f39ec0b661fd22892593ca85dc4dc470538e996
- model-response-b94e510f-92fe-4b72-ae79-b3f13010672e.json；ID：45356a9a-a904-44a5-9683-bd7d85eed109；SHA-256：8ebc40ae1fd89b34896fc378bcd28cac19f9b07c99a7ed4a0204899eef6e786a
- model-response-bb7cb0e1-df99-4c98-b167-cd644d2a511d.json；ID：0463443b-eaf6-4372-a0f5-b8ec9aec4c5b；SHA-256：d7149b6efaa0e7e284eb8e5434aa130528e37bc79478196ee7e7ea54f6e2b992
- model-response-c0aec0a6-3510-4f69-8919-aa8219708ac0.json；ID：1c847fd9-1352-4782-980e-554d9912e4e8；SHA-256：9985af10898040f73647e7e7ebebf37a992bb15b1808bd9b20e027a2f0e21bfd
- model-response-c1ad075a-b6ae-47f8-80ed-b79ec4b9b938.json；ID：4ec1ea67-4eb1-46db-9128-b8d786999d01；SHA-256：218235bf05621ad420f1b84403d2fae8f40a67d617510df895c98cedda8b9f7d
- model-response-c2d1c850-1ab5-4903-a129-3865fb8363ba.json；ID：22037c3a-2a69-4485-bbda-359c27215a2e；SHA-256：80035c0d75d17c95f13d404c75111326cdda3b3c885b9d6e2d0adb72b2b987c3
- model-response-c903d443-cd5e-4c28-a66a-6dcfd96c9ebf.json；ID：53d29666-3e70-47e7-a5ad-585993826eae；SHA-256：3bf6b8ae6983345111afc6de7e68b383aef829686df65aa344ced33986fb69b4
- model-response-cd35ba32-665a-43a4-9d91-8a2f86a3cf91.json；ID：18668a4e-1f93-46f7-9b1e-9102eb468b91；SHA-256：53534639b0baad7bbd6fcdf952d2205809155ea110b88a0fd1115b61091257bd
- model-response-cea5a635-165c-4d97-9ebd-4155263f4287.json；ID：2a5739a0-c932-49d2-af62-68a2001176f2；SHA-256：b0c13982369b5bfc888b90465d756ea16e6e89a84b61e9a0c2b80b09bfd470d5
- model-response-cf907bea-24ac-4b5b-bc2c-b29321b78122.json；ID：ed8830ef-9c51-401a-b04b-3ba26949327b；SHA-256：c47ca01280df3618084757e08aa967c3cc987898f8aa51efbf1f0b6d339d8c10
- model-response-d203377e-b0d1-4946-aedb-b650281bd4a5.json；ID：11e2483b-c586-4ae1-b22f-2a8225678fa9；SHA-256：a141f53c74536121bb864df2bd44506df729ae4a705f524d5b11fa3435402efe
- model-response-d632d797-bc5a-47a1-a40f-6e73ad99204b.json；ID：a166eeeb-0ab3-4f9b-8c11-146416acc2eb；SHA-256：f532e137f3349667af4feaa6903698a5ec48ceede1a7280d253f58d867304355
- model-response-da4b8882-9e2e-4ee0-96da-b3bfb833ae7e.json；ID：0187f6f4-611f-4834-965a-bdaaa664fc1f；SHA-256：aa752acddce8c21090a369389b30964ade0c7a09eb4ee5b41503670980769737
- model-response-dd6bd58b-975c-40ae-bc9b-2a34966197c2.json；ID：0eff163d-ec75-49f7-adb0-70d5cf3ea22a；SHA-256：72edb4ba33fe88fd61b11e510a732f3a12ab104db3fa614e87f57d22bdacfc1b
- model-response-df02efef-e570-4c38-bd67-d2a80046f618.json；ID：c928f302-8e65-47bf-ba6f-bcfac5a7c546；SHA-256：781e1e1b50b0c8cfea0f20826adb4ec8cfb95e284f040f8d589098cc891ee13b
- model-response-e21dac2f-a2c5-4624-b530-0eaa75346269.json；ID：3839e294-21c4-4aaa-a327-e2c72aeb7736；SHA-256：b95a19e9c6e0b5cb2734a7ae80bba909b63be767d30916f6d3a432cdbba73418
- model-response-e4266451-3f42-47f4-b45e-d64cf1caf813.json；ID：2ed52734-76ff-4964-a5a0-8f8d51b23fe9；SHA-256：487427f67dbc2d1cc2cb1f3911ad984aea8fa16a35a893ec40614b4e5aba1795
- model-response-eb2c8197-88f0-4b94-8c20-217786e6ded6.json；ID：2c599e31-0a7c-4e0e-aa66-62610d3f3d25；SHA-256：941681a7fd637e1e34a0105fa3805eb778b489a66a5a4636d236c5d2eac6bc45
- model-response-eb756589-0890-4ba7-a3ff-28fe3f2986f5.json；ID：b20f7b24-1cd1-4e16-a3b9-ee0c65f6cc34；SHA-256：871d2e16be2b5895bc1fd95ac9a08ef56c85bba86c35aa32229ef500fd12dde2
- model-response-ebd8ad65-a36e-4844-9c4b-7482c9aa4b39.json；ID：c317c146-c5eb-4e70-82f8-866a1e773c35；SHA-256：73607cc509ab24ab6fddc588a06fd93d2c4e9eef6a7dfbfafb750933c0e47806
- model-response-ec355747-8392-44dc-b2e1-1532d00b4a3f.json；ID：b56be22f-1a39-4c1e-ae82-a54be6d1d5a5；SHA-256：c7767627bcde2cc9831dd97b7993039bc1b9318dddbc3755441485114592f547
- model-response-ecbeb6fb-0246-477d-a585-723c975ee2d4.json；ID：61fc598b-cdde-4085-b0ac-d80a42380f43；SHA-256：93fee6c5d7906b15dd4934183f8c4e16f6f0fa497f552e1c2fec6e78bad9cf81
- model-response-edcdfac2-797b-4c0a-855d-61fb313df38d.json；ID：9f19144c-e1c5-4c60-b40d-b3780776936b；SHA-256：6f613455b4d41373443fd608c3bb059e0203e095c824b96ad41a5fdc46f294f7
- model-response-ee9fc87d-351f-4d90-9cd5-1868ff1e5c71.json；ID：d55b32b9-a9d8-4bef-b0d6-15c7e317a672；SHA-256：2c190ec5a6b9d588c665b3f035ef9820376c3b1c472382d59edd86a196fcd327
- model-response-f3db6efb-e897-4871-b1ce-438190798fbc.json；ID：8802a311-1a2b-4edf-a23a-0da6c0702618；SHA-256：93d3edc715642d2d4359c5f9c8aed7ae8350cabe97e6895fa4f4abf584d2fb35
- model-response-f494e8b5-f6a5-4ddf-894b-878a693bcfcd.json；ID：e9805df2-9481-4d6a-94c3-02d41b675558；SHA-256：bfc430277bb42064f09def151f99d4d93f58a6328e1c727364b31a894db850de
- model-response-f576981e-af2f-4b86-bac2-f4f4907ea9b6.json；ID：be6a4508-7823-410c-8715-da47d201ba12；SHA-256：91aee36ba68da064cadb9c172f0d1f8b2ca086f2a080e799b68b160d2eebb622
- model-response-f7e0caba-b4aa-41c5-a95d-82f88fdd067c.json；ID：5db3f47c-70fb-4318-a710-60bd954a739a；SHA-256：8e5a5d75ec56747406b26cca2cfc5ec35aadc3d3e599b7c6bc8644bc645cfce0
- model-response-fca570ba-0123-48db-a6ae-1234cb6c551c.json；ID：976b985a-32b8-46c5-8b69-a431a6c8f509；SHA-256：d190a4a66dc4f46e11fa424142c6e8ca93e735dd013ba12a67039dde67af0701
- model-response-fceb7841-f96e-4c10-8eff-e2643ce347b2.json；ID：41d9cf58-44de-4be8-9bf3-56f9521621e5；SHA-256：ca8f0bcdc65a8ab8c0a6f2881cbd39d59d7054052a1606e4f38b35f2c3b3c90c
- model-response-fd389f10-663d-447f-9649-6668a05e7aa7.json；ID：eaffa78b-f906-4be2-afc5-e2104b11a292；SHA-256：405c8b0fefbab5209a02592735d4a5ad81ea491acdadc037b93e205df60db405
- p06-ollama-parts-vuln.zip；ID：8ce6a7f7-d41c-4ce4-a128-acec71a7509e；SHA-256：f76d4068e93496b352824f64e851de3235367d493865a00ab60c82d88e163cb3
- snapshot-manifest.json；ID：ef31f2cf-9f3a-4e0c-bfd0-764a55bdca14；SHA-256：b67c758064a0c5712426bc3f1a2c09d7ed998009957f3df18afd72c849efae69
- source-snapshot.zip；ID：35f9b8d8-12fd-4672-af88-4ef0959de4df；SHA-256：e316cdcaa567cccf22240d0900bc223b488431137330ea2cdc42a2f7fe1cfa48
