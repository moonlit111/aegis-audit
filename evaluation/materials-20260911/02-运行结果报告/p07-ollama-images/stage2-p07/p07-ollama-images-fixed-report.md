# AegisAudit 分析报告

项目：对照池评测 20260911-093517

任务：cb6c44d5-4230-413b-bccc-5d65cfb13010

状态：Partial

目标 SHA-256：f1f36734d630259adb5e33889533543aa17d57284820860bb018ff9da499c9f0

结果快照 · 数据截至 2026-09-11T09:44:51.583Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：PARTIAL；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| CopyModel | server/images.go | L670–L700 | PARSED |
| CreateLayer | server/images.go | L654–L668 | PARSED |
| CreateManifest | server/images.go | L536–L562 | PARSED |
| CreateModel | server/images.go | L256–L497 | PARSED |
| DeleteModel | server/images.go | L829–L858 | PARSED |
| GetLayerWithBufferFromLayer | server/images.go | L564–L582 | PARSED |
| GetManifest | server/images.go | L129–L154 | PARSED |
| GetModel | server/images.go | L156–L229 | PARSED |
| GetSHA256Digest | server/images.go | L1121–L1129 | PARSED |
| GetTotalSize | server/images.go | L120–L127 | PARSED |
| ParseAuthRedirectString | server/images.go | L1254–L1262 | PARSED |
| Prompt | server/images.go | L51–L82 | PARSED |
| PruneDirectory | server/images.go | L796–L827 | PARSED |
| PruneLayers | server/images.go | L761–L794 | PARSED |
| PullModel | server/images.go | L971–L1075 | PARSED |
| PushModel | server/images.go | L921–L969 | PARSED |
| SaveLayers | server/images.go | L505–L534 | PARSED |
| ShowModelfile | server/images.go | L860–L919 | PARSED |
| createConfigLayer | server/images.go | L1096–L1118 | PARSED |
| deleteUnusedLayers | server/images.go | L702–L759 | PARSED |
| formatParams | server/images.go | L585–L640 | PARSED |
| getLayerDigests | server/images.go | L642–L651 | PARSED |
| getValue | server/images.go | L1231–L1252 | PARSED |
| makeRequest | server/images.go | L1179–L1229 | PARSED |
| makeRequestWithRetry | server/images.go | L1133–L1177 | PARSED |
| pullModelManifest | server/images.go | L1077–L1094 | PARSED |
| realpath | server/images.go | L231–L254 | PARSED |
| removeLayerFromLayers | server/images.go | L499–L503 | PARSED |
| server/images.go | server/images.go | L1–L1284 | PARSED |
| verifyBlob | server/images.go | L1266–L1284 | PARSED |

## 审计策略与优先级

对单文件 Go 服务 server/images.go 做结构优先排序：先看外部 HTTP 入口与跨信任边界的模型/层管理（文件路径、拉取/推送认证），再看执行/解释边界与内存索引操作。调用图不完整、未构建运行，因此仅根据目录与线索排序，不提前判定漏洞。

1. u\_6a29c4f6eeda6a384ab322646a7f1a8b：CreateModel 同时命中文件与路径边界和内存索引操作，是模型创建核心，最可能拼接用户输入路径并操作大量索引。
2. u\_d05d1ea7cc5708746090655b3fccf485：GetModel 具有文件与路径边界线索，读取模型时若路径未约束可导致越权文件访问。
3. u\_a688486fe1830109edd67a0b6bfe45c8：realpath 是路径归一化关键函数，其实现质量直接影响后续所有文件读写边界。
4. u\_f96f5fbf2e0656e6e91c28990992d5f1：CopyModel 命中文件与路径边界，模型复制可能跨目录并受外部输入影响。
5. u\_f00948db2bfbfebb4d9a726159cf1cf8：PruneDirectory 命中文件与路径边界且属删除类操作，输入可控时风险高。
6. u\_98d69cde3e3bdc4ac2949d92ee8f475d：ShowModelfile 命中执行或解释边界和内存索引操作，读取并展示模型文件可能暴露敏感内容或触发解析问题。
7. u\_58ee571c5b01c9fa56b761975748ecf7：Prompt 命中执行或解释边界，是外部提示进入服务的候选入口。
8. u\_57689f64b0756b1125eaa904a42f65af：PushModel 命中身份或权限边界，涉及推送与认证凭据，应核查授权与信任边界。
9. u\_2407f3a038074daed99e27f1bf1316ab：PullModel 处理拉取模型的外部输入，需核查来源校验与认证。
10. u\_8cee01b416e403be6aab843970707a76：makeRequest 命中身份或权限边界和内存索引操作，构造 HTTP 请求时可能附加认证头或处理重定向。
11. u\_03dafa6a22a89cb82e7fafcf413ea6f1：makeRequestWithRetry 命中身份或权限边界，重试逻辑可能影响认证状态或请求目标。
12. u\_f97c11920a736624953a5def49b60e1e：ParseAuthRedirectString 命中身份或权限边界，解析认证重定向字符串，需核查是否可被绕过。
13. u\_3301c0a120cc0380b0770f7c9e1e38d8：verifyBlob 命中文件与路径边界，blob 校验涉及路径与哈希，应核查路径约束和完整性校验。
14. u\_8a68c934015daa824fbeecfb90b49d5d：GetLayerWithBufferFromLayer 命中文件与路径边界和内存索引操作，层缓冲读取可能涉及路径与切片边界。
15. u\_3cf64280cd22241a99770bb57ce8cdd7：GetManifest 命中文件与路径边界，读取清单时需核查路径与来源校验。
16. u\_461e618537e93719119fb3bb1b1789cf：SaveLayers 命中内存索引操作，层保存涉及切片或映射操作，应核查索引安全。
17. u\_df0ea8b557cc1b25fafe60e40c7ef22e：createConfigLayer 命中内存或索引操作，配置层构造可能影响后续文件或请求内容。
18. u\_0a7c01045d74b621345e7f384a9c2a66：GetSHA256Digest 命中内存或索引操作，哈希计算与切片处理需核查边界。
19. u\_5da4b32dee490b72824fcec99a89f5de：getValue 无显式线索但为取值辅助函数，可能解析外部请求参数，需核查输入到内部用途的映射。
20. u\_212b5c0b131a9b6034a3e1536703667a：pullModelManifest 处理拉取清单的外部输入，需核查信任边界与来源校验。
21. u\_e26b841dc116cbcee1a8494884fb6648：formatParams 负责参数格式化，可能影响请求构造或认证字段拼接。
22. u\_cf903c008b9d5a06e383f5fc2ca2946f：deleteUnusedLayers 涉及删除未使用层，应核查引用计数与索引清理逻辑。
23. u\_e13356b4f905d4b21bda98ad07cf16fb：PruneLayers 为清理操作，可能触发删除文件，需核查外部输入影响。
24. u\_a42340252761e10647899a6d303374e2：DeleteModel 为删除模型入口，需核查授权与路径约束。
25. u\_951e4dce1805c434060147a09037b206：CreateManifest 生成清单，可能写入受外部输入影响的元数据。
26. u\_ca0e2eb44ec58d3dda04ca566bf5b413：getLayerDigests 提取层摘要，可能影响完整性校验与索引。
27. u\_8373c0eaf7050491e5fd608bf9852580：CreateLayer 创建层，涉及文件或索引写入，需核查路径与大小边界。
28. u\_18885d6c0dc4d1021d68a227ab4e784b：GetTotalSize 计算总大小，若用于配额或校验需核查溢出与边界。
29. u\_86470b586150fc614e387d6ac706e856：removeLayerFromLayers 执行层切片删除，应核查索引操作边界。

规划限制：调用图不完整（call\_graph\_complete=false），函数间真实调用关系需在后续单元审计中确认。

规划限制：Semgrep 在 Windows 原生环境不可用，本次仅依据内建线索与结构信息排序，尚未做词法扫描。

规划限制：未识别到构建系统、入口与依赖清单；目标未构建、未运行，静态识别结果不是漏洞位置或 CVE。

规划限制：recovery 为 null，本目标为 SOURCE，不能进行二进制恢复质量或保护缺口评估。

规划限制：HTTP 入口由元数据推断为 net/http/gin，但实际路由到处理函数的映射未在本计划中验证。

## 发现与复核

静态结论范围：COMPONENT

### Modelfile 中的路径未做目录边界限制，realpath 可将任意绝对路径或符号链接落点交由 os.Open 读取

CWE-22 · HIGH · 复核 VALIDATED · 验证 NOT\_RUN

输入：CreateModel 的 commands\[\].Args（来自 Modelfile 解析，经 c.Args 传入 realpath\(modelFileDir, c.Args\)）

危险操作：realpath 内 filepath.Abs/ filepath.Join\(mfDir, from\) 与最后 return abspath（U0006 第 232、248-250、253 行），实际读取发生在 U0007 第 284、380 行 os.Open

防护缺口：没有把解析结果限定在 modelFileDir 前缀之下（无 filepath.Rel/前缀校验），from 为绝对路径时直接返回 abspath；亦无符号链接解析后的二次边界校验（未见 filepath.EvalSymlinks）

前提：攻击者能提供或影响 CreateModel 的 commands/Modelfile 内容，且服务以对目标文件有读权限的身份运行；modelFileDir 为服务端指定目录

影响：读取服务主机上任意可读文件（配置、密钥、其他模型文件等）并作为 layer 写入本地模型/registry，造成信息泄露；配合 PullModel 与 manifest 写入还可能把内容持久化或推送到远端

修复：在把 c.Args 交给 os.Open 前做规范化与边界校验：解析后必须位于允许的基础目录内（filepath.Rel 不出现 .. 前缀），拒绝绝对路径与非预期符号链接；对 @blob 引用只接受 GetBlobsPath 生成的路径，并在 open 后再校验已打开文件（如 f.Stat / O\_NOFOLLOW 语义）

- 证据：server/images.go L248–250 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	if \_, err := os.Stat\(filepath.Join\(mfDir, from\)\); err == nil { 		// this is a file relative to the Modelfile 		return filepath.Join\(mfDir, from\)
- 证据：server/images.go L253–253 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	return abspath
- 证据：server/images.go L284–284 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：			bin, err := os.Open\(realpath\(modelFileDir, c.Args\)\)
- 证据：server/images.go L380–380 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：			bin, err := os.Open\(realpath\(modelFileDir, c.Args\)\)

复核 v2（MODEL，VALIDATED）：组件边界内已可证：CreateModel 的 commands 参数（调用方提供的 parser.Command 切片）中 c.Args 直接进入 realpath\(modelFileDir, c.Args\)，realpath 先 filepath.Abs\(from\)，仅当 filepath.Join\(mfDir, from\) 存在时才返回该受限路径；否则（第253行）无条件返回绝对路径 abspath。因此 model/adapter 命令传入如 &quot;/etc/passwd&quot; 或 &quot;../../etc/passwd&quot; 且相对 mfDir 不存在时，realpath 返回绝对路径，os.Open 直接打开该文件（U0007 第284、380行）。全程无 filepath.Rel/前缀、无 EvalSymlinks 二次边界校验，构成局部任意文件读取，文件内容经 DecodeGGML/CreateLayer 打成 layer。

反证：realpath 确实存在一条受约束分支：当 filepath.Join\(mfDir, from\) 存在时返回该目录内路径（U0006 第248-250行），可阻止部分相对路径外逃；@blob 引用分支用 GetBlobsPath 生成的路径（U0007 第275-281行）。但这两条都不约束绝对路径/不存在的相对路径，第253行直接回退为 abspath，未形成边界校验。未发现 filepath.Rel、HasPrefix 边界检查或符号链接解析后的二次校验。

待补信息：未观察运行中的部署、HTTP 路由或 Modelfile 解析调用链，无法确认外部请求是否把未校验的 Modelfile commands 传入本函数；服务进程对目标文件需具备普通读权限（属组件常规前提）；符号链接二次逃逸仅作为潜在增强，未取证。
静态结论范围：COMPONENT

### CreateModel 在缺少调用方授权上下文的情况下执行文件写入、模型拉取与层删除

CWE-862 · UNKNOWN · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：外部调用传入的 ctx、name、modelFileDir 与 commands（该文件被标记为 HTTP 入口 server/images.go）

危险操作：SaveLayers\(layers, fn, false\)（第 474 行）、CreateManifest\(name, configLayer, contentLayers\)（第 485 行）、deleteUnusedLayers\(nil, deleteMap, false\)（第 490 行）以及 PullModel\(ctx, c.Args, ...\)（第 292 行）

防护缺口：函数内未见 ctx 值校验、租户/用户归属检查或按操作区分的能力检查；删除操作仅由 OLLAMA\_NOPRUNE 环境变量控制（第 489 行），不是授权判断

前提：攻击者能访问暴露该入口的 HTTP 监听地址或调用该服务的 API；服务未在其上游路由/中间件中做鉴权，或部署在非可信网络

影响：未授权者可创建/覆盖已存在模型（CreateManifest 使用 name 决定写入路径）、触发远端拉取、并按 deleteMap 逻辑删除本地 blob 层，造成数据完整性破坏与资源消耗；若与上层路径缺陷结合可扩大为任意文件读写

修复：在路由层明确绑定监听地址并显式加入认证/授权中间件；对写操作（创建、覆盖、删除层）做权限判定并在模型名归属上做租户隔离；将删除层等破坏性行为改为需要显式授权开关而非单一环境变量

- 证据：server/images.go L474–476 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	if err := SaveLayers\(layers, fn, false\); err \!= nil { 		return err 	}
- 证据：server/images.go L485–485 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	if err := CreateManifest\(name, configLayer, contentLayers\); err \!= nil {
- 证据：server/images.go L489–492 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	if noprune := os.Getenv\(&quot;OLLAMA\_NOPRUNE&quot;\); noprune == &quot;&quot; { 		if err := deleteUnusedLayers\(nil, deleteMap, false\); err \!= nil { 			return err 		}
- 证据：server/images.go L292–292 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：					if err := PullModel\(ctx, c.Args, &amp;RegistryOptions{}, fn\); err \!= nil {

复核 v2（MODEL，INCONCLUSIVE）：CreateModel\(U0007\) 是库/服务内部的模型构建助手：其签名 \`func CreateModel\(ctx context.Context, name, modelFileDir string, commands \[\]parser.Command, fn ...\)\`（256 行）不含任何身份或权限形参，函数体内确无 ctx 值校验、租户归属或按操作区分的能力检查，参数 name/commands 直接进入 SaveLayers（474 行）、CreateManifest（485 行）与 PullModel（292 行），deleteMap 逻辑还会驱动 deleteUnusedLayers（489-490 行，仅由 OLLAMA\_NOPRUNE 环境变量开关）。就本组件接口而言，写入/删除行为确实只由符号化参数驱动，这一点是 SUPPORTED；但该候选主张的核心是“未授权者可调用”，而授权决策位于本单元之外的调用方（路由/handler）与监听绑定之上——本快照未包含路由注册、中间件或监听地址代码，函数也没有把“当前请求者”作为输入。因此缺少证明“本组件的调用方未做鉴权”的证据，授权属性在本单元无法判定，只能列为待验证的部署条件，不构成已证实的组件内授权缺陷。

反证：函数内无任何鉴权/归属检查可作为防御；删除层仅由环境变量 OLLAMA\_NOPRUNE 控制（489 行），属运维配置而非授权判断；未见任何 caller 检查或能力令牌被传递进该函数。

待补信息：调用方/路由代码、监听地址绑定、是否在上层中间件做认证授权、name 与 modelFileDir 的租户隔离策略；本快照中无 HTTP 路由或 handler，无法确认信任边界上游是否存在鉴权（若上游有鉴权则应 REJECTED）。
静态结论范围：COMPONENT

### GetModel 用清单层摘要构造文件路径并读取，缺少在受审单元内的摘要格式校验

CWE-22 · UNKNOWN · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：不可信 manifest 内容（来自 GetManifest 读取的模型清单，若模型由外部 registry 拉取则层摘要受对端控制；name 由调用方/HTTP 请求传入）

危险操作：server/images.go:209 os.Open\(filename\) 与 188/195/202/220 os.ReadFile\(filename\)，filename 来自 172 行 GetBlobsPath\(layer.Digest\)

防护缺口：受审函数内未见对 layer.Digest 的格式约束（如必须为 sha256:hex 且只取十六进制段），也未在拼接前校验结果仍位于 blobs 根目录之下；GetBlobsPath 与本文件的 ParseModelPath 实体均未提供，无法确认已有清理

前提：攻击者可让受害者拉取/加载含恶意 Digest 字段的模型清单，且 GetBlobsPath 对摘要未做严格白名单或未做 filepath.Clean+前缀校验

影响：可能读取 blobs 目录之外的任意可读文件（模型配置文件被解析/返回，或改变后续模板/参数/许可证内容），构成路径穿越型信息泄露或配置注入

修复：在受审单元内或 GetBlobsPath 处强制校验摘要形如 ^sha256:\[0-9a-f\]{64}$，拒绝含 ../ 或绝对路径的输入，并校验最终路径位于 blobs 根目录内（filepath.Clean 后前缀比较）；补充对 ManifestV2 的 schema 校验后再使用 Digest

- 证据：server/images.go L171–172 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	for \_, layer := range manifest.Layers { 		filename, err := GetBlobsPath\(layer.Digest\)
- 证据：server/images.go L209–218 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：			params, err := os.Open\(filename\) 			if err \!= nil { 				return nil, err 			} 			defer params.Close\(\)  			// parse model options parameters into a map so that we can see which fields have been specified explicitly 			if err = json.NewDecoder\(params\).Decode\(&amp;model.Options\); err \!= nil { 				return nil, err 			}
- 证据：server/images.go L188–193 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：			bts, err := os.ReadFile\(filename\) 			if err \!= nil { 				return nil, err 			}  			model.Template = string\(bts\)

复核 v2（MODEL，INCONCLUSIVE）：在 U0005\(GetModel\) 内部可确认数据流：manifest.Layers 的 Digest\(第172行\)经 GetBlobsPath 生成 filename，再在第188/195/202/209/220行作为 os.ReadFile/os.Open 的目标。但\(1\)GetBlobsPath 的实体在本快照中不存在\(对 &#39;func GetBlobsPath&#39; 的检索无结果，仅有调用点\)，无法确认其是否已做 sha256:hex 白名单、filepath.Clean 或前缀校验；\(2\)Digest 并非 GetModel\(name\) 的直接参数，而是 GetManifest 从本地清单文件\(U0001 第129-153行仅做 json.Unmarshal 与 sha256 计算，未做字段级 schema 校验\)中读取的内容，要令其含 ../ 需要能写本地清单文件或提供恶意 registry 清单，属超出本组件输入边界的能力，未见证据。故既不能确认也不能用相反源码证据反驳。

反证：GetManifest 在读取后计算整个清单的 sha256\(U0001 第146-147行\)并返回 digest，说明部署层可能以摘要做一致性校验；ManifestV2/Layer 为强类型结构体，MediaType 经 switch 分派\(第177-225行\)。但这些都不能替代对 Digest 字符串格式与路径归属的校验，且 GetBlobsPath 的实现未在快照中，无从判断是否已阻止 &#39;../&#39;。

待补信息：GetBlobsPath 的实现\(是否做摘要正则/白名单、filepath.Clean 与前缀比对\)；清单文件 Digest 字段的写入者与可信来源\(本地文件写权限或远端 registry 清单是否受控\)；是否存在对 ManifestV2 的 schema/摘要校验。
静态结论范围：COMPONENT

### realpath 不对 Modelfile 中的路径做目录约束，导致任意本地文件读取

CWE-22 · HIGH · 复核 VALIDATED · 验证 NOT\_RUN

输入：CreateModel 中解析出的命令参数 c.Args（来自用户提交的 Modelfile 的 model/adapter 路径），经 realpath\(modelFileDir, c.Args\) 传入

危险操作：realpath 内部 filepath.Abs\(filepath.Join\(mfDir, from\)\) 与最终 return abspath 的路径解析结果，被调用方用于 os.Open

防护缺口：未验证解析后路径是否仍位于 mfDir/允许目录内；未拒绝以 / 开头的绝对路径或包含 ../ 的相对路径；未做 filepath.Clean 后结合 strings.HasPrefix 的包含性检查；&quot;~/&quot; 分支还会扩展到用户主目录

前提：调用方能够向 CreateModel 提交包含任意 model/adapter 路径的 Modelfile（例如 /api/create 类接口），且进程对该文件有读权限；本地 API 未做认证或受限访问时风险显著提高

影响：可读取服务进程可访问的任意文件（如 /etc/passwd、密钥、其它模型/配置），读取内容随后被 CreateLayer 打包为模型层，可能通过镜像分发/查询接口外泄，造成信息泄露

修复：在 realpath 或调用处统一做路径封闭：Clean 后校验结果必须位于允许的根目录之内（filepath.Rel 不出现 ../ 前缀），显式拒绝绝对路径与符号链接逃逸，去除 &quot;~/&quot; 扩展或仅在受信上下文使用，并对 CreateModel 入口做认证/授权控制

- 证据：server/images.go L248–253 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	if \_, err := os.Stat\(filepath.Join\(mfDir, from\)\); err == nil { 		// this is a file relative to the Modelfile 		return filepath.Join\(mfDir, from\) 	}  	return abspath
- 证据：server/images.go L284–284 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：			bin, err := os.Open\(realpath\(modelFileDir, c.Args\)\)
- 证据：server/images.go L269–271 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	for \_, c := range commands { 		log.Printf\(&quot;\[%s\] - %s&quot;, c.Name, c.Args\) 		mediatype := fmt.Sprintf\(&quot;application/vnd.ollama.image.%s&quot;, c.Name\)
- 证据：server/images.go L380–380 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：			bin, err := os.Open\(realpath\(modelFileDir, c.Args\)\)

复核 v2（MODEL，VALIDATED）：realpath\(mfDir, from\) 对 from 不做目录封闭校验：absPath = filepath.Abs\(from\)（232 行），对绝对路径即原样返回该绝对路径，对含 ../ 的路径即相对进程工作目录解析出的越界路径，随后在 253 行直接 return abspath。唯一存在的检查是 248 行的 os.Stat\(filepath.Join\(mfDir, from\)\)，它只用于判断“是否相对 Modelfile 目录存在”以选择分支，并不限制 from 取值范围；仓库中对 filepath.Rel 的检索无任何结果，也不存在 Clean 后 HasPrefix 的包含性检查，244-245 行的 &quot;~/&quot; 分支还会把路径扩展到用户主目录。U0007 的 284 行与 380 行把 realpath 返回值直接交给 os.Open，且读取内容经 CreateLayer 打包为模型层（U0007:371-377），构成组件边界内“符号化路径输入→越界路径→打开文件”的完整链路。

反证：考虑过的防御：U0006:248 的存在性 Stat（非包含性校验，无法约束绝对路径/越界路径）；U0007:275-282 对 &quot;@&quot; 前缀的 blob 路径解析（仅特例，不影响普通路径）；CreateModel 内未见对 c.Args 的白名单、Clean 或路径前缀校验，也未见符号链接评估或目录根限制。

待补信息：部署层条件未证实：真实 /api/create 类入口是否存在、是否需认证、调用方能否控制 Modelfile 的 model/adapter 参数（组件契约将其视为符号化输入）；被读取文件需存在且进程有读权限（普通运行前提）。这些条件决定实际可利用范围，但不改变本组件边界内的静态结论。
静态结论范围：COMPONENT

### CopyModel 将解析后的目标模型名直接映射为文件路径并写入，缺少路径边界校验

CWE-22 · UNKNOWN · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：CopyModel 的参数 src、dest（第 670 行），来自调用方的模型名/标签字符串；query\_graph 未返回任何入边，调用者未在快照中给出，实际来源为未知外部输入

危险操作：os.WriteFile\(destPath, input, 0o644\) 以及前置的 os.ReadFile\(srcPath\)、os.MkdirAll\(filepath.Dir\(destPath\), 0o755\)

防护缺口：在把 dest/src 交给文件系统操作之前，未见对解析结果做显式路径规范化与基目录约束（如 filepath.Clean 后校验是否仍在模型存储根目录内、拒绝绝对路径/符号链接）。该判断只能依赖未提供的 ParseModelPath/GetManifestPath 实现，属显式缺口

前提：调用方能够控制 CopyModel 的 src/dest 字符串，且 ParseModelPath/GetManifestPath 未净化 &#39;../&#39; 或绝对路径；进程对该路径有写权限

影响：若解析函数不设边界，攻击者可借 dest 指定任意可写路径，导致越界文件写入或覆盖（0o644 覆盖已有文件），src 侧则可越界读取文件内容并复制到目标地址，形成文件读取/写入原语

修复：在 CopyModel 内部对 srcPath/destPath 做 filepath.Clean 与根目录前缀校验，拒绝绝对路径、&#39;..&#39; 与符号链接；或确保 ParseModelPath/GetManifestPath 集中实现并返回受限路径，并补充相应单元测试

- 证据：server/images.go L693–693 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	err = os.WriteFile\(destPath, input, 0o644\)
- 证据：server/images.go L677–678 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	destModelPath := ParseModelPath\(dest\) 	destPath, err := destModelPath.GetManifestPath\(\)
- 证据：server/images.go L682–682 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	if err := os.MkdirAll\(filepath.Dir\(destPath\), 0o755\); err \!= nil {
- 证据：server/images.go L687–687 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	input, err := os.ReadFile\(srcPath\)

复核 v2（MODEL，INCONCLUSIVE）：在 U0015 内部可确认：函数参数 src/dest（第 670 行）经 ParseModelPath（671、677 行）→GetManifestPath（672、678 行）转换后，其返回值路径直接进入 os.MkdirAll\(filepath.Dir\(destPath\)\)（682 行）、os.ReadFile\(srcPath\)（687 行）与 os.WriteFile\(destPath, input, 0o644\)（693 行），即组件边界上的符号输入确实到达了文件系统读写/创建目录动作，本组件内未出现 filepath.Clean、基目录前缀校验、绝对路径或 &#39;..&#39; 过滤等可见防护。但路径边界的真正决定者是 ParseModelPath 与 GetManifestPath 的实现，本次快照内未提供这两个函数的源码（search\_code 仅返回调用点，无定义），因此无法判定 dest/src 能否被用来逃出模型存储根目录：既不能确认存在路径穿越，也不能确认已被规范化拦截。故为缺失证据导致的不确定结论，而非已验证漏洞。

反证：本组件内未见任何显式净化（无 filepath.Clean、无根前缀比较、无绝对路径/符号链接拒绝）；但防护可能集中在未提供的 ParseModelPath/GetManifestPath 中集中实现，快照无法排除这一点。写入使用固定权限 0o644、错误路径均 return err，但这些不构成路径约束。

待补信息：1\) ParseModelPath 的完整实现（是否拒绝 &#39;..&#39;、绝对路径、路径分隔符，是否做 filepath.Clean 与根目录拼接）；2\) GetManifestPath 的完整实现（返回值是否恒被限制在模型存储根目录下）；3\) 该组件在部署中的调用方与 src/dest 的实际来源（query\_graph 未返回入边）。在上述实现缺失前，无法把该组件判定为路径穿越漏洞。
静态结论范围：COMPONENT

### PruneDirectory 递归删除时未校验路径是否被限制在数据根目录内

CWE-22 · LOW · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：调用方传入的 path 参数（第 796 行），调用点在第 809 行用 filepath.Join\(path, entry.Name\(\)\) 递归下传；本快照中未发现外部调用者，也未发现与 HTTP 请求字段的直接绑定，输入可控性未知。

危险操作：第 823 行 os.Remove\(path\) 删除目录（在第 819 行确认目录为空后执行）。

防护缺口：缺少对 path 的规范绝对路径与允许根目录（例如 GetBlobsPath 返回的 blobs 根）之间的前缀/包含性校验，也未使用 filepath.Clean 后比较；函数自身只做 os.Lstat/IsDir/空目录判断，不验证删除目标是否位于预期根内。

前提：存在一个调用方（本文件之外）把由外部数据拼接得到的路径传入 PruneDirectory；目标路径解析后为空目录；进程具备相应文件系统删除权限。

影响：可删除目标目录树中的空目录（含父级空目录被自底向上清理），造成数据根之外的目录结构破坏；无法删除非空目录，且不跟随符号链接，因此不能直接删除任意文件内容。

修复：在入口处将 path 解析为绝对路径并与允许根目录做包含性校验（拒绝逃逸、拒绝根外路径），或改为只接受已校验相对名并在内部拼接；对递归深度设上限以避免极深目录导致栈增长。

- 证据：server/images.go L823–823 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：		return os.Remove\(path\)
- 证据：server/images.go L809–809 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：			if err := PruneDirectory\(filepath.Join\(path, entry.Name\(\)\)\); err \!= nil {
- 证据：server/images.go L797–802 ；产物 61561fde-7765-47d8-9c5f-1764cc174edb；引用：	info, err := os.Lstat\(path\) 	if err \!= nil { 		return err 	}  	if info.IsDir\(\) &amp;&amp; info.Mode\(\)&amp;os.ModeSymlink == 0 {

## 关键逻辑与人工修订

- u\_3cf64280cd22241a99770bb57ce8cdd7 · CRYPTOGRAPHY · v1（MODEL）：GetManifest 对被读取的清单字节做 sha256 摘要作为模型 Digest（完整性标识，非密钥派生），属被审函数调用的哈希运算；此处用途与实现可直接从源码确认。
  - 原文：server/images.go L146-L147；	shaSum := sha256.Sum256\(bts\) 	shaStr := hex.EncodeToString\(shaSum\[:\]\)

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
  "audit_coverage_gap": "共 30 个可读单元，完成 5 个单元的语义审计；其余未审计",
  "audited_unit_count": 5,
  "edge_count": 339,
  "eligible_unit_count": 30,
  "exclusions": [],
  "files": [
    {
      "language": "go",
      "path": "server/images.go",
      "reason": "",
      "status": "PARSED",
      "unit_count": 30
    }
  ],
  "finding_count": 6,
  "function_count": 29,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "PARTIAL",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 29,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "f1f36734d630259adb5e33889533543aa17d57284820860bb018ff9da499c9f0",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 100,
    "cost_cny": null,
    "measured_tokens": 485519,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "61561fde-7765-47d8-9c5f-1764cc174edb",
  "reviewed_finding_count": 5,
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
      "finished_at": "2026-09-11T09:39:44.925Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T09:39:44.901Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 30,
  "unresolved_calls": 298,
  "verification": "NOT_RUN",
  "vulnerability_audit": "PARTIAL",
  "warnings": []
}
```

任务错误：智能体响应再次未通过校验：智能体结果结构无效：invalid type: sequence, expected a string

## 证据产物

- aegis-report-cb6c44d5-4230-413b-bccc-5d65cfb13010.html；ID：6b30db27-a938-4a80-acd2-459975d82347；SHA-256：e0e00630a08a93637a9cdd4cea5d44c09cbb72045921fefcac183ea369aa494b
- aegis-report-cb6c44d5-4230-413b-bccc-5d65cfb13010.json；ID：901b8494-fcaf-411d-95ff-c2c881e780e5；SHA-256：8ed7c9d97f0eac93ef1d88f162dc16255e9b9f526e6d6b4c85758d55176d7834
- agent-AUDITOR-48910311-5290-4968-86e2-2c3c326cbf0e.json；ID：16b25498-0292-44c2-a129-0d631da21372；SHA-256：dc6f75048ea0b9740c796d4dc96334b211a10668fbe282bb863ed3d39e543ea9
- agent-AUDITOR-8d5f817c-28ba-4e7e-a627-38b36e16502a.json；ID：8090a42e-22f7-46c0-afdc-ee2d4886125d；SHA-256：8f4cc4222d88a5baefb26037af516dd8040b60fffe80a2865cf80b5f321173bd
- agent-AUDITOR-98b214f9-9bc9-44a8-ba59-b03e3fc48b31.json；ID：d9f07c18-64f8-428d-9fc8-ffc3e23509aa；SHA-256：447870267a7d012a14f14c12c64950e87c871561cfec9a0d39edf7dfdf8a09b1
- agent-AUDITOR-b8418188-d3b2-4ee4-82f6-9df623507724.json；ID：61e85bd1-d8a7-4046-9f4b-3712c2aaa1eb；SHA-256：ad4065385302852fef63f122deeb8799b4f7e581d822e7d64242591a72b15bb3
- agent-AUDITOR-f25f1b71-aa7d-48f4-bfae-7c1bc095ec89.json；ID：8e907587-3190-40c5-8f94-d399a39f4f00；SHA-256：f87d3613c68f48ede7c5121222a1dc458369297aa53bacdc63785f358a5669eb
- agent-PLANNER-122874a5-295d-4a95-be52-948f981c510b.json；ID：cd05e456-0c36-430f-9338-7ea07e26731c；SHA-256：65dc70b3f55ea02f0cbbf10246772eb4b6e0b3d5206b02fc1017e476fde2a26f
- agent-REVIEWER-4761f2bd-f353-4430-aa85-9b8bc228c6aa.json；ID：cd7aa1a6-3a74-45c0-b101-9495c70d1b6f；SHA-256：11775eb6d6f3ef8e638c61e06982406757cc194cc5a9b09ab8e357fa7e48ec39
- agent-REVIEWER-961806a5-5955-40a8-8a19-bdb0f458e3e4.json；ID：6c6a3e05-69c3-4321-9e51-3dd7fea25d55；SHA-256：54c00756d47ff3215c34dc0dc512fbd83a3f5719e82517e8118eae0c48d79b46
- agent-REVIEWER-c170c1d5-28d1-4e76-a63a-90fc331939f4.json；ID：21511128-b16f-4905-970a-ba30a02bcb08；SHA-256：3e8be2f3992a7aa73f37315adfa87d28c99885a6f72f17aa21c000af124e8eb1
- agent-REVIEWER-d0bcd814-ec41-4609-885b-bdd79b113597.json；ID：430499af-e003-4ab5-aafa-3d0796e45652；SHA-256：73bd8157656d10865a3f59ac5ab0152cf3bb53263e7569dda70981f661d0635f
- agent-REVIEWER-d46d1dc5-8a3f-45a6-aa68-b0646ad5f7ef.json；ID：d16925e0-4dbd-4b5f-89da-0d9a842d9ba0；SHA-256：870c14a93d1dc55a2e8c2430cbf126e29af505bacebea17a3e00502bb5ddfcb2
- analysis-result.json；ID：61561fde-7765-47d8-9c5f-1764cc174edb；SHA-256：a78d2fdf2915ad042cfca5f4c777b05664be77400e08c104f1a1e6f1e0dc7659
- model-request-001b40d4-a1f8-4604-9b3b-20fdd6c91888.json；ID：033ded3e-529c-48c3-8ba9-6ae5632d10f0；SHA-256：bcd9e95e3fc351b31b3e3468eedb909b5ff7759481bb91d03bdb1590049bde78
- model-request-05c90041-ec57-451e-980f-8cec8e3c3168.json；ID：65d4fc0b-d113-410e-b2fa-bff08a09ad9e；SHA-256：ed4772d87c27c2c3835205ab348278a19733dd07b64b4e0c679f9cb63b0872c1
- model-request-06f4c70c-6c9b-451b-8bea-ba9cb445abd4.json；ID：f14a3a31-c124-419b-b84b-7a18643ec520；SHA-256：5f973a5de6e5a1ed07856734cee30b38384aa140797312b1e298ec3edfbaea72
- model-request-076504c3-6db4-4d41-b44b-6dd95c651772.json；ID：e252a22e-1e58-4e1c-b0e3-2e0d2471933b；SHA-256：af63496e628992ca5a954da0420b66f1692c573f01c77dbe6ff50dea85c16ef7
- model-request-095b4e44-0ed5-4b02-9ea6-03535cdbf751.json；ID：e91982d2-0913-4c76-8b6d-ebc5a17d238c；SHA-256：147b6b7316b86ddd9c605a469cfb181754c5b2b635b4f3ebb3914221155aee73
- model-request-0e23a9b8-f6bd-4095-bb7a-8e090dec02de.json；ID：9d000c78-0990-4456-8a11-c8a6f9523042；SHA-256：6aa3b4d0d9d0541bd56126d1c5ab8f739167500b9c446d77da4c1daf3c8b5b55
- model-request-10b38fd0-8182-4c0d-9c4a-c797ec0380e8.json；ID：e224dda8-f074-4b9a-a155-b67423d627da；SHA-256：966b7469944286c7c5874d8b34477b1c65469ea2c8cc22697cf831bc643ba8af
- model-request-115792b2-dbba-4d09-90ea-6ce627cb3553.json；ID：833db70a-6435-4048-b36b-f735fdc45103；SHA-256：f56e60f027075fc0d5fb24f2fdef351075073dae44cffa243a3e3b08e5a9d612
- model-request-12a9db70-4cdf-410d-b1f4-1abf8737cd5c.json；ID：ec6bbfb6-e3b1-47cf-8027-2a17d7e7b1a0；SHA-256：72fd8d1d6192f2196ede5098ab17235cdb0f7d17aa364033744bf32936543af2
- model-request-14998e8e-80ac-4a4f-a6a4-2479b052f42b.json；ID：5c2d0585-71d2-4b06-943a-2969d0ad5a45；SHA-256：1c95ff09cce94a4a5515fc667491b6be8007129ab5269dc004a6f493967a6d48
- model-request-169052ec-8d76-4418-9f8a-566f1859dfa1.json；ID：f0b9b074-b7ed-4dcb-8731-541fa2072c4a；SHA-256：e8cc98e85d655aff22b18285bdf12237d3da4900677a76d3a0fac6e7717be71e
- model-request-182d5c4f-7d82-4ee3-8c5b-121f1d8a6135.json；ID：f242efd8-e1ef-4448-a068-b3e14e5b08d2；SHA-256：589d6803cd21ad2ae0e98b78fe6f36ca367ae42eedd5ae3877ee7be07d90e4fe
- model-request-18b44a89-9eb7-47c8-acfc-bf237f6c316a.json；ID：40227812-8da1-4493-a942-99021f0b7194；SHA-256：8ac787d33081d8ea884ce08c05aaea8dd5cb94c36f7608d684f8436d4f07588b
- model-request-1d5883aa-0b39-45d0-8b07-f7168141d176.json；ID：2df37e69-d7f2-4aec-9b6d-923cf7b1b68a；SHA-256：9c07ba5feb40e9fea3e01484c3a1e606121032b98832c50ca82fc33bb1b7725a
- model-request-1dc09be7-3ef5-4dc2-b617-51778c583c42.json；ID：7e377edb-261e-4215-b838-5a9b4c2c664d；SHA-256：f9e2f930e4d440bd48130328ffc53b803c9e1155314104251a810cc7f8b02a8a
- model-request-25b4697d-c815-46c8-82e7-6df24ea52285.json；ID：effecec5-8154-4223-983e-df399ea0c05f；SHA-256：9b838968eef056a2ab566037e735f1165e4d65f3723e7e09c4600fc87b8698a3
- model-request-2679d379-7fc1-4d27-9b76-bb9e096c4602.json；ID：099ebbe7-c5e4-403f-9928-11d720e11dbd；SHA-256：0844f4cc01873062f5e41e9515dc0a1417cd2062ffe7363d6f881c70e6d43cb8
- model-request-26df131b-5a53-4c80-b67d-8fa2a1e1c7f9.json；ID：9de8f5cd-0584-42a6-b01d-db099c27cd26；SHA-256：6452404fa8f10c8814648e6c3369ed64fa41b0206a0c8e70e6969e20fad023f5
- model-request-2a455297-b570-4650-9972-f9c3857df436.json；ID：fcd73a45-3385-4c15-a6ad-d84d3fbb4132；SHA-256：136795e7249143f403decdb0bd7ec6c23c73bbc317b005772aa64cd9452120c4
- model-request-2c948337-7633-465e-ae07-f88f7374f330.json；ID：87f11aed-f779-4da5-8958-d8877fc6b87d；SHA-256：7d1a92e962d444acb85143d32fc39dfdb72b9e3caebcf9ab10bd9712ac4ae79f
- model-request-2e16c1e4-e221-451c-b0fe-22b286881bc4.json；ID：cc6d4137-8435-4068-9ccf-df5252c78683；SHA-256：c87283a51b19f4eda00f306e0b9db3edb52bb9549aa24b0799e84f0db4f83a61
- model-request-2f5f0fb1-5201-4590-891e-ee2dcc92b632.json；ID：b6a9bda5-ff42-4f05-bfd8-d488d18cbfc4；SHA-256：40e2f6b784aa1a07fb66a75716fbb2df3385548f89da553f9181bb0ea4b6321d
- model-request-330d4009-162a-4f4b-8b2c-40ca6a29d676.json；ID：575ebf6a-a236-421c-9d17-23aa9be9e95c；SHA-256：7205b26822b91a1f62813434169a95d7a07a471451170d162ff4509625113432
- model-request-35bd880a-3b3d-4a3e-8baa-71913bc8e5fd.json；ID：d160b035-f58c-4fff-91fb-6e1343f3da61；SHA-256：a6dd282d46e465b6bbdf6ddeef6758ccc3d204c3b55a3c62e7f048b5f0191711
- model-request-36e0120e-7f8c-4dbf-89e6-c5ab9bf1b083.json；ID：69e9d245-37b0-45d1-a7d2-3fad3d4fbcd3；SHA-256：d78f41373e9098578184cbf98fd5bd995aba908c38141a59e482092387a41205
- model-request-3826ab17-7e9d-4b4d-a1ff-2fb5da8ada1d.json；ID：c33ea232-ce30-4491-bf98-93c98ea19128；SHA-256：4738003ccb6b28b21e0965276c20d83afd501b79a7c82106dc572d4ebcd70143
- model-request-3907c97c-db3e-4dbc-bf14-e80e2ec7094d.json；ID：6125cd85-ff7b-4841-970a-f65129f1b37b；SHA-256：1e1caf44735e3834a74a5fc5038d486a9fcff548ba646ffbde2c90eff9db5284
- model-request-3bdc495c-0177-4e20-80bd-379fd599a005.json；ID：8afb626b-078b-4db6-9177-182df3ee2d61；SHA-256：503d045bf62bba7b3c13dc45e97541cab245fdc77fb2237a595cf19995c52b02
- model-request-3c543bce-c808-4768-a1db-482362704736.json；ID：d0a5e122-4b0e-4336-8da8-633db7e439a3；SHA-256：8355b6ac99b77f5567c7587777f4e7a6b761466ca1f73080d9051817a73ef52e
- model-request-4104dd2e-b45f-4d0a-871c-547a67043d15.json；ID：36fe16db-1775-4a84-8130-8cdb914cfede；SHA-256：44c177a44f596a5c697c2e9f6b5d90094a897fc3f69d864f6bc6947d515e1560
- model-request-412d2cc9-f66a-4e0a-b14f-65bb85dd1adf.json；ID：e613acd3-7851-40fa-8941-969c35bb1a72；SHA-256：5f59f821dfe69cb93037b52bfe2a4a566b8ec954987303b5e5c0d079fd79fada
- model-request-42d055bc-4f89-48b3-85dc-ee330c594dd3.json；ID：98ce631c-ba91-404c-ba7a-c1d3036409cd；SHA-256：9eb5d11f8245c2e691bd125ecf07c4f50fcd56ee0250070934be5e26114dea64
- model-request-460e4edf-8c4d-4b0f-8ca0-de8573715fa5.json；ID：38c935fa-8347-4345-8d4d-dedda346f24e；SHA-256：dbf3367cb95bef7b5173cffc6775a3c38500e1568b9e38c59e11c9e2c577c73c
- model-request-4782e09f-2736-43b7-b6a1-2fd3dbf2d8b4.json；ID：bc5b2a7f-e8f5-4cb7-8095-388d4d76943e；SHA-256：031b035225d05d0b31a1916cee9695000453eef2e81517de3f542b5171543426
- model-request-48785f22-6a98-4779-9c5d-576a09dca939.json；ID：9c84561b-970b-4130-8876-622fbaaf0b22；SHA-256：053e7e2b8bb954079791cdd070336c16077c25cf9dbb556fb1af83ac13b436b2
- model-request-4ccab715-74b7-4ecb-a895-1b26b3c20af8.json；ID：cebafafd-4cdc-4998-be95-55be3ad9c6c2；SHA-256：8e249b81b5ecfb14140b09f4bfcd8fbd3c046426bd2baf89a3b64066ae8fb8ad
- model-request-4fd9d58d-f3eb-4d19-94dc-0072190f4b5d.json；ID：12b24c9b-066a-49aa-b0fd-32c31357da6c；SHA-256：dad70d9dc7330f0c75f600ceb32741f5fd2ff7ca121e00b83884d218e4dd369d
- model-request-51e8ebab-5176-454d-88f9-4d7302f8045a.json；ID：e8eefaee-7a94-4bb6-b415-a96e67210c83；SHA-256：d9b3d16af7a671269ccf1519a993a83d9190ef674f40296772262031c6ed5d74
- model-request-5241a182-1861-406c-ae53-b60c073e37ea.json；ID：41830da7-7377-412d-a1de-f78d83d3c650；SHA-256：d8fb5c07b0beebef7ef612e9167389f91d1622597748c78684ec39d426719870
- model-request-529de909-d035-49bc-bee9-b11d12a0f003.json；ID：8d225975-de04-4518-99db-8fc968587d89；SHA-256：c51aaf225d191fcfc1f70cd049f6f09d767b97689612604804d3b708a36428bb
- model-request-5710b1f9-f701-4b09-8a42-b669616d2491.json；ID：bba9f761-deb0-4ee9-9601-1e61c1828d10；SHA-256：dcd4ce382613f9aafb3808ce093f323fbdca5ddc713603a4f57dcd40fb103af1
- model-request-58542f47-19d9-4649-ab41-c37e3582e155.json；ID：690bc1be-96fc-4a3f-90b1-a423ace04183；SHA-256：9161e090847d3d45274a32535b212428a3dc4b0345e569a80f579e7b320a56f9
- model-request-58b8fa9e-2358-47b3-90af-5cb08ba36e4a.json；ID：65ee057d-a27b-48a6-a904-7496cb11e0d0；SHA-256：807922e495a5c7df49548f4e05c310acc2d142519fda54e25d25627612383755
- model-request-58c7e4fe-6403-47e6-a56c-85be01365bc3.json；ID：2948466f-8513-42bf-ae61-e5cd212d242f；SHA-256：d6990feba15a743c7b4c5db7dbc03a8226fbfa9feac780684ed7b64e7689ce55
- model-request-5a9739a2-570e-4acf-bec8-dd00e5d402cb.json；ID：ceaa8139-2590-438d-b7ca-bf6e8eb230a6；SHA-256：e5557ec03363547163c6cc356622b55678c5f99c4788188c67a12a87ed866767
- model-request-5bdcc2cc-c12d-4529-8c27-4dcb671f2d07.json；ID：0f791475-8d98-4702-bc45-35160d430220；SHA-256：446181c100654d3f3282674977cfc050667826fd4459e4190bad3347931e2b21
- model-request-5d20e092-9059-4d95-b37e-5731644b8d6c.json；ID：e0049a84-202b-4b27-ad72-a09cb7fa84b2；SHA-256：6c3451b14800ff3d6f9170fef5611df6dffe2758721da32c76694f92bf4547c7
- model-request-5f7909e5-d0b7-404a-9199-1f7dbfc6dc94.json；ID：925b3bcb-d4bc-49d4-924b-fb9700bf0857；SHA-256：5bf20a20ed4053d5c280bd0a7e339201919172e6b30128d041b4ebd13ae2168d
- model-request-629560e9-2f99-46f5-93d5-cce0fccb1c88.json；ID：8ffb06ae-b22b-4761-9895-17413a940750；SHA-256：3511916536b8c292e6d5a6133c27a9ecd1de1c0bbbbacb20d4501237017c66e2
- model-request-683fbdb6-17a9-42eb-b1b6-54d59ccb4298.json；ID：b6013b77-55c8-4817-a0b8-08cdee0d0eae；SHA-256：3705a67ebd58c2b3c54053a8a1b5e17fa8c52c66199b0a74ec982f80332f61f8
- model-request-6c468f80-0428-4e0d-975c-8a5239cff4f4.json；ID：2eca2f64-3ca2-4c8a-94ff-772b19b34734；SHA-256：98cca62802c4266573d50b1503b65edfa7abcae44cfa0e25e309835fe2fc7947
- model-request-70ce0344-10a8-4841-bf10-084ba1c39b29.json；ID：ed01f3bb-f0e5-487e-940a-923fe023822c；SHA-256：67fad6d463a4fb5f4c7c1ce40f6db28df13fa4a7bf79b3354cea5e60f8dab032
- model-request-77e7eb5d-8c38-4e9f-9dc9-11db857951c7.json；ID：39f21cf1-790c-4dc4-a90c-ae0ded9215e9；SHA-256：14a2d8cad8f392574a78bcd613103f0d728b9bc60d9eefa5951506f3a4333135
- model-request-798d2a6e-f6fc-4132-beca-9b7566c04416.json；ID：e8e9dd9e-5134-4d15-89d0-77eb29c80659；SHA-256：c6bf2cd81bbfdb65a562dadf03265fbe13ad94f2f031122d30b895fbe8aa0dbc
- model-request-8e29b11e-8cb6-45f1-9afe-4d9a110ddb00.json；ID：9133bae8-7302-460a-8305-8dea445bc3b8；SHA-256：e24a2dac537f9ad00690fa593c9995203c03fe9afe02a46e1a9b011d58905ccc
- model-request-8f7309e8-40c4-4562-b967-217262181348.json；ID：d57befdc-ca9f-4ef5-8a16-7e5987b6236e；SHA-256：0535fae876a2886310fd6ddd63690c3f9571bfcda65ae2b93f2681a8f1d8293a
- model-request-916fafe3-3d74-4b82-aa50-8cb173985028.json；ID：7ed67b95-8edf-4919-9c19-fe84bf31c8b6；SHA-256：6033b69d25825cbf05da8425d4daf03c5c1aa5333b7db7b4a5a0f12eaf6277b6
- model-request-996b6528-2a2b-4c92-b5a1-99bf6e124dd4.json；ID：122b2e5d-5d83-4f6f-9eb0-dcbf0a702d30；SHA-256：eef16ac55696e8246a4db149186bab892b40c21c837b59b00a94c7a82265545f
- model-request-9b0937b6-b27e-4eb5-ba85-1741401cb73f.json；ID：f6bdc27d-13bc-41fe-9df1-476cac8e4811；SHA-256：d42272acbf789a8942b3a6e81f8d0231dff33c7bff0cc6a539177075b63e4724
- model-request-9d57e9fe-9fae-44ff-920e-af88bcaf709b.json；ID：3d6e832f-a260-490a-ae54-4a48b356c2fd；SHA-256：a6911c0249265b5bdf308b08727a5cd926aa1946b809157c1f1205f51744aa45
- model-request-9fe626bf-adec-489c-bcd6-3128b0037ab1.json；ID：35be66f0-7e5b-4b90-a23d-00af4808eca4；SHA-256：34fbdc8ef8eb228e9e1f72d176cee7417dd32c17a31d34a170f889528502df2d
- model-request-a6611d0a-7752-450f-831f-959634e00d6d.json；ID：622c77e1-ccaf-44c0-937c-17b1dafe2d01；SHA-256：b3e649da2fe5f1b6d73538232ed6a3c423304be4671431233bbbaefa820fd944
- model-request-a7b18e7a-6ca7-4fd4-8557-ef5f25da53cf.json；ID：59f4732e-a4e4-462d-a948-875f2cd3853b；SHA-256：15e16a52985d722c802b8938afb2b16f6e3995ded63954c6b1144efa24ba53bb
- model-request-a7c33c1d-ea2e-447a-9022-32236125a9b2.json；ID：2a98b5dd-89d7-4999-9fe9-f8cdf6bab215；SHA-256：4371d5b8f0ed7d0e684efdec099eadf5c93ce08269b833053f32a1d7b57097b7
- model-request-a82d53ab-69bd-4c37-a2ba-ccccfd142558.json；ID：0626f379-0688-4a8c-8443-81d3669d2108；SHA-256：0d12047d701a8832d26280f2a8067400d46a3c68dac9ec65531da1ee6c8fefe3
- model-request-aacfcb63-ed14-45d3-bb85-a1602d262ae8.json；ID：ba615f58-f0e5-46b0-a4b4-235ec50c81c2；SHA-256：f79ed17da2b02a212f946fef83f43c3ccad00fb64a08e6efd499d47912fe823c
- model-request-b27f207d-7799-435f-8e11-3a7568fa5ff2.json；ID：b2d29c67-da6a-4e1e-a6db-2193030e8817；SHA-256：9af335ae95337ec6cb8750f4b212b43fce2ffd0f73223362b118114012f8aa01
- model-request-b6b5ff5c-dcc5-45bb-b04e-8b70d6a7c77d.json；ID：9496cedd-8b21-4da6-9a20-337f0c8b8fdc；SHA-256：3e3af8422adab0a4f6b5b2c7becef0ea13dd099db792b2dcdc4ea4713c6f0a67
- model-request-b7367460-5d05-4fef-ae81-e6e2ee48df69.json；ID：99bf820a-b6c3-4823-bdeb-b875891cc996；SHA-256：5331e1abaa50e8e7129f05d6260978f7671b103da806eccc80cd102b9a4ea662
- model-request-b761b22f-b868-41ca-a13b-5750d015e0cb.json；ID：fc16a9a8-1577-4518-988f-fe1accc3e5f0；SHA-256：2d1495a6c1c18cd24700a97da8b256521c9570de52a198f7ff607f0b1234bae8
- model-request-b81c61b2-9a37-403a-93b9-223ce900327a.json；ID：b79a7c69-45ff-4070-85e7-a58d3686bf20；SHA-256：f8ab4c6ec500418b54a2c226d59185a7fb5ae875bb1ba50e87246e82adbfe98b
- model-request-b92a358f-022b-4da4-ad62-c2add9a6cde6.json；ID：7f7cdd54-0e3f-4fa3-967c-29ea27a60c1f；SHA-256：8782b28ae6973bfbf270d0dcf296293b5c526e65ba3afe5e428067f4c371c51f
- model-request-baa7482a-1455-4a0a-9697-29bfa459a361.json；ID：6f850421-f612-440c-aca0-ee85fd730ee0；SHA-256：b7f79f21f46b3aaf463fd1a4c288cea5dc1f09517f42cfea6a5a3ed4d3f30ceb
- model-request-bacb06f7-51bf-4ea2-83fc-640392227389.json；ID：80400fcf-2204-491e-9bf5-95ccb927cc9a；SHA-256：410eaf5a301a604db27696b16e627aae6e9ef85869fc0ab8a9d81b20ef00c391
- model-request-bc70b295-188c-405d-b1dd-aee7629571a1.json；ID：fe70cb67-9437-4ce7-9e61-9760206f88d6；SHA-256：cc0ac107cc799866d6437766d00d6152b8b5227415da721129e061d0ae02d562
- model-request-bd66f27b-fa76-46c5-829c-a0a3c9ea8279.json；ID：c4eeaa3e-a0d8-4491-b080-bb67e9bf18d3；SHA-256：337fa4279a70d7cdd439fa0498d1ccaaf42e47744f90327e9adf49c0afdea34b
- model-request-bdd979c8-af96-45cb-a968-dfadbc33d0ad.json；ID：45aa1d5e-9d13-4d66-93c8-db5f045e180f；SHA-256：4406d159df017709422f936729e226d28f874e0a47c4f5d74d1acef2ba30dc61
- model-request-c046a251-5d9f-4147-b5bc-7fd88389555d.json；ID：252537c1-3ac5-420c-9bd3-edb00231f20c；SHA-256：51612ed65f7b7e11a06066d509df4f3a49f7a0969e5505fcb02da0e78dd08111
- model-request-c242ebce-37d5-4684-bba1-eb2ad278eb8e.json；ID：68418145-3b69-40a8-85a0-119296bceb22；SHA-256：a3f91bbc79a3aae8fea5c576ee343c09bdc26af9dceb53235f2fad6e7511f92c
- model-request-c565aaca-9223-455d-b38b-6ab824a16fd9.json；ID：03c68a33-ea31-4155-ba37-6984e67ac354；SHA-256：7efaee4c2835e69464d38831ed9a6bb1857e85ccd50720403db29c1c586b7174
- model-request-c570a392-9739-4238-ae8e-30ad6f62e9b4.json；ID：3955a77a-8fb6-435f-b05d-99acbf1b1cf8；SHA-256：23a06e712d2f1b235014860b54e207b196c108bb62562c4ab3147fb773922be0
- model-request-c8f4fd86-c6ba-4a41-a2dd-70e14b458ca6.json；ID：fa006dc4-428d-42b2-80b3-4354e2a848c9；SHA-256：90d16a1f439ea63843d9323bb4783d7d45dc7b4b5c0e0fc856878601493a6fc4
- model-request-c9431acb-ccad-4362-be07-867269e1bb40.json；ID：2d3b5686-1a52-4962-a2a7-1df194ab78e0；SHA-256：47fdd36295f9bc6adbff14f155fc405fcd0e1c7c67d5872ba34eb1ad616db388
- model-request-c98207db-1f0a-448e-af77-99b155c43dee.json；ID：54e512e4-e65e-45ca-bd28-abf79fa5df63；SHA-256：a7cf6175b23d71761829a17a9bcdc498b71f1ce847729037d0e17a03ee0abd0c
- model-request-cbb21998-bccb-4877-8639-6d96beb02a83.json；ID：57e5b003-b62f-4ee9-b2ff-589e5938a38f；SHA-256：38725cd340ae9f5c16f229c02b3aa3cb2ef36d998936dadc73ca616b6f705763
- model-request-ccf4f545-7231-4501-8495-2877d80b7471.json；ID：01b98cba-fa15-45af-9e18-7171304507c6；SHA-256：2ecd545db11fb35035a58addaa31f5b900359cb6c36abdab8b48f4a46a69406a
- model-request-cf463c41-4935-4a70-9ac2-22a54f68a577.json；ID：566943f6-fdfe-4d00-84c5-73cb2d06e0b5；SHA-256：1feef7dcad9cc9fc5fed6df58f78d45eb7c7283cc248d17b07a2b478054083f3
- model-request-d0a52c91-053a-4099-b0f7-aca445a16602.json；ID：bc02852b-b6ec-4ed9-bead-09e051f1b417；SHA-256：28fed0219b80f684a1befd7d45f743571e5d4a84a26853f5eea297245c0099fa
- model-request-d55bd9f5-4159-4ef8-a473-25c83f0824f0.json；ID：f52e348c-2002-4961-b888-bb5a4753afaa；SHA-256：44244ae7d62fe3dde30e3296c51f1c3a52b019c2e8b815dbaa098bc81b54eab3
- model-request-d67cea6b-f5cf-4fb1-a8dc-990d128baa41.json；ID：a46fff92-acda-4549-8eea-c336bbee74d4；SHA-256：3825c5aacab163abc4c845032877ea751af57eede7a0f7f1811b0f2a49e756f0
- model-request-da397100-30e6-49d9-bd4d-d519c80c2e3b.json；ID：5f917473-4c52-4681-8b6b-05b629c30357；SHA-256：00a291324141cae1d5c985826d0ddf434a28d8f572677513872f65dbd014e949
- model-request-dc8b8ab8-d705-4018-aa64-e8f4282b8112.json；ID：f2b38bd5-b64e-4d2e-bc00-7be3c7927441；SHA-256：cd399f44f1affcdfe0af24e2ac28438389587cebc540fce7ba7d520a3ec04b2b
- model-request-dd2319bf-32ae-4476-a848-c3bf9da7d1b1.json；ID：63533023-96e2-4c6d-b252-a5edaf34dc3c；SHA-256：114f41d39755d3f5907420a1587de090127dd3f58e302a90e1462d2bdfe419bd
- model-request-de5b3c74-7bf1-41f2-8ccd-7d799778cf5e.json；ID：b96824e7-6ee8-4139-91ec-67283757a28b；SHA-256：c6708faada99872e25fce9f33dfaa7dd9a44e5123d2bb6d185c574a048811a29
- model-request-e222a93f-11c2-4b4f-9073-65a026fc1372.json；ID：c048f9a9-41dd-4305-8c31-50e0ab158a1a；SHA-256：3bca294cf1a956dd8ab47c972c81b07bb136ffa2003d5ab34eeb5eeb4c6af75d
- model-request-e3b83d8d-bbd5-4cc4-9457-d89c19a64aaa.json；ID：1d6bcd13-f87a-4df5-bc38-7ecc330d85b6；SHA-256：d0168f1130d6f2742807de3abafe38618008a4ebedbbc66242eb4feea2cb8770
- model-request-eefe2eff-2519-4bb0-a558-2d0a7601827d.json；ID：00af482c-58d6-447f-b836-ceddf3345dd5；SHA-256：631a4a280cc612f8c3e6ec8fa7c6d977f39b48950fd937bbda0eed3b2a8df9bb
- model-request-f03b0bfd-2eb6-4c73-9d05-a9e7c6f51d9b.json；ID：9c3287af-5c1b-4d59-8bd7-4d4e10ef3e6d；SHA-256：0fa2f2d08db3b582014983736ce7b27e87d88f963953166728d3fe14822acc34
- model-request-f6dc59c0-5ddd-4a67-ab27-66e74da3c55a.json；ID：7e5d55e7-1684-4fbc-94ce-8866e047c467；SHA-256：f9cb035cfdcff88f742e75482155e7c2e0b0e781bd17a472edf8141dc059c089
- model-request-f90a5fd7-25d3-420e-81ec-e270a386b2e9.json；ID：6d29e297-c139-463c-a342-48e4b8ff1e0f；SHA-256：4185903d38111d824cb04f1dbd938cc6fbdb28f7da11a29dd85551eb743b935d
- model-response-046ab0ef-7175-4409-b86f-91d86072c3ef.json；ID：3a149dd2-91d9-4744-88d5-735fc8775c7c；SHA-256：136d7d903d214f3d1c20b71841b6308d45c721f806f5e2ebce9728619fe9bc7e
- model-response-05fbb93d-5f5e-40f5-b0b2-8a71a27ca54e.json；ID：d3c1a5fd-8318-4781-aead-7a85c9e7e06b；SHA-256：bdca179317185f93e667a40803dd678a08d18e93208ebb8f28a967c06173c725
- model-response-07c53b33-a340-4dc7-bbac-c5610f703aa9.json；ID：a8ea2471-df21-4058-9cfe-312b2bf188e3；SHA-256：b7d0adfc9382cf59e054197a42903180b7aeae89f2387869f9254887a602b0b4
- model-response-08a3a604-23e7-459d-8319-ef93be1e011d.json；ID：9fc7b658-787d-4ee3-aa38-a9403914da57；SHA-256：461dc9fbfb547d9ce5674e73be462635d89a25961c50802574a3ba6672ce113a
- model-response-0acaa543-3fbf-4b3c-a72c-a8b8ee154041.json；ID：c79e35be-9e33-43f9-a501-e8b6d30d0db1；SHA-256：ddc4a8729132c9bea743de1156a0441af5a4e0cde88329a08d4db9ed18cd852b
- model-response-0bd0c676-65ca-401d-a685-cec2b5a166ba.json；ID：9d1b3d14-43ec-4d39-aaa4-b4d3878308e3；SHA-256：f448a582b94b05882bf2daa9f066f6b3c00f723c666bb38b7664dfc4c0d0ebdc
- model-response-0ffbd767-9aea-4d43-85b8-bef0e582aea1.json；ID：b96c4dc8-99bc-484b-ac00-8416409ed87f；SHA-256：8cc955f008e09f481429037c9e07b0eb42e5e9b9fbb67c47761830159812cdb2
- model-response-132fae58-7ac9-40e3-b4a9-77c3f0861d38.json；ID：124ab9c6-1557-4cfe-96c5-b691fe8ced78；SHA-256：94cb73b9115846e7812234adb11245172f3cdc7cf9678adb20b90d2a0cf898dd
- model-response-13672133-a795-406b-8ec0-d2854c94d51e.json；ID：da05a1ff-222d-40c1-8068-89230e4ef743；SHA-256：44a66f2e3f8062fe9cec99e6395b83ec1cf72b23720a404cf611026d707fa03c
- model-response-1448b090-b768-409d-ba45-8100a5863eb5.json；ID：c31bc8ae-9e1b-4d9e-8d48-47a66a2f61c8；SHA-256：3b2d565d55e31ab01e1ec8f2cdd4dd09f3ddf4d844347ba0363104d8c9d0e73e
- model-response-159192cf-f1da-4627-b596-42ee199444af.json；ID：46f11dee-f130-4777-9fc7-d7a52f904f2d；SHA-256：704bbe95dfb4d1fbbe6987cbe96a70abeb444b23f66ad5a119e6f9e39373a59c
- model-response-19d5d9b0-7db5-4e22-bad3-8411bf9c26c8.json；ID：77c564f7-49dc-4288-8eab-9d44eca17115；SHA-256：fd347992b24abbeb5d7865ce54f18483a57b233efb380b3662cf8b88d84a29ac
- model-response-1cfeb942-9d1c-4be9-bbf9-4eec5e514d19.json；ID：84b1cf26-56fe-4d4c-b435-6ee4eba16141；SHA-256：557883ae6f250b4479ce089481611b2112f9ca53b7f755167c4dacf51f703f40
- model-response-2077fbe7-7e15-45b0-807d-02b1fab05110.json；ID：651970b8-96d9-4a33-9df6-79a99f7d9f9c；SHA-256：59dad696ff3f59b2dd2e2e18dd8f3e5327117d1f92b849d648410f024934de27
- model-response-20ccac34-a16c-45b9-8e28-19346c667f0b.json；ID：5b3fbbc7-d1da-4da9-b8f3-11e49befbae4；SHA-256：b1ad9302397f7af45ce0d5b190b87487600eaafe07769b6194b024a59c54e89d
- model-response-21d53a19-549f-4cec-9e6d-0faafd98b8d5.json；ID：f30cf122-e7ec-4f65-a058-8f5e273f5999；SHA-256：321cae64a7f74578532a041d4d18900a1fa06803ef2bbacb0030a196281c4b3b
- model-response-2365eaad-af02-4550-949a-effcb14ea2ad.json；ID：2ebc40eb-e04a-46f4-8e88-d42a485e56a9；SHA-256：165b88557dd781b9885cdc38d79b368d429926a191e10a5fba50ce813abb2a7d
- model-response-256abfa3-1a34-496f-9242-c2344c2f81f7.json；ID：937d5197-d840-4dd0-b54e-76b36d0487cb；SHA-256：209bcb607ec9043af97ee18ce612e16d07d51e1de810f957a1e846313d861ff2
- model-response-29a67255-dda1-4a53-8561-7549c63136c3.json；ID：fedfbdd5-4bf1-4d4c-91e6-70ddb0fae67f；SHA-256：0aa1813a3e8e52060b8616909f1775dadc09b1ddb504719c67453591b5dc818c
- model-response-2a5dd492-5a0f-4544-ad03-fbae7a4a50bf.json；ID：223b4a40-ec40-4b04-a407-a871ee240009；SHA-256：0385b5566f60a1eedadd31c726b62220381be96ac87a272b4ecbc5148d23812d
- model-response-2e36ef46-23ae-4398-80b4-3fb79dadce3a.json；ID：cb7a743c-5248-4dfe-9780-44f047cd5a1f；SHA-256：dcafe7bc1db71428ec65e99ccfb6b03af697d785d990708583be804441368c4b
- model-response-2fec4720-1a32-4a1a-9d43-d3493d9fea40.json；ID：d31f5e2b-431e-4d68-91e2-1436f13e8ec4；SHA-256：ab843a0e1503fd1a12b7baa1aeba2c74fd16a6935da98335e2bbb5d8929f277f
- model-response-302c4e4c-a545-4cd6-9fec-3e296980b346.json；ID：d1c4a1f0-3cef-4ab1-8bff-4d9638bc685c；SHA-256：5a2a85ad20b445d1a3ce45bc46c9aea5f7661d78f86e0d886e7c8996e96dadf1
- model-response-35685749-a0e4-4eb6-be33-f77663ccae4a.json；ID：8732f228-f657-42fe-b3ab-a6c8c8254414；SHA-256：61800d3dbc9dabf5e88121e2a53c16d6a1d01d3cdfa5322ae1b95efb4b3b87ff
- model-response-38adc86e-c23e-48ad-a492-7709d044e432.json；ID：39f95414-2287-433c-8665-540315064519；SHA-256：9b53b2af4bf0864ecd16db56c0335cd042908357e5c94fca721caae8424f6eac
- model-response-39e62b85-a064-46a1-bc50-8a595ad17ad3.json；ID：75fbdf3c-2d5c-4bf7-8c96-afff82a3798e；SHA-256：82257bcace87593fa0443c99556ff3df116392e264e7ffbaba14df7e28bf81c9
- model-response-46122686-ceca-45cd-870e-70d37b226910.json；ID：c6e74ee4-8e3a-4d31-8365-341f90167b74；SHA-256：c6410876b5710a993bdece2e3bf0e0100ed646f66761cd150f0920f06e1c0a16
- model-response-4b22f46f-0531-4662-aacc-2812e74aa011.json；ID：a3377719-45bf-44df-b509-d61c3076a3e7；SHA-256：e4cda0c83c13b775167bbdc84ff647487c8eb2bb96333fcea9f3f6a8f5c6efd4
- model-response-4bee5948-828a-485b-b834-1116d7fc3f29.json；ID：3e50e7db-ebcb-4e9a-ad3d-3f0bff2a8e36；SHA-256：81fd1a82c7ae1dd867ac4d596d9a5bcd0edb9a8976444f0bb0c555dcae806eed
- model-response-508ec46f-beee-485d-9806-46ff944a6f61.json；ID：e6bf491f-fbf3-43cc-a4d7-4655825d2069；SHA-256：c187381a97b7712ddb6125a8c441b7f4354014983f296d2e8f0aac2050fbff5e
- model-response-51f18301-af8a-4a64-b581-8b159804108d.json；ID：4b5fcd5a-aad4-4170-80ea-59824c0094e4；SHA-256：a97f35992293af482bf05bc71d82c4bd934a6f437ce4924f7f0d0c9d20f0fd36
- model-response-5382a464-b1db-45ad-a675-1b607943047b.json；ID：6a0dbe82-d303-4635-9518-88b1cbf0a072；SHA-256：77c25aea4811b03773e9b9a8b7487a58104ec9c7402671beaf1bddbdd8e89732
- model-response-54579d98-a36b-4389-ab73-3286d65fde60.json；ID：42f44d36-e287-470a-9469-fa8b4f1d85a4；SHA-256：78a2da17ab279bc624e97d2a0af7d76a68f42e3ca8b7411b7a2ce9502e21afc0
- model-response-56e3600f-5cc8-4da8-ab02-d78bddd03d06.json；ID：82d7b8e7-599c-416f-89bf-3281f4a9ed83；SHA-256：389b68c2c095630e2929d08054e506ccdcf05f608c53e45b68f569c7408f0788
- model-response-5bf59b62-8848-488f-8f72-95e222ca37b5.json；ID：a1a8e946-4e7a-41d5-8165-d02a8039ead6；SHA-256：31e85bcea7f8bbea661fe383f881365f5e8abb685b027f9b4109d0b205f919e1
- model-response-61e0db99-7b68-4c8c-96d8-fd251fc5966a.json；ID：841792ce-be0c-46db-9132-cd2bb967b857；SHA-256：942ccf9c79d9a776f7dc8bf7c021be179fd53022d7b4cc4b5e14e7a9f3d10694
- model-response-630a6b6a-113d-4390-9078-30fefbcfbfa5.json；ID：6465bed7-e54e-4539-a109-c99ba44c5b3f；SHA-256：8874786ab612f9ff07e7b4f835d87ab0fbb67877f6d64a05fe2c21b20123ab35
- model-response-6361d1e3-5cb5-4dc0-8df9-c9408d044128.json；ID：8c7b0be9-b1db-4db8-8c3e-26852a050fe5；SHA-256：f0f6e4fbeda74c9f2b843239103d51ea4dab53a4d7e7c07ec2b18f5e01c14e7c
- model-response-6503f247-6923-4d71-bc27-731c0f9c9cfc.json；ID：bd1b0bd8-a681-4f55-8cb5-8f87760724d3；SHA-256：34415863efd0a7a95c9098fe788f82d580769865a4ccef2e21d8e993c379487b
- model-response-6567c3fa-968c-4209-a68a-7e5e913dde9a.json；ID：c1830e77-3277-4dfd-a3a6-4dd1bc9633d1；SHA-256：1a858b9aaebb5315e946e50d35d06ec2a270444014070ac92153c1ac8ccbc817
- model-response-66376ad9-ee6f-4b4d-a753-05674956b227.json；ID：4fc60fc9-04a2-4308-b55b-37c0c1979714；SHA-256：d692d340841bbc7dcd52336bf435d6ddcba9942e591ba9d2c89c8406172f3087
- model-response-6692feb2-2376-4909-a659-a5fd5c85a3d5.json；ID：423ab997-a6e4-4511-a849-8bd00052e115；SHA-256：3c8edc0fa7965f833146388750f7fb66d530588c03d19bc8192e2334d3c8929c
- model-response-67ed0104-f4e5-4fe9-a472-dd80577a96ef.json；ID：a4efda1c-1c38-457a-b07c-cee9e54eac51；SHA-256：a05b195a2e85e7c31de8cf8954e86a18f372d691d8730d825175ce99461b9d8f
- model-response-6b08a023-f193-4161-8b21-a48ea9b769c2.json；ID：5184864e-9636-46f7-876f-dd2edf6954b0；SHA-256：62936b6bd63c2049a00fcb8b68590be3f6cc52f8f30b1f3631944c345d8a5538
- model-response-6c0d19ac-abbc-417a-bd4d-3e70ae133e41.json；ID：eeb13e6a-debb-4b32-9a78-fe511b18c45a；SHA-256：3ea1d074d99b9a245fd09015223e7eb081d27e91e3a70228a76c955cdd4ac954
- model-response-6e7ea6a7-f689-4fd3-8b70-0f37fa11d5b6.json；ID：3ee873c2-9fac-443b-be25-5917755e4e3c；SHA-256：a8cac6e26ef656bf33bb3097bafa8ecf5c9086757b3691e09bdc6d847141541e
- model-response-7860e958-e73b-44b0-a45d-e66446e866d0.json；ID：415ca867-cb3f-4ed1-86fd-e2e4175917a8；SHA-256：2e9929f74f7956c56adcb80efa861838b7a0fbb39e5b10eb46eeabaf0a1e14d8
- model-response-796711e6-e629-4df9-9b20-39959327d46d.json；ID：077a99c8-5911-4fac-8cfe-b4ab9a83bb6f；SHA-256：13bfdeb6894c0fd76c6c60ee5c83b67b242797f48bb72a2c4223d71a0180dc46
- model-response-7a3df66a-d6fa-4fde-bad0-bff1b3e3fa87.json；ID：6e0f4ea0-d79a-410a-948f-d20a195f36cd；SHA-256：163bdbecd02a036b5c0eb92127d5bcc0e66e727bf98fb73e57f11e18db31e7cc
- model-response-7d6dcc33-87e6-4863-a54f-78e0874e1864.json；ID：3f6c280e-0029-4977-8db8-71afe113ba8c；SHA-256：664a39fd00af4dc9135c09f8e6d2a142e2f0f14465117faf93519ea7befee0bf
- model-response-81ee07fe-569f-414c-9e27-e5a1cea2bd24.json；ID：83a92b88-7bf9-4782-b707-c3cc70c87444；SHA-256：7ba181729c72406aca21ae355368b003b502d6066cc26757207129a165bace1f
- model-response-82ff4740-256c-4dcd-beb9-999349a3f0fd.json；ID：0b5fc292-97f7-472e-8b49-fedda727c73e；SHA-256：00410e29c06493b18d3ab06c72ef6959ee869bb4e8e2ab776ba821b9997eb44e
- model-response-8360b29f-78ce-4f90-bedf-e6cefeebe7b0.json；ID：b5527bef-5f5e-440d-acee-57a61f1dcdc4；SHA-256：f6811f802fa52686814d7f4bbde4fd60f5b6aa31134f7bf2a3a66e3090702de5
- model-response-96842434-a298-4743-8f86-28edd3a12172.json；ID：c64c06fe-6be3-407b-bec4-155fad06bbe6；SHA-256：ca239845b981a682449b2cdbab47b851bb1fe059a07269d43e04b49a6aabb137
- model-response-9bed371a-a634-4cc9-9502-dc2fee90eb53.json；ID：3f4b90ce-cbf8-4be5-92da-e373d6d60393；SHA-256：423baedc813917fa45f7fe94854e757542df41c3062fe6a7f15a403f0a04a10f
- model-response-9c26b089-20ec-4888-a019-a48ce77a5416.json；ID：f41c1d4b-2726-4d10-ba1a-eb8a93577e4d；SHA-256：77256602eae3ad970fca24b91e0a4fa9b8866c2a210b2fb2a69c07fc823a399b
- model-response-9d42e3e0-75a3-4c89-94ae-dbd3eafbf9c3.json；ID：8465d814-1fe1-4924-978b-7ae545983b59；SHA-256：2e67b2b428e160860f9eb98ecf81f471532b3abdbb534ab4592c79540769ed17
- model-response-9fb261ec-6a54-49df-878d-a6cf9a659665.json；ID：dfd1974b-6328-441a-8d75-d5caa91bec94；SHA-256：d84258c460f1045300160446eebfd5f7565d71e3d0fd413f400a9a427a88eaeb
- model-response-ade9ba45-364b-4d57-8a37-f60feba753c3.json；ID：a6503157-281a-4351-b4c0-2153128379d7；SHA-256：77bfc128768d3574b46b8621075bf7403c429049c7be31dfd060cb40de921970
- model-response-ae4dbde9-55a0-4fcf-ad22-903f3cdffcf2.json；ID：d0fc7219-5955-4349-a8dd-617af2936fe1；SHA-256：399f8e791225f28a316579d9553fab8c73811cf5a9812b4c596a78ef91bf0ae9
- model-response-af8b5cf3-3d3a-4f47-a4d3-e6920b01ed13.json；ID：afe3f90d-defa-4869-b684-c80884fdee6a；SHA-256：355e763d0b9c53f69388ee57de71d48a5bdb9c7b0a0c001d10339d18d796ffa9
- model-response-b09f455d-212b-4d63-9bec-2baed8b27165.json；ID：35b16c25-594d-40c9-a90b-df6a4e258bae；SHA-256：b99405c5a9c5b735fa031a17df551ceb90cbfce79eaf20afd0e2483a35dbea36
- model-response-b286c55c-e704-4c91-aa48-02ec0a9051ab.json；ID：1efb8470-c3d1-4956-9ec7-f5f91588ad66；SHA-256：2efb768b0af4d1d5f5ca36d71808a61806837c0fd8d0b0b08030877cc572e1c2
- model-response-b2c1a180-acc0-429e-9809-df1838689227.json；ID：017904a1-9781-41cb-b455-88782aaf98ae；SHA-256：3550f2f0ab44b48ffdc06cabcf2fe6d7c0f86a5724967339c4cae745c29d7912
- model-response-b45e546c-7385-43a3-a3a2-05f091ee98b0.json；ID：a6f8e198-ce16-4073-aab0-f1e410222cdc；SHA-256：56a626e08c897c4a4303afce9e4b567ba25122870b8ac02814cd37eb67be2c26
- model-response-b633191e-9bc9-401f-aa20-0c2e3e4e6f2f.json；ID：19b39195-45b9-4b8b-b0ef-9c54ad8d4884；SHA-256：f202a7a4a22c8c8536a936b21711f1676df06b1ad08c8949269cf44ea1292999
- model-response-b813d0be-0d85-4f0f-8a17-327afce05e70.json；ID：7648ed60-8e73-4f03-bf1d-b1931736d44d；SHA-256：0f940328aa268c6ba53f01eddaabc7af60e544cb38f9c117ee0d6a6504dd30c5
- model-response-bacd924f-16f2-498b-a9d8-2434d307be33.json；ID：26cac87e-8bf9-40e7-9703-5ea81417dc33；SHA-256：7dfded2161fd35fa750b4fb8bdce9b367953f11c63dbee4893bf488cc2d34745
- model-response-bc49090f-1c56-4633-b5a7-138976d19820.json；ID：1e7980f7-fe77-41f2-bc60-204d949a2e66；SHA-256：58986855c3411835bfb604bfa5637cd031946d5c179837b7a1b2788cc3545c7a
- model-response-bf8e355d-853d-4e81-bf6d-154dd4abcf31.json；ID：49851ba3-c01f-4cdb-96d9-00bad4bbb01d；SHA-256：55fb54015c4d7b65830d18daddbeb3ed06c6bac6b1947dccb74e8ec799be1b2e
- model-response-c30a1bef-fed4-499c-bb10-212df51347f8.json；ID：4830de12-553a-41c9-b737-0fe663acb101；SHA-256：da5e3697403f8a1cfeacd519bce17057b10e67e38c16c11a46b993f3c143f2cd
- model-response-c79d50b6-871f-43cd-b510-aa2e917d062e.json；ID：64fe43fe-4fde-48df-bbd5-11d9e11c04c6；SHA-256：a49f254a28103f85c84a7e9fe8da40f8be5c5f5783a8b126c6de77a7c6000f08
- model-response-c84bb431-54d0-4ea6-8247-1120ad7e7efd.json；ID：0a6e1584-a35a-4f7d-bd1d-2fed4b57957b；SHA-256：b6ddbfa38ff146b7200d69545db5b9c7f4fadf5bb39747bdf25f2bb5a118d1d9
- model-response-cae4b8df-eec3-4491-8788-363cfb5dbdb0.json；ID：780095f4-9168-41a1-b7e2-6d7b2da3f911；SHA-256：e84e461303ae893c33443489d47efdf9156fac487214523cb3e526787923fdc5
- model-response-cc238964-2f73-4d0b-b7a9-e7d9c261057e.json；ID：abc4ef20-e056-4ea9-9fd0-dd497a7faa06；SHA-256：2f905bc0e9df033c0d16ac282c3759492a43371f8522aa881a1857afcd6d58cd
- model-response-cc8cfba3-35be-4e4a-b12b-e88de000ec1b.json；ID：d7cd2116-39d0-4df6-8dad-72f2743e020d；SHA-256：7b7331df0b69296393da332e6a49e39495224fee863a85fe7191b48f3b602f60
- model-response-d0c2a822-8d01-4dbf-8ac5-8bae352299ea.json；ID：5566d2cc-c158-4e41-b0e0-056f71cb9fd4；SHA-256：556d446b70c95997e1628e66d60a8bc7221759e7584d7c7c393355ecab6038c0
- model-response-d3ab5927-f702-4572-93e6-61b3cd0ec897.json；ID：0cdd64f3-6c86-48b5-917a-00ea0f3e6f97；SHA-256：fe5d2b3d3f632bdc2eb7e5041303769fcc4536048360ba57457f9d968282463c
- model-response-d63295a8-6e28-4820-87d9-30d77cab363a.json；ID：f5538eb2-8067-455e-9186-d2fd31274741；SHA-256：d97edc1e8c842bcbeddb969a7bb1dc3c1e9ae504eeef3aafb3c424cd75fe99bd
- model-response-d9ed13f3-b7f6-44b7-b224-9fd9de247cd0.json；ID：1d90ccb3-d27a-4e0e-98fa-dfb8378806ec；SHA-256：c526fc2649c6e84c43f6fe34d595b3ac97104fcc454cd3c2fd05081583b730d8
- model-response-dc573c70-2b01-421f-b79b-a918f79a72c3.json；ID：d6a38658-4de4-4a8a-8873-881a001236a7；SHA-256：0dc248e0476eae441f1016acd629f549dfccb522dff68ad119793869ecdcd4a8
- model-response-dc67dc47-e376-4bc1-8dbe-c72867fcacdd.json；ID：3070f53c-2a7c-4ddc-867e-c2f27b9aad4d；SHA-256：67ff9e179308d12e357d8149e2103502744c4aacb1ea7c8139643ee3dbfe66ad
- model-response-dc96bcdd-9015-4f78-8b44-da1aac43e550.json；ID：ab34f669-572c-41ec-be97-6c4722d4e85a；SHA-256：698eade0d1dc245b49e296364ee2de81d73986b41fc87e9ac7eef87f33db48ac
- model-response-e010b13e-f20a-4a66-8da2-d0383be3362f.json；ID：971d428d-5fee-40a4-8225-a3967a0bb7a4；SHA-256：6882673b7e3a6aa3c81af5173b1150aef6d14a2ac288d4c094e5467fb3fe2230
- model-response-e061a320-5d76-4c60-b2ef-4f12a9e929b9.json；ID：93a6c910-cb32-43d6-91a2-5dd53aa92ec8；SHA-256：a2c1ad1ccb8f85df492df3ed6096e39d0d4a979c6f8c9cd197d4996ef4153911
- model-response-e0a15862-4f5c-4643-b792-50a2fe58d475.json；ID：9d78774b-3337-44ed-a9f2-82b438339fbc；SHA-256：390f35595ec485d3218cc12d422dea92d5b270cfad68cfc58ce8cc2666550901
- model-response-e1e506a7-7ba2-47cf-98e8-bd550f854cf4.json；ID：cca1ba74-3b66-4d41-b059-5bfd625883d0；SHA-256：d98f33a07b14a1cdee62f33b76d841c630a56309b3ba4aafbb3e20ae5118f251
- model-response-e96ffa53-f778-4c17-9652-511769c9177b.json；ID：ab72304a-b5bf-4904-aa70-2bbe58077251；SHA-256：25b98c3cdd4f5a3e2c19a68341e2967c801da337931df4eb832c1672160cab7b
- model-response-ea614828-c147-4f72-9c6d-16b361f656bf.json；ID：58bb0f2f-ebdf-4f5b-a157-0ed95cb7c8ee；SHA-256：3b07a26e5d3bc9d929fdd36ed58192c10f81bbfdd7200165a14aceaf24e90a6e
- model-response-eaa3f35c-2088-4a65-9108-cc59fe905757.json；ID：f272dcce-fc43-4332-9a1a-8353177d2db6；SHA-256：ca69436d43952217e1f287f2429597308d627e3b6150587fcb5466aebb1ad769
- model-response-ef0747fe-3c97-4990-8db7-d4551f69b26a.json；ID：80143433-3bb9-4225-a28f-9a17c01bda2f；SHA-256：989b135b4c7d7f9cb210b47c2b6085a8192ef86ba52be5cd4dada2ac93eceb24
- model-response-f0aece68-c3e6-4880-9bab-e9b4b950170a.json；ID：90f9633e-6711-47f9-962b-a4666714f1f0；SHA-256：4f55559099bd4224e62062febe9bd7439d346950df5a86b7c073ef7005f932be
- model-response-f1b55b23-a123-4674-b960-b824aae3db5e.json；ID：66f50904-6950-41e8-88b2-891e1d6c77f5；SHA-256：36531d8a41674d3f92e1b9af88d2aa30e20e43188766ba9c6aa32d3e8a81e227
- model-response-f3981973-358c-47bd-b9ca-135adadc73d5.json；ID：a7aba857-aa4a-4d37-bd9e-812378ecabb8；SHA-256：83334a434830cc85e65a29dff4a6b843a71b00fa26a0251463f116696c3fe258
- model-response-f5a36e01-8f28-474b-984a-c9ce7ed26388.json；ID：231a65d3-8f44-4e38-adca-028bc974cc8b；SHA-256：d23e7d1c088759f8b8206410f619b886d9d8ce431579b4f4b0fb73bee9bff437
- model-response-f617ee75-70db-4821-9dcc-9cf8b1e412e6.json；ID：186db80f-0f0c-4b8c-8e7f-5b4d976580cf；SHA-256：6c32417497c216554fdfd4b9844e7390ae2e36f7a6a2f5dd02808d7b5ce6d570
- model-response-f6737aaa-b92e-4d26-a250-37d957430dee.json；ID：c0a8c3d4-3d95-46a0-b369-1157d2735b6c；SHA-256：3aaf559322d5f7c47e69312dd8f2e9fcab75c5bf0acaebf7edbec1c14ac6ad5b
- model-response-f774640c-e659-49d1-9c58-8e224ee802b0.json；ID：ba769d45-88d0-4b7f-91d8-7f280c5a564e；SHA-256：99b0d6dad39b13ced49b60a6ebe5348e6009cd15696307ad516dad76a2c2fdd9
- model-response-fa93e1f3-cb8c-40e9-9b08-046352155cb3.json；ID：79b8e9d1-2fd1-4b5d-a78d-e2db9de11758；SHA-256：b06b1f88c729c7ea3cc01d3585aeac797ac41f2508c4000d42807b31fc824f84
- model-response-ffdce4d3-d10d-4251-91ba-011e5613e135.json；ID：cddf1d21-db19-44a3-aa62-74bb9dcf2310；SHA-256：b56978f5404438e86daa8860cb428ffbfb79e588db0bd2de6ab2e8ddea4dff07
- p07-ollama-images-fixed.zip；ID：d88b7817-a9a0-4c1f-8dfa-3d01f88fe143；SHA-256：c51b08ac82756d60184455c8e99ca40585eb456f046c60c4e8bc84899536e02d
- snapshot-manifest.json；ID：15a6ad06-679d-42f7-817a-00094ac5ebf8；SHA-256：278616069f9668a7138331a0231086d2ee9b6a2880508ac60bce2c83b95ab300
- source-snapshot.zip；ID：4ef5f247-a5e8-4865-986e-729306ec571d；SHA-256：f1f36734d630259adb5e33889533543aa17d57284820860bb018ff9da499c9f0
