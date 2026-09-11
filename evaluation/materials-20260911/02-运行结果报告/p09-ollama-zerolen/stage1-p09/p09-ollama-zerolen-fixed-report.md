# AegisAudit 分析报告

项目：对照池评测 20260911-073454

任务：d00a0c6b-35e0-473b-88e8-422770c527a3

状态：Completed

目标 SHA-256：b783cb05475c436ddcf76b87881c58408174ec1d6dd4f8242442e7bd108018bf

结果快照 · 数据截至 2026-09-11T07:56:39.485Z · 导出时任务状态 COMPLETED。漏洞审计：COMPLETED；独立复核：COMPLETED；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| BatchSize | llama/runner/image.go | L102–L117 | PARSED |
| EmbedSize | llama/runner/image.go | L119–L125 | PARSED |
| Free | llama/runner/image.go | L53–L64 | PARSED |
| NeedCrossAttention | llama/runner/image.go | L127–L135 | PARSED |
| NewEmbed | llama/runner/image.go | L66–L100 | PARSED |
| NewImageContext | llama/runner/image.go | L29–L51 | PARSED |
| addImage | llama/runner/image.go | L163–L183 | PARSED |
| findImage | llama/runner/image.go | L151–L161 | PARSED |
| hashImage | llama/runner/image.go | L143–L147 | PARSED |
| llama/runner/image.go | llama/runner/image.go | L1–L183 | PARSED |

## 审计策略与优先级

目标为单文件 Go 源码 llama/runner/image.go（10 个单元，调用图不完整、Semgrep 未支持、未构建未运行）。规划思路：先从模块级读到的真实代码确认外部输入与信任边界，再把审计优先级放在「外部字节流进入 → 缓存键计算 → 缓存查找/写入」这条数据流，以及模型路径/架构分派、并发互斥、生命周期释放等语义授权与状态一致性问题上；对仅有词法线索（如“身份或权限边界”）的单元只作为排序依据，不当作结论。

1. u\_8581aec77c9ecae72cfd77f81b51a36c：NewEmbed 是主要外部输入汇聚点：接收调用方提供的 data \[\]byte 与 aspectRatioId，先做长度校验、再哈希并进入缓存/推理分支。需独立核验 nil 接收者返回 \(nil,nil\) 的语义（可能被上游当作成功）、错误分支是否泄漏部分状态、以及 c.mllama 与 c.clip 同时/均未设置时的分派完备性与缓存写入是否一致。
2. u\_d73d58d14ef51b37c399b9c6de4f412d：addImage 是缓存写入与淘汰逻辑所在（imageCacheSize=4 的 LRU/覆盖策略）。需确认索引/淘汰算法是否越界、lastUsed 更新与替换是否原子、并发下是否与 findImage 的返回切片共享底层数组（缓存返回 \[\]\[\]float32 是否会被调用方修改而造成跨请求数据串扰）。
3. u\_1fd9f0921d4ab95361ae3f6c724c9d6d：findImage 根据 uint64 哈希在固定大小数组中查找并返回缓存值，是信任边界处的内容复用点。需核验哈希碰撞/键复用是否会导致返回属于其他输入的嵌入（缓存隔离失效）、命中时未校验长度或来源、以及返回切片是否被调用方原地修改。
4. u\_8f47aec19010dce631f126a009a1c48f：hashImage 使用 hash/maphash 生成 64 位非加密哈希作为缓存键，且对共享的 c.imageHash 调用 Reset/Write/Sum64。需确认该哈希在安全语义上的定位（非密码学、抗碰撞性有限）、共享 hasher 的并发使用是否依赖调用点的 c.mu 加锁，以及碰撞被接受的风险是否被文档化或缓解。
5. u\_ea5f5cd8fd1559582908c514b71fc7bf：NewImageContext 依据外部/配置提供的 modelPath 经 llama.GetModelArch 决定架构并创建 clip 或 mllama 上下文，属于模型与信任边界选择点。需核验未知架构的错误处理、部分初始化失败时的资源释放、以及 modelPath 来源是否为不可信输入（路径/模型选择是否被上游校验）。
6. u\_9da5eea6db08c72b0d59490c8de8293f：BatchSize 被标注为“身份或权限边界”线索，且接受外部配置 configuredBatchSize 并返回给调用方用于内存分配。需核验返回值 0 与配置值的语义（0 是否会被下游当作非法批大小）、mllama 固定返回 1 的假设在非 mllama 与 nil 情况下的一致性，仅词法线索不构成结论。
7. u\_f85f2d53adc378539862404b2690c76b：Free 释放 clip/mllama 资源但不清理 images 缓存与互斥状态，且 NewImageContext 失败路径存在部分初始化对象。需核验重复调用/释放后复用、并发 Free 与 NewEmbed 的竞争（Free 未持 c.mu）是否构成释放后使用或状态不一致。
8. u\_10ee8a116cf66c1e94a49e24754659f9：EmbedSize 依据 c.mllama 与否选择 mllama.EmbedSize 或 llamaContext.Model\(\).NEmbd\(\)。外部输入为 llamaContext，需核验上下文为 nil/模型未加载时的行为与返回值语义，是否可能被下游当作有效维度用于分配。
9. u\_5afa666310736bf20b67642f9320d3c2：NeedCrossAttention 遍历 inputs 判断 embed 是否为 nil，属于跨注意力解码路径的输入分类。需核验 nil 输入切片、混合 embed/nil 输入的语义是否会误判路径，从而跳过必要处理或触发错误路径。
10. u\_72dc10c49e40ba8729b36e096b415789：模块级包含常量 imageCacheSize、ImageContext 结构（mu 注释声明“生成嵌入或访问缓存时必须持有”）、缓存数组与共享 maphash.Hash。作为整体重新核验互斥覆盖范围（hashImage 在加锁前调用）、缓存容量与生命周期、包 main 的入口/外部调用方边界，用于校验各函数级判断。

规划限制：analysis\_scope 为 STRUCTURE\_ANALYSIS：call\_graph\_complete=false，无法确认 ImageContext.NewEmbed/findImage/addImage 的真实调用方、input 结构定义与上游输入校验，外部输入可达性属推断而非已验证事实。

规划限制：Semgrep 状态 UNSUPPORTED（执行器未准备 Windows 原生 Semgrep 1.176.1），仅有内建线索；elder 词法线索（如 U0001/U0005 的“身份或权限边界”）未经语义验证，不得视为漏洞。

规划限制：build\_executed=false、target\_executed=false、verification=NOT\_RUN、vulnerability\_audit=NOT\_RUN：无构建、无运行、无 PoC，任何缺陷均为静态假设，未确认可利用性。

规划限制：本次预算仅允许 1 次工具请求，实际只读取了 U0001（且该单元在 160 行处被截断，addImage 主体未读到）；U0003、U0006、U0007、U0009、U0010 等未逐一读取原始行，其优先级基于目录元数据与所读模块代码推断。

规划限制：recovery=null，目标为 SOURCE 类型：无二进制恢复/保护/加壳相关元数据，未发生也未声称任何解包或反混淆；缺失的构建系统、入口、输入接口与依赖清单需人工补充后才能版本化复核。

规划限制：缓存键为 64 位非密码学哈希（maphash），碰撞可能性与实际影响未在本快照中被量化或验证，不应据此直接判定漏洞。

## 发现与复核

静态结论范围：COMPONENT

### 缓存键使用 64 位非加密 maphash，抗碰撞性不足

UNKNOWN · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：hashImage 的 image \[\]byte（外部图像字节）

危险操作：c.imageHash.Sum64\(\) 产出的 64 位键被第 80/151-158 行以相等性比较判定缓存命中

防护缺口：未使用抗碰撞摘要或（摘要+长度等）复合键，也未在命中时复核原始字节

前提：能够向进程多次提交不同图像并要求同一 ImageContext 复用缓存；碰撞需在随机种子下偶然发生

影响：极小概率下把一张图像的嵌入当作另一张图像返回，造成跨请求结果混淆（不构成密钥/完整性攻击面）

修复：若缓存正确性重要，改用 SHA-256 等抗碰撞摘要或保存较小的字节前缀做二次校验；至少记录哈希算法选择依据

- 证据：llama/runner/image.go L144–146 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
- 证据：llama/runner/image.go L80–80 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	embed, err := c.findImage\(hash\)

复核 v2（MODEL，REJECTED）：候选主张的实质危害是“不同图像字节因 64 位键相等而被判定为同一缓存项，返回别的图像的嵌入”。代码确实只用 c.hashImage 的 64 位结果做缓存身份（U0004:75/80，U0009:151-158 仅比较 key 相等、不回验原始字节），但该单元所用的键是 Go 标准库 hash/maphash 的 Hash（U0001:26），它是带随机种子的 keyed 哈希：代码中没有任何 SetSeed/Seed 调用，零值 Hash 在首次使用时由运行时取随机种子，模块外不可预测。因此“让两个不同图像产生相等键”不是本组件接口（NewEmbed 的 data \[\]byte）能控制的输入：攻击者需要针对未知种子伪造 64 位碰撞，属于额外、未证实的攻击能力；而随机偶然碰撞在仅 4 项的缓存中量级约 4×2^-64，属可忽略的理论正确性风险而非可辩护的安全缺陷。故按给定主张（碰撞导致跨请求结果混淆）判为 REJECTED。另注：第 75 行 hashImage 在 c.mu.Lock\(\) 之前调用，imageHash 为共享可变状态，这构成另一个独立（本审查范围外、未经证实）的并发隐患，不作为本主张的证据。

反证：1\) 键为 hash/maphash（U0001:26），带进程随机种子且代码未设置种子，属抗离线构造的 keyed 哈希，不是 FNV/CRC 类无种子摘要；2\) 缓存查找要求 64 位值精确相等（U0009:153），攻击者无法在不掌握种子的情况下定向构造相等；3\) 缓存容量仅 4（U0001:15/48），偶然碰撞空间极小；4\) 对完全相同字节返回同一嵌入属该缓存的既定语义，非缺陷。

待补信息：未证实的能力：获得/预测 maphash 的进程内种子并以 ≤2^32~2^64 代价为不同图像构造出相等 64 位键。组件前置条件：同一 ImageContext 实例被多次调用、data 为调用方提供的图像字节（这些属正常组件契约）。本快照未显示任何暴露种子的接口；并发下 imageHash 在锁外使用的问题（U0004:75 位于 U0004:77 加锁之前）需单独评估，本主张未提供该证据。
静态结论范围：COMPONENT

### 缓存键在互斥锁之外计算：hashImage 并发访问共享 maphash.Hash 造成数据竞争

CWE-362 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：NewEmbed 的 data \[\]byte（外部图像字节流，runner 请求数据）

危险操作：c.hashImage\(data\) 内部对共享 c.imageHash 执行 Reset/Write/Sum64（第 143-146 行），以及在持锁前使用该哈希作为后续缓存键

防护缺口：在调用 hashImage 之前获取 c.mu；或将 imageHash 移入锁保护的临界区/使用每调用局部 hash 实例

前提：多个 goroutine 并发调用同一 \*ImageContext.NewEmbed（调用方是否并发未在本模块内证实，属不确定性）

影响：缓存键计算与缓存状态竞争：可能产生错误键值导致缓存命中错误图像嵌入、错误嵌入被送回请求或缓存条目错乱；也可能触发 maphash 内部状态不一致

修复：把第 75 行的哈希计算移入第 77-78 行锁保护的临界区（或改为每次调用新建独立 hash 实例、把 c.imageHash 视为锁内状态），并加 -race 回归测试

- 证据：llama/runner/image.go L75–75 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	hash := c.hashImage\(data\)
- 证据：llama/runner/image.go L77–78 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	c.mu.Lock\(\) 	defer c.mu.Unlock\(\)
- 证据：llama/runner/image.go L143–146 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
- 证据：llama/runner/image.go L18–19 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	// mu is required to be held when generating embeddings or accessing the cache 	mu sync.Mutex

复核 v2（MODEL，INCONCLUSIVE）：代码层面属实：NewEmbed 在第 75 行于 c.mu.Lock\(\)（第 77 行）之前调用 c.hashImage\(data\)，而 hashImage（U0008:143-146）对接收者字段 c.imageHash 执行 Reset/Write/Sum64；该字段位于共享的 \*ImageContext 上（U0001:26），且 U0001:17-19 明确声明“生成嵌入或访问缓存时必须持锁”，说明该结构的互斥锁正是为并发共享状态设计。若同一 \*ImageContext 被多个 goroutine 并发调用，第 75 行对 maphash.Hash 的无锁读写构成真实数据竞争，会破坏哈希内部状态、产生错误缓存键，进而可能命中返回错误图像的嵌入。但本快照只包含 llama/runner/image.go，未提供任何调用方或 goroutine 分发证据来证明“同一接收者被并发调用”这一前提；候选自身也承认调用方是否并发未证实。按审查规则，竞争前提必须单独举证而不能默认成立，故无法在组件边界内将其判定为已验证的静态缺陷。

反证：锁本身确实存在（U0004:77-78），且 findImage/addImage 均在持锁区间内执行，说明未持锁访问缓存是被有意约束的不变式违反；同时第 71-73 行对零长度输入有前置校验，排除了空输入的越界路径。但锁的存在不等于并发调用已被证实，无法据此把“并发”当作既成事实。

待补信息：1\) 是否存在多个 goroutine 并发调用同一 \*ImageContext.NewEmbed（本快照无任何调用方/分发代码）；2\) ImageContext 是否在 runner 请求处理中被跨请求共享；3\) 若并发成立，maphash 交错读写的实际后果是否确为跨请求嵌入混淆。缺少上述证据，竞争前提仍为 UNKNOWN。
静态结论范围：COMPONENT

### 图像缓存键忽略 aspectRatioId（及上下文标识），导致不同宽高比请求复用同一嵌入

UNKNOWN · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：NewEmbed 入参 aspectRatioId（来自请求方/上层 runner 参数）

危险操作：第 80 行 c.findImage\(hash\) 命中并返回旧嵌入；第 96 行 c.addImage\(hash, embed\) 仅按 hash 缓存

防护缺口：缓存键未纳入 aspectRatioId（以及必要的模型/上下文标识），也未在命中时校验参数一致性

前提：同一 ImageContext 被用于同一图像、不同 aspectRatioId 的请求，且两者间隔小于缓存淘汰窗口（缓存大小 4）

影响：请求得到与自身宽高比参数不一致的嵌入，视觉语义被错误地附加到后续对话/推理，造成模型输出被误导和可复现的跨请求结果污染

修复：把 aspectRatioId（及模型/上下文标识）并入缓存键或作为缓存条目字段校验，命中不一致时重新计算；为多宽高比场景补充测试

- 证据：llama/runner/image.go L80–80 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	embed, err := c.findImage\(hash\)
- 证据：llama/runner/image.go L83–83 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：			embed, err = c.mllama.NewEmbed\(llamaContext, data, aspectRatioId\)
- 证据：llama/runner/image.go L75–75 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	hash := c.hashImage\(data\)
- 证据：llama/runner/image.go L96–96 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：		c.addImage\(hash, embed\)
- 证据：llama/runner/image.go L137–141 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：type imageCache struct { 	key      uint64 	val      \[\]\[\]float32 	lastUsed time.Time }

复核 v2（MODEL，INCONCLUSIVE）：组件内静态事实基本成立：NewEmbed 第 75 行仅用图像字节计算 hash，第 77-80 行以此为唯一键查询 findImage；U0001 143-146 的 hashImage 只写入 image，U0001 151-156 的命中条件仅为 c.images\[i\].key == hash，命中即返回旧的 c.images\[i\].val；而第 83 行 mllama.NewEmbed\(llamaContext, data, aspectRatioId\) 的产物显式依赖 aspectRatioId。即缓存键（仅图像内容）不包含该影响结果的输入，命中路径也无一致性校验。但&#39;同一 data 配不同 aspectRatioId&#39;这一触发条件由本组件之外的调用方决定，源码内无法证实存在多宽高比复用同一 ImageContext 的用法，故不足以判为 VALIDATED。

反证：已检查可能抵消该问题的机制：第 75 行的键计算、143-146 行的哈希输入、151-156 行的命中判定，均未出现 aspectRatioId 或模型/上下文标识，也无命中后重算或参数比对分支；mllama 与 clip 两条分支复用同一 hash 结果。未发现任何&#39;键所含信息足以决定产物&#39;的现有防护，故不是防御充分导致的驳回，而是触发前提在组件外未证实。

待补信息：1\) 生产调用方是否会在同一 ImageContext 生命周期内，对完全相同的图像字节传入不同 aspectRatioId（若宽高比由图像自身确定性推导，则该缺陷仅停留在接口层）；2\) ImageContext 的共享范围与生命周期（是否跨请求/跨用户）；3\) 缓存容量与淘汰窗口下两次调用的实际时间间隔。
静态结论范围：COMPONENT

### LRU 缓存写入使用默认索引 0 且未校验缓存切片非空，存在越界索引风险

CWE-129 · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：本函数入参 hash/embed 由调用方传入（第 96 行 c.addImage\(hash, embed\)），其上游图像字节流处理未在本快照内提供；同时依赖结构体字段 c.images 的长度。

危险操作：第 180-182 行对 c.images\[bestImage\] 的 key/val/lastUsed 写入（第 179 行的 slog.Debug 首先解引用同一索引）。

防护缺口：缺少 len\(c.images\) == 0（或 bestImage 越界）的防护；第 167-177 行的选择循环未设置“找到候选”的标志，bestImage 保持声明时零值 0 即被使用。

前提：ImageContext.imageCacheSize 为 0，或 c.images 因其它路径被置为 nil/空切片，导致循环体一次都不执行；随后同一对象调用 addImage。

影响：索引越界导致 panic，进程（图像嵌入缓存所在服务）崩溃；在并发请求场景下可被重复触发造成可用性损失。当前无法证明可达，故为待复核假设。

修复：在写入前显式校验 len\(c.images\) &gt; 0，并在循环中跟踪是否命中候选（未命中时提前返回或改用带容量的固定长度缓存初始化）；同时在构造函数中保证 imageCacheSize 为正。

- 证据：llama/runner/image.go L180–182 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	c.images\[bestImage\].key = hash 	c.images\[bestImage\].val = embed 	c.images\[bestImage\].lastUsed = time.Now\(\)
- 证据：llama/runner/image.go L167–177 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	for i := range c.images { 		if c.images\[i\].key == hash { 			bestImage = i 			break 		}  		if c.images\[i\].lastUsed.Compare\(best\) &lt; 0 { 			best = c.images\[i\].lastUsed 			bestImage = i 		} 	}
- 证据：llama/runner/image.go L164–165 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	best := time.Now\(\) 	var bestImage int

复核 v2（MODEL，REJECTED）：claim 的前提是 c.images 为空切片（长度 0），此时 for i := range c.images 不执行、bestImage 保持零值 0，随后第 179-182 行以 0 号下标访问。但原始代码显示 c.images 只在构造函数 NewImageContext 中通过 c.images = make\(\[\]imageCache, imageCacheSize\) 初始化，且 imageCacheSize 是常量 4；全仓检索未发现任何将 c.images 置为 nil/空切片或重新赋值的路径。因此在该组件契约下 c.images 长度恒为 4，range 循环必然至少执行一次，bestImage 始终是 \[0,4\) 内的有效索引，第 179-182 行的下标访问不会越界。claim 所述 precondition 被源码直接否证。

反证：U0001 第 48 行 c.images = make\(\[\]imageCache, imageCacheSize\) 固定分配；U0001 第 15 行 const imageCacheSize = 4。搜索 &quot;.images =&quot; 仅命中该处初始化，无其它写入/清空点。因此不存在 len\(c.images\)==0 的可达状态，声明为 int 零值 0 的 bestImage 也未造成越界。

待补信息：无（本快照内 c.images 的构造与长度已被完整证据确定）。若未来有代码把 c.images 重新切片或置空，则需重新评估；当前快照不存在此类路径。
静态结论范围：COMPONENT

### 图像缓存命中判定未区分未初始化条目：零键槽位被当作有效命中并返回空嵌入

CWE-754 · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：外部请求携带的图片字节（NewEmbed 的 data）经 hashImage 计算出的 uint64 键

危险操作：findImage 中 c.images\[i\].key == hash 判定后 return c.images\[i\].val, nil

防护缺口：未用哨兵键/初始化标记区分空槽位，也未把 hash==0 或 val==nil 显式当作未命中

前提：进程已构造 ImageContext 且 images 缓冲存在未写入槽位（构造后即成立），且出现键值为 0 的查询

影响：调用方获得 nil 嵌入且 err==nil，可能把空嵌入当作有效向量继续推理，或在下游对 nil 解引用

修复：为 imageCache 增加 valid 标志或使用非零哨兵键；把 hash==0 与 val==nil 归为未命中路径

- 证据：llama/runner/image.go L153–156 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：		if c.images\[i\].key == hash { 			slog.Debug\(&quot;loading image embeddings from cache&quot;, &quot;entry&quot;, i\) 			c.images\[i\].lastUsed = time.Now\(\) 			return c.images\[i\].val, nil
- 证据：llama/runner/image.go L151–151 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：func \(c \*ImageContext\) findImage\(hash uint64\) \(\[\]\[\]float32, error\) {
- 证据：llama/runner/image.go L48–48 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	c.images = make\(\[\]imageCache, imageCacheSize\)
- 证据：llama/runner/image.go L143–146 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
- 证据：llama/runner/image.go L80–80 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	embed, err := c.findImage\(hash\)

复核 v2（MODEL，REJECTED）：findImage 确实以 key==hash 作为唯一命中判据（U0009:153-156），而 images 由 make 初始化为零值槽位 key=0/val=nil（U0001:48），因此在语义上空槽与有效条目无法区分，缺少 valid 标志/哨兵键这一防御确实缺失（DEFENSE\_GAP 成立）。但要触发 \(nil,nil\) 静默返回，必须让 c.hashImage\(data\) 的输出恰好等于 0。hashImage 使用 maphash.Hash（U0001:143-147），其种子为进程随机、Sum64 在 2^64 空间内近似均匀，调用方提供的图片字节无法选定、预测或廉价地迫使该输出为 0（期望约 2^64 次尝试）。因此在该组件的输入边界（NewEmbed\(data\) 的字节入参）上，攻击者无法把输入推进到“命中空槽”这一危险状态：INPUT\_CONTROL 与承载它的 EXTRA\_PRECONDITION 均被反驳，REACHABILITY 也相应被反驳。该缺陷是一条真实的潜在正确性/健壮性瑕疵，但不能够经由所述符号输入被触发，故不构成可辩护的漏洞主张。

反证：已考虑并核实：findImage 若未命中会返回 errImageNotFound（U0009:160），因此正常路径不会误返回；NewEmbed 仅在 findImage 返回 nil error 时直接使用 embed（U0004:80-81）。问题在于空槽（key=0）会被判为命中，代码中不存在 valid 标志或非零哨兵键。反向证据：hash 由 maphash 随机种子产生，非攻击者可选；无证据显示 hash==0 可被业务输入选定。

待补信息：无关键缺口。唯一前提是“hashImage 输出恰为 0”，该前提不可由组件输入控制；未观察到任何种子可控、可预测或可廉价碰撞的证据。本结论限于该组件局部边界，不涉及部署后的整体服务。
静态结论范围：COMPONENT

### 跨请求共享的图像缓存仅以非加密 64 位散列作为唯一身份，命中路径无内容或来源复核

CWE-328 · MEDIUM · 复核 REJECTED · 验证 NOT\_RUN

输入：外部图片字节（NewEmbed 的 data）→ hashImage → uint64 键

危险操作：findImage 中 if c.images\[i\].key == hash 的匹配及随后的 return c.images\[i\].val, nil

防护缺口：未校验图片长度、内容指纹或请求来源，未使用加长/带密钥摘要，命中后无二次确认

前提：调用方能提交图片字节并可与另一条缓存条目同时驻留（容量仅 4 槽）；两次请求复用同一 ImageContext 实例

影响：键碰撞导致当前请求拿到另一张图片的嵌入向量，形成跨请求/跨用户的语义数据串扰与错误输出

修复：以 128/256 位抗碰撞摘要或 内容长度+摘要 组合做缓存身份，并在命中时做最小指纹复核

- 证据：llama/runner/image.go L153–153 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：		if c.images\[i\].key == hash {
- 证据：llama/runner/image.go L143–146 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
- 证据：llama/runner/image.go L25–26 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	images    \[\]imageCache 	imageHash maphash.Hash
- 证据：llama/runner/image.go L15–15 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：const imageCacheSize = 4
- 证据：llama/runner/image.go L80–80 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	embed, err := c.findImage\(hash\)

复核 v2（MODEL，REJECTED）：findImage 仅比较 c.images\[i\].key == hash 且命中即返回该槽位缓存值（U0009 151-161），缓存身份确实完全由 hashImage 的 64 位结果决定（U0001 143-147），且 NewEmbed 把外部 data 直接送入 hashImage 并把结果交给 findImage（U0004 75、80）。但候选结论依赖的关键前提是“攻击者可让两张不同图片得到同一 hash 并被同一实例缓存”，而 hashImage 使用 hash/maphash（U0001 6、143-147）：maphash 是带进程内随机种子的非密码学摘要，种子的取值不经由 NewEmbed 的任何参数进入，调用方只能决定被摘要的字节，无法决定或观测摘要值，也无法预测该 ImageContext 实例的种子，因此在给定接口上不具备“构造碰撞”的输入控制。另一方面缓存仅 4 槽（U0001 15），即使纯偶然碰撞，任意两个不同图片在同一实例内映射到同一 64 位值的概率约 2^-64 量级，远不构成可用攻击面。故该发现只描述“非密码学摘要 + 命中不复核内容”的健壮性/纵深防御改进（换用 128/256 位摘要或内容长度复核），不构成可辩护的静态漏洞；候选自身也承认碰撞构造与多使用者共存未经证实。

反证：1\) 摘要算法为 hash/maphash（U0001 6），非可预测/可逆的固定种子散列，攻击者无法将指定图片映射到指定 hash；2\) 缓存容量固定为 4（U0001 15），偶然碰撞概率极低且不随攻击者请求数线性放大（每次 addImage 覆写槽位）；3\) NewEmbed 对外部 data 有 len\(data\) &lt;= 0 校验（U0004 71-73），并持有 c.mu 串行化读写（U0004 77-78），不存在并发篡改缓存键值的路径；4\) 命中只返回该键已在同一 ImageContext 内建立的嵌入向量，调用方并未被授予跨信任边界的身份提升，缺少“另一张图片属于不同用户/更高权限”的源码证据。

待补信息：该组件被部署为多用户共享 runner 时，是否真的存在不同安全上下文（不同会话/用户）复用同一 ImageContext 实例；以及寻找该实例 maphash 种子或碰撞对所需的额外攻击能力（本静态范围内无源码支持）。
静态结论范围：COMPONENT

### hashImage 在互斥锁保护范围之外读写共享 maphash.Hash，并发请求造成数据竞争与缓存键串用

CWE-362 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：NewEmbed\(U0004\) 的 data \[\]byte 图像原始字节（来自 runner 请求路径），以及并发调用者调度

危险操作：c.imageHash.Reset\(\)/Write/Sum64 对 ImageContext 共享字段的无锁读写（U0008 第 144-146 行）

防护缺口：未在 hashImage 内部或调用点（NewEmbed 第 75 行）取得并持有 c.mu；共享 hasher 也未做拷贝或每请求实例化

前提：同一 \*ImageContext 实例被两个以上 goroutine 并发调用 NewEmbed（真实部署下的并发请求），或 hashImage 与 findImage/addImage 之外的其他持锁路径交错调用

影响：数据竞争与哈希状态污染；缓存键计算错误可导致返回其它图片的嵌入向量（缓存投毒/结果错乱），影响推理结果正确性

修复：将 hashImage 调用移入 c.mu.Lock\(\) 之后（或改为函数内先加锁/使用每调用局部 maphash.Hash 实例，例如在 NewEmbed 中局部构造并 MakeSeed 初始化），确保所有对 imageHash 的访问都在同一互斥范围内；并对并发路径补充 -race 测试

- 证据：llama/runner/image.go L144–146 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
- 证据：llama/runner/image.go L75–77 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	hash := c.hashImage\(data\)  	c.mu.Lock\(\)
- 证据：llama/runner/image.go L17–27 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：type ImageContext struct { 	// mu is required to be held when generating embeddings or accessing the cache 	mu sync.Mutex  	clip   \*llama.ClipContext 	mllama \*llama.MllamaContext  	// cache of images to embeddings 	images    \[\]imageCache 	imageHash maphash.Hash }

复核 v2（MODEL，VALIDATED）：U0008 的 hashImage 对接收者字段 c.imageHash（U0001 第 26 行声明的 maphash.Hash）执行 Reset/Write/Sum64；该字段属于 \*ImageContext 的共享可变状态。U0004 在调用点第 75 行先执行 hash := c.hashImage\(data\)，直到第 77 行才 c.mu.Lock\(\)，因此哈希计算及对共享 hasher 的读改写全部发生在互斥范围之外。U0001 第 18-19 行注释明示「访问缓存/生成 embedding 时须持有 mu」，说明该类型契约即面向并发共享使用；在此契约下两个 goroutine 并发调用 NewEmbed 会对同一 imageHash 无同步读改写，构成 Go 数据竞争，且计算出的键可能串用，使 findImage/addImage 命中/写入错误条目。此为组件级静态结论：局部边界内共享字段被无锁改写且传入 data 经 hashImage 到达该 sink。

反证：已考虑：findImage/addImage 的缓存读写确实被 c.mu 保护（U0004 77-78、U0008 上下文），但保护范围不覆盖第 75 行的 hashImage；代码中不存在每调用局部 hasher（如局部 maphash.Hash/MakeSeed），也无将 imageHash 拷贝后再使用的写法；hashImage 内部亦未自行加锁。传入的 hash 虽为局部变量，但其值来自被并发污染的重置/写入状态，无法消除竞争本身。

待补信息：未提供调用方/路由证据，无法确认实际部署中多个 goroutine 是否共享同一 \*ImageContext 实例（若有则竞争触发；若每请求独立实例则不触发）；未运行 -race 测试，竞争为静态推断而非运行观测。
静态结论范围：COMPONENT

### Free 未持锁且未失效化状态，可导致原生上下文竞争释放/重复释放（UAF/双重释放）

CWE-416 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：外部生命周期控制（调用方传入的 modelPath 与调用时机，如 runner 卸载/重载模型时调用 Free）；modelPath 参数在函数体内完全未使用，说明该入口由内部状态机驱动

危险操作：c.clip.Free\(\) 与 c.mllama.Free\(\)（第 59、62 行）对底层 native 上下文执行释放

防护缺口：① 未在释放前后加锁 c.mu（与第 18–19 行“mu is required to be held when generating embeddings or accessing the cache”的约定不一致），无法与第 77–97 行持锁的 NewEmbed 互斥；② 释放后未将 c.clip/c.mllama 置为 nil，也未设置 freed 标志，重复调用 Free 会再次进入释放分支；③ 未校验 c.clip 与 c.mllama 是否可能同时非 nil 或已被释放

前提：存在并发或重复调用路径：例如 Free 与 NewEmbed 在不同 goroutine 并行执行，或同一 ImageContext 被 Free 两次；需外部调用方具备该调度行为（调用图不完整，未能确证）

影响：对已释放的 native 上下文再次释放或在使用中释放，可能导致进程崩溃（segfault）、堆内存破坏，或把已释放上下文交给后续嵌入计算导致未定义行为与信息错配

修复：在 Free 开始时获取 c.mu（或改为显式生命周期/关闭状态机），释放后立即将 c.clip、c.mllama 置 nil 并设置 closed 标志，使其对重复调用幂等；要求调用方保证不再并发使用该上下文，并在注释与接口中明确 Free 与 NewEmbed 的互斥语义

- 证据：llama/runner/image.go L58–63 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	if c.clip \!= nil { 		c.clip.Free\(\) 	} 	if c.mllama \!= nil { 		c.mllama.Free\(\) 	}
- 证据：llama/runner/image.go L53–56 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：func \(c \*ImageContext\) Free\(modelPath string\) { 	if c == nil { 		return 	}
- 证据：llama/runner/image.go L18–19 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	// mu is required to be held when generating embeddings or accessing the cache 	mu sync.Mutex
- 证据：llama/runner/image.go L77–79 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	c.mu.Lock\(\) 	defer c.mu.Unlock\(\) 

复核 v2（MODEL，INCONCLUSIVE）：在 COMPONENT 边界上，Free\(modelPath\) 确实在第 58–63 行直接调用 c.clip.Free\(\)/c.mllama.Free\(\)，且释放后未将 c.clip/c.mllama 置为 nil，也未设置 closed 标志，因此从纯静态代码看“重复调用 Free 会再次进入释放分支”这一路径成立；同时该函数体内完全未出现 c.mu（第 18–19 行注释声明 c.mu 在生成 embedding 或访问 cache 时须持有），与持锁的 NewEmbed 之间没有显式互斥。但：① 参数 modelPath 在函数体内未被使用，攻击者无法通过该输入控制是否释放或释放哪一个上下文；② 触发双重释放/竞争释放依赖于“同一 ImageContext 被 Free 两次”或“Free 与 NewEmbed 并发执行”这类调用方/生命周期行为，本目标未给出任何调用点或并发证据；③ 底层 llama.ClipContext.Free / llama.MllamaContext.Free 是否幂等、重复释放是否真会导致 UAF/堆破坏，也未在本目标中提供。因此缺少关键条件，只能判定为 INCONCLUSIVE，不能升级为完整部署漏洞。

反证：Free 第 54–56 行有 c == nil 空指针防护；第 58、61 行在调用底层 Free 前分别做了 c.clip \!= nil、c.mllama \!= nil 的非空判断；这些说明作者已考虑部分生命周期防护，只是未覆盖重复释放与并发。

待补信息：需要：① llama.ClipContext.Free/MllamaContext.Free 的实现或幂等性说明，确认重复释放是否造成 double-free/UAF；② Free 的调用点（是否存在错误路径或生命周期重入导致二次调用）；③ 是否存在 Free 与 NewEmbed 并发的调用调度证据；④ c.mu 的语义约定是否覆盖 Free（注释仅提“生成 embedding 或访问 cache”）。
静态结论范围：COMPONENT

### hashImage 在互斥区之外操作共享 maphash.Hash，并发请求下产生数据竞争与错误缓存键

CWE-362 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：NewEmbed 的 data \[\]byte（图像字节流，外部输入）经第 75 行 hash := c.hashImage\(data\) 进入哈希逻辑

危险操作：c.imageHash.Reset\(\) / c.imageHash.Write\(image\) / c.imageHash.Sum64\(\)（第 144–146 行），以及第 75 行的调用点

防护缺口：未在 hashImage 内或调用点持有 c.mu；共享的 maphash.Hash 未加锁、也未改为局部 hash.Hash（如每调用创建 maphash.MakeSeed 后的局部实例或 sha256 局部实例）

前提：两个及以上请求并发调用 NewEmbed（或任何并发调用 hashImage 的路径）；需要外部并发输入调度

影响：数据竞争（Go race detector 会报告）；哈希结果可能对应另一请求的字节流，导致 findImage 命中错误缓存条目并返回不匹配图像的嵌入（跨请求结果混淆），或哈希内部状态被同时读写而异常

修复：把 c.mu.Lock\(\) 提前到 hashImage 调用之前，或在 hashImage 内部使用局部/每次调用新建的 hash 实例；若需要抗碰撞/抗猜测键，改用带密钥的加密哈希（HMAC-SHA-256）并明确缓存键的信任属性

- 证据：llama/runner/image.go L143–147 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\) }
- 证据：llama/runner/image.go L75–75 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	hash := c.hashImage\(data\)
- 证据：llama/runner/image.go L24–26 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：	// cache of images to embeddings 	images    \[\]imageCache 	imageHash maphash.Hash

复核 v2（MODEL，VALIDATED）：U0001 中的 ImageContext 明确定义了并发契约：结构体注释（第18-19行）写明“生成 embedding 或访问缓存时必须持有 mu”，且 c.imageHash 就是该缓存的一部分（第26行，与 images 同属缓存字段），整个结构体因此被设计为可被多个 goroutine 共享调用。但 hashImage（第143-146行）对共享的 c.imageHash 执行 Reset/Write/Sum64，既未加锁，也未被任何内部同步保护；其唯一调用点在第75行，位于 c.mu.Lock\(\)（第77-78行）之前。因此并发调用 NewEmbed 时，多个 goroutine 会在锁外同时读写同一个 maphash.Hash 实例：Reset 与 Write 交错会使内部状态（state/n/buf）被同时访问，Sum64 得到与传入 data 不对应的哈希，再经 findImage（第151-157行）以错误 key 命中 cache 条目，可能把另一张图的嵌入返回给当前请求（跨请求结果混淆）。这是组件自身接口上的锁纪律违规，不是外部附加能力假设。未发现内存越界写（maphash.Hash 为定长字段，竞争导致错误哈希值而非指针破坏），故 MEDIUM 的后果描述与代码相符。

反证：已核查：NewEmbed 第77-78行确实用 c.mu 保护了 findImage/addImage 及视觉模型调用，因此缓存读写在锁内是安全的——缺陷仅限于第75行锁外的哈希计算路径；data 的零长度在71-73行被拒（避免空输入），但不影响竞争。也未发现 hashImage 内部存在任何同步、每调用局部 hash 实例（未新建 maphash.MakeSeed 或 sha256），或把哈希移入锁内的替代实现。maphash.Hash 不含并发同步机制，故不存在令该竞争“安全”的语言/库语义。

待补信息：部署层是否真有多个 goroutine 并发调用同一个 ImageContext.NewEmbed（本次静态分析只能看到组件内的互斥锁契约、共享 imageHash 字段与锁外调用点，无法观测实际调度）；未运行 Go race detector 或任何动态验证。组件级前置条件：NewImageContext 已成功初始化、由调用方并发复用同一 \*ImageContext。
静态结论范围：COMPONENT

### EmbedSize 回退分支未校验 llamaContext，可能解引用空指针

CWE-476 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：调用方传入的 \*llama.Context（llamaContext）与接收者 \*ImageContext（c）

危险操作：第 123 行 llamaContext.Model\(\).NEmbd\(\) —— 在未检查 llamaContext 的前提下调用其方法

防护缺口：缺少对 llamaContext 的 nil 校验（也缺少与第 120 行 c \!= nil &amp;&amp; c.mllama \!= nil 一致的显式防御）；nil 时无错误返回路径，函数签名也不返回 error

前提：c 为 nil，或 c.mllama 为 nil（即未加载 mllama 后端而走 else 分支），同时上层传入 llamaContext == nil

影响：运行时 panic，导致当前进程/请求崩溃或连接中断；若被远程请求路径触发可用作廉价的拒绝服务

修复：在该回退分支前显式判断 llamaContext == nil 并采用安全返回值或错误路径，或让调用方保证非 nil；同时统一 c/mllama/llamaContext 的校验策略

- 证据：llama/runner/image.go L123–123 ；产物 c762e2bd-0068-4c42-a28e-e20d58e54dc2；引用：		return llamaContext.Model\(\).NEmbd\(\)

复核 v2（MODEL，INCONCLUSIVE）：代码层面事实成立：EmbedSize 第120行仅校验接收者与 mllama 字段，第123行在 c == nil 或 c.mllama == nil 时无条件执行 llamaContext.Model\(\).NEmbd\(\)，形参未做 nil 判断，且函数返回 int、无 error 回退路径，故一旦收到 nil 的 \*llama.Context 就会 panic。但触发该缺陷需要“调用方在本组件接口上传入 nil llamaContext”这一具体条件成立；快照内没有任何 EmbedSize 调用点，无法确认上层是否（例如视觉后端加载失败时）会传入 nil，因此不能静态确证该分支可被实际触发，判为 INCONCLUSIVE。

反证：仓库其他函数（NewEmbed 第83/88行、BatchSize、NeedCrossAttention）同样未校验 llamaContext，说明代码把“llamaContext 非 nil”当作隐式调用契约；NewImageContext 在第37/39行会用调用方传入的 llamaContext 构造后端，暗示正常流程中它由更上层保证非 nil。这些是契约层面的反证，但并未在 EmbedSize 内形成显式拒绝 nil 的校验。

待补信息：缺少 EmbedSize 的调用点：无法确认调用方是否可能传入 nil 的 llamaContext（例如后端未加载/加载失败路径下复用同一 ImageContext），以及上层是否已有未展示的 nil 校验。这属于组件调用契约条件，不属于额外攻击者能力。

## 关键逻辑与人工修订

- u\_72dc10c49e40ba8729b36e096b415789 · CRYPTOGRAPHY · v1（MODEL）：hashImage 调用标准库 hash/maphash 计算 64 位摘要，仅作为图像嵌入缓存去重键使用，不参与口令、密钥派生或完整性校验；属于散列逻辑但非安全用途，且为非加密散列，评审时应与安全哈希场景区分。
  - 原文：llama/runner/image.go L143-L146；func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
  - 原文：llama/runner/image.go L75-L75；	hash := c.hashImage\(data\)
- u\_8581aec77c9ecae72cfd77f81b51a36c · AUTHENTICATION · v1（MODEL）：NewEmbed 第 67 行对 c == nil 直接返回 nil,nil，第 92-93 行对未加载视觉模型返回错误；这是“视觉能力是否可用”的能力判定而非身份认证。第 77 行 c.mu 起到同一 ImageContext 内的会话/状态串行化作用，第 66-100 行未见任何调用方身份、权限或配额校验，也无跨请求所有者隔离，故仅作状态边界登记，不判定为鉴权缺陷。
  - 原文：llama/runner/image.go L67-L69；	if c == nil { 		return nil, nil 	}
  - 原文：llama/runner/image.go L92-L93；		} else { 			return nil, errors.New\(&quot;received image but vision model not loaded&quot;\)
- u\_8581aec77c9ecae72cfd77f81b51a36c · CRYPTOGRAPHY · v1（MODEL）：缓存键使用 hash/maphash 的 Sum64 对图像字节求值（hashImage），仅用于以 64 位键查找 imageCache，未参与身份认证、完整性校验或密钥派生；属非密码学用途，但仍按哈希逻辑单列以便复核其碰撞/复用影响。
  - 原文：llama/runner/image.go L75-L75；	hash := c.hashImage\(data\)
  - 原文：llama/runner/image.go L143-L147；func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\) }
- u\_8f47aec19010dce631f126a009a1c48f · CRYPTOGRAPHY · v1（MODEL）：hashImage 对图像字节执行 hash/maphash 的 Reset/Write/Sum64，用于同进程内缓存去重键，而非口令、签名或完整性校验；它是非加密哈希且带进程随机种子，因此不能作为安全摘要使用，仅在此登记该密码学相关操作（本身不构成漏洞）。
  - 原文：llama/runner/image.go L143-L146；func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)

## 覆盖与错误

```json
{
  "audit_config": {
    "max_model_calls": 240,
    "max_output_tokens": 0,
    "max_tool_rounds": 8,
    "max_units": 20,
    "model_timeout_seconds": 900,
    "reasoning_effort": "high",
    "timeout_seconds": 1800
  },
  "audit_narrative": {
    "limitations": [
      "无任何运行时证据：dynamic_execution=NOT_RUN，全部发现 verification_status=NOT_RUN；本报告只能区分静态验证、假设与被驳回候选，不能确认可利用性、影响范围或真实触发条件。",
      "评审结论存在内部不一致：同一 hashImage 锁外访问问题分别被判为 REJECTED 语境、INCONCLUSIVE 与 VALIDATED，且重复成多条，结论口径需统一后才适合作为最终判定。",
      "覆盖范围受限于目标快照：audited_units=10/total_units=10 但结构警告为空、注解为空，缺少调用方代码、部署方式与线程模型信息，因此缓存共享范围、Free 的调用约定、EmbedSize 回退分支可达性均无法确认。",
      "原生依赖（mllama/llama 上下文）的实际所有权、释放语义与并发安全属性未知，涉及释放/重复释放与空指针的判断无法在纯静态条件下闭环。",
      "类别与哈希强度类问题分属 AUTHORIZATION 与 MEMORY_BOUNDS，分类的可信度受限；缓存键碰撞/猜测风险在无攻击者模型与密钥假设时不能被确认。",
      "缺少独立复核记录与人工注解作为交叉证据，本摘要仅汇总已保存发现的评审状态，不新增、不升级任何结论，也不替代对原始代码的复核。"
    ],
    "recommendations": [
      "优先处理静态验证通过的 hashImage 竞争问题（af38bd02 / 7c2da3d8）：把散列计算移入同一互斥范围或改为每次调用局部 hash 实例，并补充 -race 回归测试后再评估是否可升级验证状态。",
      "合并重复发现：af38bd02 与 7c2da3d8 为同一根因，应作为单一条目跟踪；同时裁决 97b2a968 与它们结论不一致的原因（评审标准或证据差异），避免同一问题出现三种结论。",
      "为 INCONCLUSIVE 条目补齐缺失证据：a4208a32 需要调用方是否跨宽高比/跨模型复用同一缓存实例的证据；a005b821 需要 Free 与并发使用、重复调用的调用约定证据；0b841efe 需要回退分支可达性与 nil 来源的路径证据。",
      "把缓存键身份问题按信任边界单独归类与评估：确认缓存是否跨请求/跨用户共享，是否需要在命中时做来源或内容指纹复核；若仅用于性能去重，应显式声明该假设并写入接口契约。",
      "修正分类与去重：将并发数据竞争类问题统一归类，把缓存键强度与身份问题与内存越界类分开，避免不同类别下重复计数。",
      "安排动态验证以关闭当前缺口：至少执行竞态检测与并发压力测试、Free 与并发嵌入的交互测试、多宽高比请求的缓存命中对比测试；在此之前所有发现应保持未通过运行时验证的状态。",
      "向读者明确：4 条 REJECTED 项是被驳回的候选（现有静态证据不足），不得在叙述中当作已确认缺陷；2 条 VALIDATED 项也仅为静态验证，不等于已复现。"
    ],
    "summary": "本轮为纯静态审查（static_review_only=true，dynamic_execution=NOT_RUN），对当前不可变目标共 10/10 单元完成覆盖（audited_units=10，total_units=10），无结构告警，人工注解为空（SAME_SNAPSHOT_IDENTICAL_CODE 范围内无参考条目，因此未引入任何外部主张）。数据库已保存 10 条发现，按评审状态分布为：2 条 VALIDATED（静态验证）、4 条 INCONCLUSIVE、4 条 REJECTED；全部发现的 verification_status 均为 NOT_RUN，即都没有经过运行时验证，也没有崩溃、竞态检测器输出或原生库行为证据。\n\n已验证（VALIDATED，仅静态层面）：af38bd02 与 7c2da3d8 指向同一根因——hashImage 在互斥锁保护范围之外读写共享 maphash.Hash，并发请求可能造成数据竞争与缓存键串用/错用。两条记录描述实质相同的问题，属于重复条目，报告层面应合并跟踪而不是叠加计数。\n\n结论不确定（INCONCLUSIVE）：97b2a968 与上述同根因但评审结论不同（锁外计算缓存键），反映出同一问题在不同评审中被给出不一致判定，需要统一裁决；a4208a32 为缓存键未纳入 aspectRatioId 及上下文标识，属语义身份/信任边界问题——静态上键构造只依赖图像内容散列，是否真实导致跨宽高比复用取决于调用方是否复用同一实例与模型状态，缺少运行证据；a005b821 为 Free 未持锁、未置无效状态，可能重复释放/释放后使用，是生命周期假设，需调用约定证据；0b841efe 为 EmbedSize 回退分支未校验 llamaContext，是潜在空指针解引用假设，取决于该分支可达性。\n\n已驳回（REJECTED）：45e050e4 与 39448e46（以非加密 64 位散列作为缓存身份、命中路径无内容复核）、260db39b（LRU 写入默认索引 0 的越界风险）、48538ccd（零键槽位被当作有效命中返回空嵌入）。驳回说明现有静态证据不足以支撑这些路径可利用，属于未证实的候选而非结论。\n\n需要报告读者注意的一致性瑕疵：同一 hashImage 竞争问题被拆成 3 条发现且分属 AUTHORIZATION 与 MEMORY_BOUNDS 两个不同类别；缓存键强度类问题也分散在 AUTHORIZATION（45e050e4、39448e46）与 MEMORY_BOUNDS。类别分配与问题性质（并发/竞态通常归并发或内存安全；缓存键身份更接近信任边界）不匹配，建议在分类体系中复核。"
  },
  "audited_unit_count": 10,
  "edge_count": 31,
  "eligible_unit_count": 10,
  "exclusions": [],
  "files": [
    {
      "language": "go",
      "path": "llama/runner/image.go",
      "reason": "",
      "status": "PARSED",
      "unit_count": 10
    }
  ],
  "finding_count": 10,
  "function_count": 9,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 0,
  "independent_review": "COMPLETED",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 9,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "b783cb05475c436ddcf76b87881c58408174ec1d6dd4f8242442e7bd108018bf",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 136,
    "cost_cny": null,
    "measured_tokens": 584799,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "c762e2bd-0068-4c42-a28e-e20d58e54dc2",
  "reviewed_finding_count": 10,
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
      "finished_at": "2026-09-11T07:44:45.256Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:44:45.254Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 10,
  "unresolved_calls": 31,
  "verification": "NOT_RUN",
  "vulnerability_audit": "COMPLETED",
  "warnings": []
}
```

任务错误：

## 证据产物

- aegis-report-d00a0c6b-35e0-473b-88e8-422770c527a3.html；ID：33615f39-d3a9-48cc-9148-3ed634fffdfa；SHA-256：bc6631645d01962dfdb6b52ece3778d8b3dae24ce78bf17a3c1847da89be659e
- aegis-report-d00a0c6b-35e0-473b-88e8-422770c527a3.json；ID：a02db377-2448-4a4a-964c-92fbd4ff8b8b；SHA-256：0058f1d390b6aa61cd064ebd78183b79d04d9f5ba9e70a9b94c75f4e7c44caba
- agent-AUDITOR-0183c61f-3b96-422b-b12d-a42de65f57af.json；ID：89985561-d0b1-4d89-bdf4-365fa8429a09；SHA-256：7417b8165fbc8c619fe2e055f23ac7fcc1154083310652d6dabe11707ee6dab8
- agent-AUDITOR-06255b73-e010-42aa-9db0-0402815881a0.json；ID：f0361b9d-1487-4eeb-a7b4-faeafe9367e1；SHA-256：d62198b8d17c757b654e359796e10f99573dcf24d9d780a5a58d9708c344b21e
- agent-AUDITOR-0bc02b5b-7bc8-47f7-add4-858bb91bafb4.json；ID：75c1bedb-5c8c-441b-bb4d-209d1676c561；SHA-256：aa9e43d5c7344c47badbc63e42646b1ca1452703e27b7ec2a1841bd0b07fb799
- agent-AUDITOR-30d30e74-c0c2-451c-8cbd-70b8ba181514.json；ID：327a5562-8b64-43c0-bed4-4350eeb5f663；SHA-256：2d6e538f248ee1ade3afc1317fe1449c466baded01ac7881b2d69d376a783504
- agent-AUDITOR-392d3aa5-6a7b-4885-bbef-e5ecd0dc6c6f.json；ID：5e9f27af-33f2-4f36-8b34-59ec60a34398；SHA-256：f985b51ae1fd818d4d9d9235ba5c63139bea4b463e9bfba37b2ad9ef61f87c94
- agent-AUDITOR-5bcdedf5-b020-4a0e-9d03-f6377e17ed35.json；ID：eeaec294-581b-4a92-b2f4-bf8e85173b27；SHA-256：4dd5ac3edea030978b8aabef6b1233f11384126a459e374b24d5c977205565d0
- agent-AUDITOR-604c9cef-fc14-47ee-b469-34b9136f95f5.json；ID：f6ea6956-bbdd-438c-a5e4-570e57760fcf；SHA-256：0857b7c225b6e87b424302ff47ada2d15ca2c0febf8de46e5a642c315a6a5638
- agent-AUDITOR-7da7d86f-22ee-418c-b0b9-f0fa19f33872.json；ID：82293c4d-462e-41c8-a1b3-189f7ff1b35e；SHA-256：b871bdd0592f53486238f828c8c163df4cec9355e940cf28cd294260cbac4e3a
- agent-AUDITOR-c0817864-7d4b-4942-8e9f-ecd0ca775466.json；ID：326567d2-6ece-4f9d-b677-3f50065980fb；SHA-256：b538755649bf1a3f586294a9cb18c62c2e014da007bc88f145111bcc117a2169
- agent-AUDITOR-f57def0f-061a-4864-9d8e-68895db84c55.json；ID：9483336d-2894-49f2-a9fe-5ce9f573b067；SHA-256：3facd97363ec6f74f591ac6d6b223a9f2889830d131aa251aace2977b985fa0f
- agent-PLANNER-83dac943-5076-42de-962e-9eb221ae77fb.json；ID：30ef4be1-46d5-42ce-8652-cc300a3c4997；SHA-256：f47bbc86ce707468fea4b4bbecaddfafc1d1440dc29f90b52bea2cf6f7ad3c76
- agent-REPORTER-b5557658-5512-42cb-9c28-7fe7177e8151.json；ID：91bce003-56dc-48f9-a3db-bb09567657a1；SHA-256：31e068398e51b3103798e16ee41cf97711a658c02136b661ef63f5bad8897a61
- agent-REVIEWER-13b672bf-fc35-4e5c-ad7f-3edf92161f7e.json；ID：ca1bf80f-2ab5-45d1-b49f-e20edad9c832；SHA-256：6b772fddf328b21dc9f91b9eadfe069f47f9cb2a5653ff7addeab9ea76bc12e8
- agent-REVIEWER-1781bfc4-8e93-4072-9a4c-c3888bc083fc.json；ID：f187efd1-50f7-45ce-8d1b-7ae144d59450；SHA-256：7089a6369e9bb6925a61a956703618dd3eb788837ac773eaeb7d57313737b320
- agent-REVIEWER-1af9ebd0-3edd-4385-b7e5-7154d14d3aec.json；ID：5eb71e9c-3f8f-400c-8d2a-0261b89c7829；SHA-256：4b65b27eda13b5e3c2419d2d6e564521f94ae3e46290396a186865a976f79f36
- agent-REVIEWER-53ef7199-e714-4879-8d40-98dfa1cc3be6.json；ID：c08024e3-4644-48d2-b756-7591142b13ec；SHA-256：cd0f65e7b9400684b74fcbc29a924d28a0786778ce25a83f84a09dc29dd70824
- agent-REVIEWER-6047115a-2edc-48cd-afea-0b62eaf9745f.json；ID：cf62b553-e3ba-4519-938b-5c27020dd443；SHA-256：5b11993306e82df0005dd2e22e7a2681516f07c014f08023862e1e419faf033a
- agent-REVIEWER-b1a1f8ed-69f6-4473-ad12-38804d8b004c.json；ID：f11d73d9-22f5-47ed-bdb3-ba07359e1fc2；SHA-256：32af75893e5462a20b4611c143f062310da7e94109ff5286f6f29831cc0004d4
- agent-REVIEWER-edb37d7d-c046-438f-b66a-9033e6be3dac.json；ID：0bd9fe71-521d-4396-ada4-8393f90deae8；SHA-256：6cb516294563c76863b625b676a91ddfe3d49130478f92bba3f87b5027204c1e
- agent-REVIEWER-f28896dc-27b6-4ac4-a146-b43540c58658.json；ID：aefec0c6-af1c-4a8e-8e90-117cf1463ee8；SHA-256：6bb183be7a46693a9f56e923061d0ee27f2f21463e96f762947084ba9d5f049a
- agent-REVIEWER-faa7fe43-bb08-4794-b683-dafb67b71f02.json；ID：7a1980dc-fd25-4465-9454-ebd23f1446a1；SHA-256：1f151ccb482a2a810c36191a533ce03eba7e04f8370352b42a37982119dde6b0
- agent-REVIEWER-fcd74840-4db7-4d43-b0c7-05c8939f0307.json；ID：7f8c73ca-c90d-4460-a00d-3cc26828d90d；SHA-256：7dd1d1d865fa07539bb6e60330d41bdecefef1d64759a0fbe63b0addc1459309
- agent-VERIFIER-d2942f9b-fb78-4163-b819-d0483ce73fb1.json；ID：5cbd830d-cbe0-4290-bab2-4187e335b454；SHA-256：de5b76d6027de09420217a164e3ee9eea2b83d41885e5982b047a6424613d685
- agent-VERIFIER-e748e3c3-c24a-43f3-b712-29fc92ec1d00.json；ID：2995c903-3aec-42d6-b59d-93e043301b3d；SHA-256：083530a0171b9d406cf799c75523317347b118e011701c0b258411800d36a181
- analysis-result.json；ID：c762e2bd-0068-4c42-a28e-e20d58e54dc2；SHA-256：1144b098108a858249c9b387feef9ff99c9a4f6a08be1b3b5934d5ef442b1ac7
- model-request-01196502-02e7-4306-afaf-232ea986a2fc.json；ID：428128a5-453c-43f2-a94b-44c0c11e6259；SHA-256：70d7a9d4a5f1499cd1a8b38b2419ccc17b947bf100d8dd6268de5e595b228a3d
- model-request-01d00bb8-1109-4f6f-b243-a15ccec95516.json；ID：29f7df9f-187c-4ddf-b714-84fcedb3a5f4；SHA-256：fba15c2ff37d83b66b7e7d737d1919c79fb362631696b93f4a671d7039aac826
- model-request-02153c6f-a6b8-45df-80bb-8d3a2aa3e73c.json；ID：6bd724cc-bdef-44e7-b1ad-52d4d339a5cd；SHA-256：c6a9a9da5e844c25af68f3c8a7c1337d3b898d27678c10a14379e56ff18c21cb
- model-request-0311a01c-afeb-444a-9a3a-fa85539b9442.json；ID：bd7b737f-bdf1-4f44-8852-61dd2e27480e；SHA-256：6b56b014a74f13be3363d9d1666e5b8a46f642f1c9de12b57af165def855aaec
- model-request-03df80b1-0748-4b21-8f2c-79edfc2318be.json；ID：74986433-8e70-4405-a563-be4710733e2b；SHA-256：bd9765d2b05fab3bfc00ad9fc558db160ad5997b62fef0b536bb2ad57c2c49a0
- model-request-0456aedf-98e2-4d1f-8d78-fae1fa5bd2f6.json；ID：f87dda68-1722-49aa-806d-6ad67cfedc62；SHA-256：39d0e9e071f4e85f9676b225fb19e77f72e41f3093d1de749b44e2199dcd12e5
- model-request-06af7c1b-f3fd-4c45-b92e-93337cdc2805.json；ID：42ad7002-beb8-4ffa-9985-686f019ae932；SHA-256：39d28b57227d54193c3ff4d04e052d031e3e18afde781a94d79c10457e3b7c28
- model-request-06f78d6d-628d-4def-b606-fde1de55f682.json；ID：16b0a0b6-fc7b-4d45-8332-b6c989eda7ce；SHA-256：1e4f37a1db3b5b62dba032a24b8defb357e143ecbedd157fdfb93552bb1eefbc
- model-request-08810c29-aad4-4c5e-b5b2-acb963506512.json；ID：6ce00c49-f22d-43a8-8955-a9023f1351cc；SHA-256：90e0ec49adb7c109ff7802c2f31f429834db12aa4e912c2e3f7e2366eea4d414
- model-request-08eddcda-8662-45e9-945c-eff2f3cd6990.json；ID：8bd33cf3-f28a-4f45-9996-3f923cd9cb75；SHA-256：38c80f5b348b90c465af94c76a57180e231e24824e3e81f46a96baa23e8f75ee
- model-request-0b7ab46b-3cd7-49de-bc51-b246c300f1f8.json；ID：2e2f904c-8232-4cb8-af5d-f2f713d2b6f8；SHA-256：68d712c636ecca3cca159065bd5b5e699760daa0452af71a25217b964597f290
- model-request-0babc9da-d63c-4b9b-8c7c-ebf962997512.json；ID：d6395432-5202-4d77-a523-e6746e01e322；SHA-256：4af57fb6e1b4bf319b2014a4734e9ed29eb0a92da53e3398dc20795cbc92e179
- model-request-0c25de39-ffa8-4621-8bc8-39c44565ef73.json；ID：95660af1-a538-4195-a25e-a4c70a29f8c8；SHA-256：3c23994a5e01e578d3caadc7b790cf521db5a46dbeb1c639c4ee4f690786bffc
- model-request-0e208004-b821-468a-b13f-9d1df6d0c164.json；ID：4a4283a5-cb01-4fbf-a69c-42acde27166f；SHA-256：f185e91c83733fb17c884d3932f2d8cd893bfb97332cf8cd2a82eafe7c112ea0
- model-request-0eb9aa40-c5ef-451c-a813-4b9e5f0be5a2.json；ID：9952f910-4f64-4010-9400-53e9f58a8fe3；SHA-256：559ab741d49d56cf33a28139d8520e596eac7821b3df251c5605aa53a486cc1e
- model-request-10a35871-4b4d-4b58-9971-9dd002b61bee.json；ID：289268d9-7178-4a1c-9f60-7babc97b4ec3；SHA-256：c7c133b73d6f6d737ea94a111036d611a0d71544ff12e135e1abd33cd298189e
- model-request-1917e80c-a545-4ec3-b671-378091d0f6a6.json；ID：12387c5a-882e-4ee2-88e6-eb3a50d2aa24；SHA-256：8daaa537bc9e2861237a4f9b75928b6876027ec26bdfabd4ea8c403bd6e08c8e
- model-request-1bcdba31-9fb4-46d6-ae6d-a36f43641074.json；ID：a2a35717-8b65-4116-b0c0-fee2e9e5f650；SHA-256：29f6c0f611489fa99d86aef1febbd4d1ceca7453b555aebc06994170679c9892
- model-request-1c7012a7-d19a-49fd-9499-2a19c8a15126.json；ID：c27bcd8b-119d-45c9-99d5-6f87d5b3dda9；SHA-256：01f0d9c70c28bc091143942a29043e3c9ead9bc476e71a7a4872eb709d6d88a1
- model-request-1ce4e4e7-b63d-4c6a-a79f-30fcacbc2e9e.json；ID：370a9334-2617-4ce6-a153-fda3fd886f73；SHA-256：2f68aa95a7c0d0acd55f164cdda947c983c27d8a3c325deb9e8cfdc43716e821
- model-request-1d84b0c9-2d0d-4529-81ab-b5a729160121.json；ID：fb023261-f632-4cab-be90-e872ff4d06ed；SHA-256：e3a023041799020a0a1a5cd97f14a1bc57e2a345332b25bc823e89e95f806ca6
- model-request-1dd38ce4-8ca4-4617-a674-5ae51d8177e6.json；ID：05cc47a2-f39a-4328-a070-41c90fa7f8bb；SHA-256：c3b1c4b471647d6f4c3884855a846042b1f0e41be704dc563abe4109643ec262
- model-request-1e38bf7e-e66e-4676-92ef-5bb9ec45fe8b.json；ID：88c93a23-eb40-4d05-b719-8d56665a1c8f；SHA-256：1ec4f434ea1aa2056c3fa1df7d4a1ca359d408704f0c98b1c3fa3297ef59b077
- model-request-218cbe22-11b5-4c38-965c-eccaba366864.json；ID：5a194ac9-f234-4ab9-abed-96c01c406898；SHA-256：0fe095edc87561c44fe197a1e3a60d477fd687ff405613b442e9cb8aa952e0d3
- model-request-21d08efc-4ea6-4eed-8c34-3be0aef88bde.json；ID：6342854a-a33b-41b1-b7b6-233b0060610f；SHA-256：5947c6f47d055994e36d190986ebe1953f83ac03e866dd3cdcfebba3152c23c8
- model-request-258be543-4606-498a-8139-4315aae57493.json；ID：ab1aba8e-1911-459d-a884-998d98ec3e30；SHA-256：04a1ad76017c8aed96a1f7ba1ce1a1deee0bb63d1d0d27e35e7546473ea6d26d
- model-request-28021f92-4ae9-4e12-b675-3908582b1157.json；ID：690230d8-0cd2-4d96-a318-ed8e9c5dd763；SHA-256：2dbb93063bb1e7b126d0b538b38f66cac29bf6d11df76bf54dc9b245fe5c7e6e
- model-request-2fbcec9a-4a5b-4a33-b21a-21db17bede9a.json；ID：282cd93c-de9b-4038-a18d-37443b6c4747；SHA-256：930e80ed39b304888fbf332d069e6b846d08969118c50965822e868720439111
- model-request-32380cb9-d556-440a-97d7-6b1d305a3e9f.json；ID：d605b4ad-3b90-4a43-b79c-c9286452244b；SHA-256：a32556b64b92fb20bc7862c724e88661b2fe1eefb450706d824a4e0154f45cc9
- model-request-340b9f4f-67c8-4464-aadb-23e65479b0b9.json；ID：4162958d-cbcc-4296-a7ce-2135bf84090c；SHA-256：8333b629ea4b16209b3e54d27c70c9d3de01b8c2ceb845adea82b9ff8b438a91
- model-request-36428594-62c9-459e-95c7-fd55e42600b0.json；ID：a625fad6-4182-48a2-9c74-06b9552193d1；SHA-256：78edcbf7de481e4fe871410749476faa042558229694d6c56f9d60d6f0382af7
- model-request-386bf773-6a38-42f2-8dba-e1731ce954ac.json；ID：5c3a241f-98fb-4451-b25e-fa3fbb4770de；SHA-256：fed4b50c93868ae49fc605cd6ef10a78c472e8646694c6b35b0a5cf418a25ed7
- model-request-3da6a44b-dfbc-4903-b183-71d8b22b2255.json；ID：11a08a01-5151-443e-8eaa-0cd7c8063b38；SHA-256：63a0609d6b0650f5d59a9dd46365ff6579971a44525165bdaff35d943d6c8abd
- model-request-3f081b29-b83a-4e37-beb5-f4158516bed5.json；ID：11198969-55ce-4b67-a6e3-015c17df9be4；SHA-256：6fbbe9449cc7dbcd1b14d68db01d51d4310711105a8adeb6c9e80f17f5f8a2b0
- model-request-3f2c3946-86dd-4441-8151-ebcd3a131bba.json；ID：8af3ed48-65b0-40d0-b465-124b3ac85cd6；SHA-256：0e23c976285282cef4e7938c668d62abce260d30bab73620c309cd0c9fa5d0e6
- model-request-4038fbe5-f202-4261-af38-c7ac40de170a.json；ID：68c772f0-79a1-46a4-bf42-9be5e3e5cdb8；SHA-256：257384eaa9e2f1c100ae0102d92717518efd84490d200a996d35f3e0006581bf
- model-request-40c29a22-9979-4e81-938b-a38ff8461975.json；ID：dce428f7-4488-4353-990c-cca18f53005a；SHA-256：30ecf2e69965ee16fdea1e38cba35b3ce80a1ed65d5252718e8d0e7d7b327bf2
- model-request-42127f78-47c3-476c-aad9-d7b0d56874fd.json；ID：3f5eef02-3884-4e10-82cf-02db045cd72e；SHA-256：158031ff12950d2215d9d95be95984206719093780c0dd82890e626fb4efca0f
- model-request-427e6848-307a-4554-8b08-7ff8f7940c16.json；ID：a1906fde-c2e3-4ef5-8010-e478cf5adc29；SHA-256：d17bb116e3440bf938f4f3fd6d85f926f34b20200d7f18915917f04ab25a1eae
- model-request-42bd5629-6e5f-4e64-80bb-f539e7b2d238.json；ID：fa409e2e-4d1a-4563-b31a-3ecbead86b46；SHA-256：bbd74cfb1208e6c9182990e72e531a83a12177cbf7d89b909d3052c67f924ebd
- model-request-43d982e8-f0bf-4c64-bb40-8d8016d6e2c6.json；ID：4140b2a1-350a-46ca-a4e0-8065a12f1281；SHA-256：fbb5ab5e1c75248df1092568e58aa0ab6821dea1d4461fc301ad89ea9f334311
- model-request-44700d0a-bc0f-40bc-9b7a-6c59294dd2c9.json；ID：f1359257-4e4f-4ba4-8e8f-a760deea2773；SHA-256：773886b51dcd9e8cde15b2d724ca15eb5e94456531db3531c38d4fa98fc2d3fb
- model-request-46b76498-8237-467e-832d-0f3063252914.json；ID：f9e499fa-5399-4f95-bd02-94dfc3ccdf3b；SHA-256：0f4eb8fca298661f29161eb32c0c418b201ea2501161867efc15ed7d25692fc1
- model-request-483ab8e7-5cd9-4243-8e2c-f884b822790a.json；ID：28f57bec-31aa-4da2-80ba-aa65b08c9905；SHA-256：fc7cc9d56b038c062355e4a98e8f1466eafcb5a2a28d11e50bc17bf2ce63de0e
- model-request-4869bb2b-fc5c-4307-9463-36f8e0ddd89a.json；ID：d5d6f461-3913-40bd-a36e-8f56604e773d；SHA-256：4ed2ded499aeace93fd3d17aa349f0cf068bd8f35cef39d91b9a74e058990e47
- model-request-489fdacf-3078-4f3a-8210-a2fe3a776625.json；ID：0f8a0442-85db-493c-86cc-314257eecabf；SHA-256：390b49b3c638d356278a7ff38d03e18eeca24fc5cb4d9472fce361c476785cfe
- model-request-4cce9c6f-6451-45bf-8175-2dd080d3ed18.json；ID：7dcb2351-3c79-4fe2-a029-68217efbc676；SHA-256：a30811e2f81d6e622c76ce3b8ccb05da495729752b10e0749824482550041de2
- model-request-4ea45e37-d041-4bfc-965f-b732446fcca8.json；ID：ee641b7c-b05c-4fd6-a97f-37ba43d12202；SHA-256：9f0f2831b1162657eb5a36d7b27f08d7a1bc66fc3af1d4167c8d4801c7ee7de4
- model-request-50e458bc-49bc-42dc-ac88-dd9866fbd272.json；ID：395c8145-c197-4495-940a-1ee7ff048876；SHA-256：4a4556cc28d47559af5ce5fdf366f5409e1ddcb4313bef622d5fe4148c313ac9
- model-request-544bc36c-65ab-4c50-9dc6-10f6b4edfc94.json；ID：680f8c0b-cb2c-4e70-b488-db7d44b032e2；SHA-256：a9d2df0da2e1d052361810803d5bcd6e60a100e59957402b78ef103fe8f0a9ba
- model-request-5673ce92-7b55-4077-bc7e-b40729c7873e.json；ID：6742a99b-79b9-4ac4-8f5f-effb7bd43be7；SHA-256：f814044e6544e05cbd78f82a7e992562eeb25845984981bd4aefd09abf62fa88
- model-request-584b6dbe-7765-42f5-8a8c-102c0ef39c17.json；ID：6aa04e95-0ed7-4356-902e-9f0f4c7ab22c；SHA-256：d210321efd046b436efe912eb9073cd7c28041c822893ef3fae9cf0619dc271f
- model-request-596c2ea4-5789-4567-a647-80049173619a.json；ID：15877ebf-6404-4e4c-a9d7-15c5c6a437ec；SHA-256：ec7b265fe238f6bcfcdc5baba6fa6ee69ce8eb15a0eb66f92d609a1005597f65
- model-request-5be99f94-efb2-47c2-911a-6262921525ce.json；ID：818a97f0-2240-4c77-80a3-0b045dabdb66；SHA-256：4745cac76e7424afcc3e765fd95d8a3db416882603f22636513d98ae421a7a06
- model-request-5ca7a60f-f207-4c54-89bc-08288c09656b.json；ID：f77e7cba-8b8f-480b-ac12-3741cf50ec79；SHA-256：36edbfbb23398204e3d171aecbe1800fd5f24ec9e399c746bc4681b28d1107e0
- model-request-5f5d4bb6-3e9b-434f-8aaa-72a6e51a9509.json；ID：1bad2967-647c-4874-bcc4-70f2296efd27；SHA-256：ba1bbdc38631fe35a6e6bdae496485d7533c6e0cf6a557688299a0bb94143068
- model-request-60e8a2b5-7a37-40a5-94dc-072914e287a1.json；ID：bb079411-c50d-49fb-a456-3f745d8d37a5；SHA-256：23a67e2bf67680b566f66186f302e1c167e3be9689d1da8574404087c098eea1
- model-request-63c00c3c-e11a-46b5-8389-b2ebde895ca2.json；ID：5ce03d7d-9bf4-41b1-944f-e13782daf200；SHA-256：e505e5065c92cd81d61af3d904e30413e9ff487a9a14830c78d47e159197171d
- model-request-65063c07-b421-4fab-b099-facbe968df36.json；ID：45817842-711c-44b6-bc58-66e952901e02；SHA-256：11077c3c32d9c4720e4bf3b98b48758be6f71cc44070bfa14f22df9c8a048f83
- model-request-6716b64f-af4e-4d26-9b08-db0730ad1261.json；ID：d9126e79-72d2-4754-953a-3fcf27e609f0；SHA-256：3dd9fcd43ae2a32b07b64a23bc749dbfbe21ce2d8daba4f844dac84a58ee8853
- model-request-6bbe6cdd-0c2f-4c19-8f77-a3e9f3c0245f.json；ID：9dfab1c8-7ddc-4c1f-8f6d-888df3804d14；SHA-256：8524fb14ea5435bf4d386048c05cf8ebc262b1f8207cb64efa8f7086a28d6b46
- model-request-72801673-ce4c-41ec-b73a-c6549c03c4af.json；ID：bee8a8ab-9425-4a7d-8e90-9af74a8ab03d；SHA-256：16408614578f64d523556a93d6019320ad653996e08f791271770cc8c78091c5
- model-request-7337ecf7-3f10-488c-84be-c47c7f05d15a.json；ID：8b999e4d-a419-496b-95a6-ac1e45f78a42；SHA-256：4884c12b51c19d575367fcb4b41b7223dcc243c137c0cfa2c2826d91ab662244
- model-request-7507d5be-73a7-4ab0-b264-7e57c43b1f4f.json；ID：6eb96301-d706-46bf-a9dd-872608b0a0fc；SHA-256：6785d0a9bef2b53bda19a43bdddd838889f4cd9fb0b19cb51968750edc7564fd
- model-request-7f089da9-7ebe-4ab7-a17f-4f9bad631504.json；ID：ae73c5b0-7b2f-41ae-b03e-bcdf0ef14904；SHA-256：74964eb2b338acd3fcbe6e1e9e78689427b6b4475426b3f17bc58cc90461daa6
- model-request-7fc8c18c-944a-4c90-a221-169f59c1c66f.json；ID：f23aecfa-1b55-49a6-b672-8f50d9e88e61；SHA-256：d460c83d0b847e2e693b958977de3a7cb043962f9f7c690ad8bc474402cf65c7
- model-request-802dcad1-dde1-4d5a-af92-10add5063dc1.json；ID：990e94cb-6931-4f9a-82bb-a08b2766cd14；SHA-256：2065b6b7e823ca9e6a05db89ff1edba20c0233bbfc01ef17bb41ccbd7950240a
- model-request-816971fc-fa35-4847-abac-30cc2c59e2a2.json；ID：5c9fda9b-41eb-47e7-b600-ca6e80178ae0；SHA-256：1365b205459ca8614c7e503bed404e0a9ee13b564009578653c72549d913fe64
- model-request-853f3270-c075-4ae9-96f3-97130352b42a.json；ID：58ef9299-a6a7-479b-8b3b-85e7230995b1；SHA-256：6a019f22cddf2464c6f87315e7c253a98db349457d821d16224f191cb87619c7
- model-request-866e6990-72bd-4061-aab3-15113ca25679.json；ID：c101a044-534b-4293-8a7f-2fb62cb61719；SHA-256：604fc452e6a69109d62ee9bfc94a57b385342f9f152cf7118938f8d4402765ad
- model-request-88f605ad-2f12-4c2d-9322-1751f17bcc91.json；ID：ff9aa56a-9c3f-42cc-8af0-f81d8f342692；SHA-256：b98160178d669005633a4d75aa31b0d34988836fcde26c21ad5dd93648a41ddc
- model-request-8bf1f113-3f6c-403e-af75-f2fe068cbf5a.json；ID：8197ca22-2ea8-4dd9-8cbe-5b6064a8f9cf；SHA-256：eeca2245d42ab7f12d5e7f2b0338bf9151623e822f07f2c17a14ea6ddaca3475
- model-request-8c484f49-f0bb-4a81-b695-18a8c4715fd0.json；ID：aaaeedd5-0e05-4065-9bc7-c6e78a6a4be7；SHA-256：238ae90406d9fe6c16baf5a984fa1cc8186a24cc0fc2919a3e1caa6042e5a9f9
- model-request-916bb582-7819-4252-b70d-fa1312873f4b.json；ID：dfac2f31-5633-4c8f-aa97-9f5813a18c99；SHA-256：279bf28dcb447d5aa0e9105ec846fca0b4b6face34f1c4535dd0c4e045e8cd19
- model-request-955154f6-ff7d-4ce3-b29c-44381efc450e.json；ID：a2392407-f62d-4ea3-bcfb-09ab2bfcc847；SHA-256：f5693d29cbeadb39cd19dfb39ab7cdb739a2ac2b3cae6f1fd9a4266f7b0c1be2
- model-request-980b3ef4-04ac-475f-a93e-75e0e728f449.json；ID：07921e9a-a211-4670-921e-5a02d66d103e；SHA-256：999f4fcbadca607aea623534608fac23cec342d3c8317049cef27a1ebeccee31
- model-request-981b8b15-7d8d-44cc-9d6a-ac288ef67360.json；ID：1b687bca-b281-4fd2-97b6-280cd7456842；SHA-256：8708c660fa435b7bf934c1b24c07115a2882f4b17a069ed0d6ebb5f2ffe31eaf
- model-request-997ff6ac-15ce-43d1-a632-6317bfa2f459.json；ID：5acd22ec-2e6e-4c26-8947-107aa77e9404；SHA-256：b1d7d0714a84bc9c9c63a9f3d9845b2db7bb3feec6445a0fdb5352252bf21bd0
- model-request-9ccc5f26-cc7c-4549-8e5c-ebd3ac9ebfcb.json；ID：fb70ef2f-e2a0-45b1-9063-a70bd78c974f；SHA-256：3881848e50f66c09b0d138cd120db756c7a475313976de3b06cc98012ae46393
- model-request-9e6de4f4-f0f3-4da5-9f36-2527354ceb61.json；ID：f8933f6a-bd6d-4fe9-a381-6ba2bde74388；SHA-256：1ab03ea4aca13270fa26b839e251528b67fe7f2245d7de99e2c142909698565f
- model-request-9e7eeed5-5e88-498b-80b5-e09d3accb094.json；ID：450233cc-3b9a-46c4-8681-7f5e9961cbd7；SHA-256：fc8500b678b2bffd1c5d09c30cc3e9ae74bc91aa1c56f1ffe50a79860b854445
- model-request-a19df59a-a3e2-4166-aad0-2625e206de4d.json；ID：de3ba256-b677-4b8d-9772-3761cd3adf90；SHA-256：e9b7192ae2565343aa8dcdd39d3abd2c2c197f6256023993135ea6bae97410c9
- model-request-a2520ef4-3a34-4828-b93e-9e33d6e1492d.json；ID：4f128805-5064-4ebf-a980-384f722a9eeb；SHA-256：18940f5c01fbbfcd36f84bedebab5dcbe7dca6e4c4cf39bf8955afaa494df0f9
- model-request-a2f400c0-0a5d-47b4-97ac-ae33a9dd0ebc.json；ID：746e361a-da27-452d-b34a-6df1062f44c4；SHA-256：0cd26a09e766e80cce31d3dd9a6ea2a7a94f19ed8fe697562a3962f0d1d3b533
- model-request-a701fa5c-c5ff-47eb-aac0-0f2af7706189.json；ID：d0247953-95d6-42b4-bbfa-7290d56a0de3；SHA-256：777f6ee22d7c24fd139f1ce5eab45133cda5af8e6b3ae2586c907095598156fc
- model-request-a7093e93-0f1c-4f65-99b9-e6870411b877.json；ID：67c1f132-0bcb-48f5-b29f-0631ee5a23c1；SHA-256：cd14559f03c0e1de568fc243760a1bb5e419ad2eef8cc4785834d0e40804ac10
- model-request-a7431b24-184a-4b52-8b7d-76aab1210152.json；ID：6ceed2ca-5a31-4edb-bb26-ada4042244a8；SHA-256：0ab9bf3f921fcbf6072ada14bb119eb3279fe62a6a45272c020fa63eafec5370
- model-request-a872c8f2-c7ff-40b6-b6b6-16710f9f545f.json；ID：a10bba54-2e78-4c93-a1d3-d0a65b27fccc；SHA-256：bf0e2d958b51815ef17fb6fc4eeccb954b8dc3b0e71c51a0c2f782995e57a47a
- model-request-a93e266a-42fc-41c9-83ee-f1c352222ac7.json；ID：7eb2300b-f6fd-475c-9129-a129d6573ac9；SHA-256：4280752bbadec62c2f8448c51690296e0e9de213a0ddf368caa07c2a41f96a1f
- model-request-aa4f26f2-33ca-4cdd-8e08-9f913133ee9f.json；ID：6a3160bc-a31b-4ef0-a486-9ddc08061132；SHA-256：36258025a100abe7e8cbf29bff00488207b25690d8d6c9ee132393f64b8bfd06
- model-request-aa88a6f9-4dc5-4f52-bb82-7ec624fb220d.json；ID：7992654b-7597-468e-8fb7-3e6131c9c0cb；SHA-256：ea7fbd02117c3f00d975696985cad289df98b9ca6ff2c0ec809da7eaac58524d
- model-request-aac3afb0-befe-4344-a0de-6eb44be78ffa.json；ID：e71dfec6-cede-470e-b038-1ab9c33e9fdd；SHA-256：499a73e8ae7ffc6b8b26be38a920dfa2ac15f5fbe5f1dc2d4121f750e06df309
- model-request-adf17af6-2875-4691-80d4-4386ef51c522.json；ID：a560280a-49b2-409b-bd80-0ac4b032f6cb；SHA-256：44db95d9d2b0f7f122b0468e669f322a81b3ca9f1e442a28236fece8c5bfe3ce
- model-request-adfd406b-4605-45f9-8ce4-a282517b80d1.json；ID：82a1015f-e70f-43cc-9d32-7bc4aa1ee9bd；SHA-256：dab32e68f4ccb01cc22ed24e30f11ee6a88fb5c2a151163746ee24877b94076a
- model-request-b26ee70d-9192-4e50-b43a-e7c9d9cae37b.json；ID：379a83cf-5982-4ce7-b467-d213502c6862；SHA-256：1f1f1c09d438e16b226a8fa183601df8dd3ac5d10e9c01a4b612fee7b533e0fd
- model-request-b3fff278-cf21-490d-81fb-f6ad194dee02.json；ID：48ac61f3-5d4e-4916-bb72-3f1bf5c02941；SHA-256：5f844c1ec7a1eaaf87133e443cf4fa6b073c1961ac1eebb39ce1a142065fb2d7
- model-request-b4d11d58-71b6-46d9-b647-a4ef754c3f15.json；ID：ce279205-3b01-4109-b32a-d96c1df17a4e；SHA-256：8df282f545775ba1b31507399ff844f785bbfa2a035de95e22775f5df2ef4150
- model-request-b6d80cae-0f18-486d-8bae-60cfe65149ca.json；ID：aaae2ad5-8ec2-4ae8-a49c-58b058bc9bc8；SHA-256：d8e054f128a14d67fb4770579b36034b333d90786730589cbe42c7a40cf386ed
- model-request-b70ddda4-52e0-42c9-a494-af503b5f1ee3.json；ID：8ffacbf5-4f19-4d98-ac96-d01a8102fba5；SHA-256：f9a75f2f1ad9a973dff1c06d9f12e305fb38bd31bc91bede599a8ccfd5291419
- model-request-b7318721-6586-4326-bd1a-9c226df3fe0d.json；ID：393be444-395e-4e77-afc8-a54e9bcd7a8e；SHA-256：ec12bd6a7c07924c2442f2ae99298453c92d7e3aade7d7118ff81174c70072e4
- model-request-b7cc566b-12b5-4b20-8905-5ac527f3ab37.json；ID：523fbc0b-c3d7-4aa6-9859-bf1443e10ded；SHA-256：65accf7ea31af52fefbf92fe3362b9a46cac322566b3f725b83291793505a8e9
- model-request-b893dd15-dc81-4a33-9b67-567e87796e9e.json；ID：bb2a971f-dd35-4bde-94c1-3e1af87d0506；SHA-256：1097d91ba4fa7dc3014a9ed7173c58bac913d03897ecc656a0449052ea8cda2e
- model-request-ba68a4b6-dbd0-4f56-b471-da73e79af607.json；ID：70f020ad-59af-4ae0-a2f0-7c5a45e39ad2；SHA-256：d08936bb42a473a80569f76d1efe2a1656743341e1c0ef0c241642cf665e8ab3
- model-request-bc2c4e47-69fb-490c-b31b-d969d2c36efa.json；ID：1ecbd516-aa97-46ad-a190-ec9a68310343；SHA-256：389e64375217c84e08e8ece6c097298708414509899189984e858f566becf0f8
- model-request-bc981931-503f-4807-aa62-2bb144f7fb68.json；ID：60fb9338-b936-40ee-a8c7-1fc60a289079；SHA-256：b72b0f7508e694f773fbdd5a08672ef19e1dd3cc76acf3a9b4ca4e78574a8c5c
- model-request-c032c05b-c784-4a76-b8d0-8b85b4811057.json；ID：58fd83d6-57fc-4537-bbb6-4e2f773dd2b1；SHA-256：090b5b266f55c102231cb5dd3b2548e6ee27689b5c8ca3b65aac5c8df76fc9da
- model-request-c463246b-fe13-4ec1-8005-1e92d9f599ef.json；ID：cca629aa-f741-49a6-b0de-b98424de0eb0；SHA-256：6b455692ca951ce1e87433190d150aa867b7a4da0be6653847c46cc8bbdef5f3
- model-request-c47ee8de-9a5c-4e7a-b832-39ad988978bf.json；ID：f757bc9f-8fa5-414c-a253-e4cd5232aa0d；SHA-256：ac072f602b55d4a506d3b9c80b8036fc203ad72cca9f1ad9977a0782ba5b548a
- model-request-c79d903d-2516-4c15-b284-b0b7cb6d79a7.json；ID：effcc093-1bd1-44ec-bd76-7ddbedc189a4；SHA-256：6a58504305b1aec8f8b6036769edf52b62f02ef69fecb3b16d88daed434d3d12
- model-request-caaedcc0-cda8-4913-9858-27fe8367c3b4.json；ID：8f45642e-a329-485c-bc99-23bacae404a4；SHA-256：598396c30597743a82be323d300090319a208830250823690984769af9e53be3
- model-request-ccf26b2d-0764-4499-a8d0-36ce3b3b8dca.json；ID：dbe97738-6f0f-4330-9969-aa7aef838497；SHA-256：d8982ab8860a27e95d1a216a8fc8afdfe6faef1568edbed91bc3216f4167d7a4
- model-request-cd9d36a8-dd43-476f-8be9-10e7b486d1e9.json；ID：8b65d9d5-f390-42d5-8714-a4ba32abf950；SHA-256：85344c5b867bc1294b874e580dbaa6f068e9514d5ed1f44a7bfd1ed9aa4c97e4
- model-request-ce2d90cc-f5fc-4c09-833c-3ba5fd4e31ff.json；ID：1ff8fef6-51f2-40c4-bccc-8b3302ad0576；SHA-256：83cd108453832ea1fe454502a398bbd3ef2a60f0bd8acbdd49024dd2d350af43
- model-request-cf58a9fc-a9fa-4d18-acc0-3de69b340208.json；ID：757afd15-9718-43f9-a1da-20445cfc80a2；SHA-256：3bf790cb0e6ff7c973c47f5d13185a745cb4a485b809bde6ff538ee52e8cfff2
- model-request-d005b563-21d1-41e8-ac24-4192728da297.json；ID：4cf40cfb-60de-41d9-9c79-b26266809cce；SHA-256：3102ea7f12cd35d6a568855bec7106fb4a693a2421d2331056fa0182ed2120c8
- model-request-d2819329-2dd2-456e-9851-467702d03a12.json；ID：ce511027-522e-49c8-82c1-c100eb6c658a；SHA-256：773082b8d31b6a00f5d413436acb80fe493b99b42c48088328c46bd033f0a13e
- model-request-d6a0de8b-9bb5-440f-9afc-9eeafdf6c609.json；ID：59e58b6b-e191-460e-90e1-d58aee329a62；SHA-256：e07b66c751ec14eef80fe36b9dad38548612b7b1728a7d69e92d93067b9d9863
- model-request-dbf3ac4d-59b1-42e4-a192-412c2db7ef04.json；ID：501896bc-c279-40f0-b525-0f0183db1f0b；SHA-256：47d07e401fe1876e80f887929aa0395dd625c51de665ccaa36277d0d86453381
- model-request-ddcddd1b-4f0f-4554-83ed-f8d481f87c92.json；ID：08bd3091-3ba4-4fdf-bd85-37858be8b0fa；SHA-256：494f59f2b9e155872a4350c5e527195001646688c462e07d34ccd283f183430f
- model-request-de753ef6-d961-4d62-9da8-ff322246096b.json；ID：735ea804-1f1a-4f32-8ddd-7d5b3bc1d90d；SHA-256：a22996951ecfcaff220d161fe4e2220756b39b330499e75322820f3ec0592a5e
- model-request-dee037df-fb71-4bf3-822f-616b8ec3c5cb.json；ID：f3d50d1a-2376-482c-ad76-b6666365888e；SHA-256：204aadb0a84740611d940c5c8ff69d470aedd097d99c88dd18cee34ebbdd58f4
- model-request-e0effebe-f8ec-4e0b-b58a-846b94394af7.json；ID：57be7e4c-c45d-47e4-823c-233bd77beb93；SHA-256：b14653457a02703ba6b979d736b8bce4733487a7d21d35f24b373afec92fdea1
- model-request-e3008fd0-c8ce-4097-8e14-8820a9aba695.json；ID：9899e690-7375-4645-b349-b18d7e84e763；SHA-256：9c852e39bfab7452d619b22fe374f6326b8efc8d1559c26aaeefece5610a9b27
- model-request-e5c8918e-6a2c-44a2-8ea3-a604422a6f37.json；ID：f7b30365-50a5-4ecd-a471-d074dc82da6d；SHA-256：80090a53a623ff9543f7f3cee34c2c396211a6116ac015116c87b2dd20f0a3ac
- model-request-e64c68ae-b324-4d77-979d-7dae5c46aca5.json；ID：3976a930-4e64-4cf2-a665-eb5bcad752a5；SHA-256：f9994bbfe9e4381269f35b700f3600b44298403516e35bdc94a9ee2dbe305e1f
- model-request-e70f3d1f-4ea1-4578-8c77-8266564a9d78.json；ID：69c7dc22-53b5-4d21-835d-04e2242b86b5；SHA-256：d3de2c9caf10074f4b482aa5c07cc1c08503b3b27825e8f79eeff6750120ea8f
- model-request-e94a390d-3c85-48b8-ab9b-2cb33b0b69e8.json；ID：b7224436-a64b-4057-a029-88557fcfbf62；SHA-256：67b8bfd871c59bab11da38422da215fb8f85adcb7e6ac393deb77f472cc22314
- model-request-ed22051b-8d3f-4def-aede-8c2867758927.json；ID：92092dbc-407e-4926-8896-57ec3dd8e5a8；SHA-256：fcc726b4a8c13b7927a2cc0ec5684c48e8df3c24e02b647e2309ecdd36a41c50
- model-request-ed5c3d5c-5b16-4664-898b-59221abff538.json；ID：5e3ef5e4-d3b3-4337-81a8-8de52f1c1276；SHA-256：7d556283798dd2c1227e1ffbe7fc90499390f4d40491712d713051c2d12b1e69
- model-request-ed98a6cb-ea66-4f53-82ce-6f8d0d9dd0cb.json；ID：abe761dd-7075-4d98-9196-5b3eaaba0ae6；SHA-256：e0d00ca63c1393a0ac96b333d9ea046bad79733462609e73f9f0b470a97bc57e
- model-request-f1d3ccef-28f0-42d2-af0b-631722c10d47.json；ID：ad6fee9d-5901-4e1f-ac0d-14581d0ef535；SHA-256：a22552c57e9fe518093dbbdb74ac7928bb06e1c790e8f50d17c5314ccbd41852
- model-request-f6c74618-d107-4bd2-9679-3e3feaf567fe.json；ID：4d7080ab-65da-4285-b96d-21c17d594d5a；SHA-256：c4e18f27ec5c8870b3a2c228ccc87c4fdc4a4acfc9fdee51c900f2a99d8c9831
- model-request-f9d352fa-5435-46a4-a8b3-81f4b273107c.json；ID：cb787278-5add-4b44-a9a6-90b562b7fc1e；SHA-256：d808d9ef1735149ce4374ac5ff514f3a0009f5e24ac5633d5576687472fefe1e
- model-request-fa44005a-eb30-4cbf-9d78-1555763bc654.json；ID：345d17a9-03d5-4b20-937d-4376c6462a0c；SHA-256：45802b643d9616f469bbfd0cbd03d39464679c3130e94dce32bcb33b3a493b04
- model-request-fabb45d3-50ad-446d-805c-1bf754c717ec.json；ID：5c5e8250-8119-42f3-a3d1-2d372a9536c4；SHA-256：923380e2e21f84ac8b1c352ca1acb2311dc05ed100bf9068760b417b557dfe92
- model-request-fff97465-cb30-4014-8de5-76fc03c4df01.json；ID：a5c0ace9-5baf-46fa-9e16-b8ba6b7c3c99；SHA-256：eb6a19df3a92a382b907cfb5c4e7344938047378d1a326c36e3968d4c15024a9
- model-response-003985d7-81df-41f3-9215-cb5d08579944.json；ID：213211f3-f38d-4426-a0a7-28cf3a126c33；SHA-256：dd7d201bf7302e270f50f264b1ca62fdb2303dc71955496a60f426ed1ca4a79c
- model-response-02836757-d415-4112-8022-263c4d74e5e2.json；ID：be0fba12-9e93-4920-a2e5-50101ce81955；SHA-256：7445ef0c9c764821bb5453a816926b7c69f588c83281e30505ad42a254d2d1c2
- model-response-03c768f0-3247-4ec0-9461-320e692622ea.json；ID：d3de7a94-f7fa-4107-ae07-44429919ab15；SHA-256：518a61ecf342278b09998523177e5ff937e7160da44de8dbad687d9d43cacca9
- model-response-04f78ba4-c40f-4c6b-900d-d7106597d81e.json；ID：e9912632-c540-4406-8f7e-cd554e59e62f；SHA-256：3e879c97ac8bc91598a9b29a7bc40a64b0c2d3334378f96b1247f91fd155c1ea
- model-response-07fceb81-1787-47e8-baff-2f7e3361753e.json；ID：e9c60c2c-748f-492c-a6e6-6e1a5fed9eb0；SHA-256：7c64565a7f34b88553dc3b1c708929c3e810fe604193702d8159e50a9353d249
- model-response-0825b668-96ce-40db-a2df-9fedece4c90c.json；ID：7beb308c-1226-40fa-9562-8f37754bb987；SHA-256：4ac2a058de6f37e4c397a72b80d9f2024012c8fdee8e02ba251b9657766a98d1
- model-response-097e144d-db4e-4052-859b-c6527945b3da.json；ID：454a27a1-b730-410c-b16a-fe543b4d2ff6；SHA-256：ee32cfb083214331ac5bfedb33e82f1b79bd40851e83be3dbe4d8da857f94769
- model-response-0a47c0c8-0ab1-4e92-928c-35a8644f8e57.json；ID：b2337a92-3c61-4215-a39e-7341ca57e2bb；SHA-256：8cbb8585a094569246cb0f43fdd852cd30fc43b41ff6f5b08598219d01bf234d
- model-response-0c83a193-b806-47b3-8255-3b28d1677889.json；ID：c7dfd07b-5b90-40b1-902a-3fc09b2d7a11；SHA-256：bdd0615e42d097e4003a6bcaa0b707d5230b16c732556e8a036382f0bdc0cda3
- model-response-0d7199d3-e1c4-40b6-a140-72a16b56bf70.json；ID：51dce46a-8594-44b5-ad24-a3394de2e18e；SHA-256：ffd89d05a472dcec9c681f2f3b24cd7f2ba81773e2fd416a0935acc1ea9cb48e
- model-response-0fdb1506-dd7e-47c0-8a91-a904ae508dde.json；ID：f744699d-1fd0-4e6c-8539-b91a8a621db1；SHA-256：6a25915ebfd2cb565da3ad648d0c5603eb7ca961a12ee20f669d71b4d2898738
- model-response-1090c6b5-b42f-4789-b9b6-1afa64588b86.json；ID：33e2a8bc-97c5-4aea-8f26-0bef0beae190；SHA-256：9f00b8abfb40da71729d02802df2bbd941b4d34341306c827c488a136a4fc437
- model-response-1221a303-fbb3-4c48-97f0-eef69514a19e.json；ID：e5d5361b-a90b-4002-99b0-eff11ec5bd68；SHA-256：861eddb59a90933f17ee97ac2a9c4238b54a87a3da4532c99a5d850a28147f60
- model-response-12262f31-b591-4960-867b-2a926b95ff67.json；ID：84fe18dc-f478-493c-ab94-79bd1c47151e；SHA-256：3d3dbe50bbf6a4fe95eae98aad007dbf62ff9f4f66a2a57ac887733a7036e264
- model-response-139d81a7-dcb9-4a00-8d70-6f18ac90e1a8.json；ID：fc6f8aa5-9e27-472b-b681-5d7b3c2ed630；SHA-256：2627c7b5625db130e1c163d7b0f3cc3a7843f8e02f51b553a6a569cad22e37d4
- model-response-16a3500e-9d52-4644-9a04-856d5d6dbd65.json；ID：5a304a9e-6583-40e8-9b2f-5c053dc6daca；SHA-256：ff5bfcb3042ea22b5725d9ec0f0843d97558f84a7e2a4720b3548999c4efc4b2
- model-response-19e07e5e-a319-465a-8e6e-8f1606c17e3f.json；ID：a95f93c7-5245-47d2-8c5f-760ed58f2262；SHA-256：34ab79d825c9ec254c4901dfb7567df26174be130d4956beaf67e01ba1cf9af9
- model-response-19edaec4-57b4-408f-9201-4930cdc0be52.json；ID：f53441e9-2f58-4705-bd7e-e8f502a61c5e；SHA-256：8e063de19b22724adc4c490f6e6257ef4aa20bbc06ad615bc7e187b3176d0263
- model-response-1b223785-b7c1-431b-b9f8-88c5ca9febd8.json；ID：20d5e907-7487-42cb-a379-1c0a205a8c7a；SHA-256：bd55a322a892d10eb01b49f6a34a862a4dd78cfcfae2d1d65b0dab3cdf58c748
- model-response-1cc1f942-2161-49b4-9476-e560837a38e6.json；ID：4407e7d0-54ad-4dfe-84fa-f33b21bf056c；SHA-256：768e0873a7895d7f0ecba74cbbe6228188a38d1766516ede4d30c242ce8318b3
- model-response-1eee457a-2364-4770-9a22-625453729596.json；ID：4cccc006-ca35-4deb-b93a-153e4f7acd12；SHA-256：54b59ea618ffcd6897bb02af4de6214c6b8d02daae336d67c9721abe14728f26
- model-response-1f9ae62b-46a7-49c0-8729-8ce17d04f042.json；ID：41196c1a-3fd4-4be0-a701-8f58a688f87d；SHA-256：f555dbda600dd70f9e7308385866a34fb6f6b9bfd582fa9d9e383a3ef54d4c1e
- model-response-21747241-7b33-4fe2-9907-604e1e42675f.json；ID：51dd3034-e80b-4d40-9d86-5f8f88b2754b；SHA-256：9d6f2fd8aa4f7fc88380d4802b84b2e866534cff6f7b1dffbc3b3fbcb978de2e
- model-response-217d1150-6e55-4859-9899-4a33bb59b5d0.json；ID：09ba5939-cf64-4f26-b118-85ca89ccd4f0；SHA-256：c448cf0864a66186a63c4cf83d43ecb146b77be4ff3a08ba95885e0fc34fff90
- model-response-2454d97b-7d3e-47ef-8edd-377566c1c7cb.json；ID：f88b5727-7639-44f8-95cc-5b4d8b1f631b；SHA-256：d9645574c7f79e511b2112c57960ba5359fe9c278a01f245e467c13ce9b8b6b7
- model-response-24c8223f-30aa-491f-9e22-0bfe4cc33293.json；ID：7b837b6b-b779-4b7b-80f1-890bf60c1300；SHA-256：70a9800f1ab9ec9fb78831c82302e3a881b8d9729791c5e5710357b881aed52c
- model-response-251006a9-6120-4acb-b085-04d2a9856a92.json；ID：0edb4b87-b0c9-453b-baed-870854d15528；SHA-256：e6da3397ceb46c057fa31052c02fcac3971db4a2aedb113d4f4bf1e09d9938bd
- model-response-273bbaed-834b-441b-99d4-e2c591a4f483.json；ID：629862bc-a932-449a-af45-e8baa58c719b；SHA-256：f744b51d0f7d2c1254f5acf9fd3886048455167676929bfd4ac59bba1c58c738
- model-response-2a4b51e6-5ff9-4de3-b257-9488350e7366.json；ID：eeb58d12-fa16-42aa-a539-00bc67f700fb；SHA-256：a64d7333deba450404d309fa5366c5863821de04fd20b45cc99c7793e8343a69
- model-response-2ebdacd8-0587-4c25-b13e-c025dd49f80b.json；ID：6fa8adfd-4db2-4b1b-9248-cf280f77b283；SHA-256：1bea089113afc2ec3c8749d438a1517bb958073f1048b8879e5b4665c2c0f36c
- model-response-324333b4-bc9c-4197-a26d-83cdfa917bad.json；ID：b8b20057-044d-4d54-a726-3767eec5bf32；SHA-256：024836900a73987710e31164032a6555bd1b4716b549eb7e1874d4e740feb17a
- model-response-3362d3ae-9561-4b27-a103-c81172828e0a.json；ID：f45552d9-5e3c-4bd8-a3a6-9ddef36c75a1；SHA-256：a5da11b46195cfb64c1e52fabe5f95b110b851bfca9fe48dbe54afafddda1570
- model-response-37d1ab22-cc1f-44a3-a92e-916488b33762.json；ID：b5e7e175-f8d3-451e-8581-7adb0f450d60；SHA-256：8a916a2e97ff5ddcca6ba2d33f660dfbfb0041d9b440661e15405873e0cf216b
- model-response-3aa6cca0-263b-40ee-8938-f03584fdf703.json；ID：2712ce0f-9b33-4810-b5bd-0784acb3b621；SHA-256：7be21fa10258dacbc369f229c138516325eccf17599600f4d3a79e8fc72f6025
- model-response-3c474a04-920f-4cb8-ae04-eb154f8941de.json；ID：903077ec-95fb-4f14-8b12-a06a07d70131；SHA-256：39c41ee5d6378ff8d1d6574e956fb46981adfa3266a4362826caeb2ddcc9e0c1
- model-response-3ccb73f6-c450-4871-975c-45e665802a22.json；ID：29b7227a-a677-4269-b030-b8df75d5eaeb；SHA-256：0f9710e031fd17dea622d7a11862ae279456199b0fb040a560ac824b2fe39d3d
- model-response-3cff9f0e-3757-4edf-b189-afee6e352bb7.json；ID：aba7f7a0-66de-40f5-804d-648516e997b5；SHA-256：e69427db5da36acef2f9be30964b58a627dfec2a6f4ac3703c04f3f88651aa05
- model-response-41a707e5-682c-4edb-acd3-c587bbcce011.json；ID：ee3fcc4b-5d94-4a89-b64f-cebc70a49541；SHA-256：247b14350981bf4e350d4b506957ec09f614e8ec00837b4b9e534ccc537263ec
- model-response-41f8302a-8633-408d-9965-30b58b5537b2.json；ID：5ea7c236-2aa8-4dec-9ff4-714d198eb460；SHA-256：c5c6d4338f7a4641aa1b3f45cb702ac45552c65c17f8ba5ccafe56d5ccc38f25
- model-response-425adc1c-9640-4c80-91e4-8304239f19bc.json；ID：a090aac9-1ed8-4fe0-9a29-38be274028c3；SHA-256：d2c9c43465824356704da45bee36a2fe60e6f872bd92c51f55e4e2adab18e914
- model-response-455f0040-9dcd-4be6-9515-743062efee62.json；ID：086e6e82-be36-4ad8-9d2c-a2602fffd130；SHA-256：f71969c4f3f1a25342505215743091b5676e355306f912f8c8d2b011cc602fdc
- model-response-47eb491e-ff67-4e59-b642-299d37c63b0e.json；ID：b88714d1-f3dc-4cc3-b926-19dde4e2b4d3；SHA-256：f9c38bbfb3dc46ea1250bd293d350b45e8c87909d4cae8a38753d79037ae5e82
- model-response-4afb8719-771f-4fa2-8ad4-f8499e2c7918.json；ID：41c49700-bb0a-4a92-a3f3-b553cc3e594f；SHA-256：991c38193682f688205016f18c1a5cba90fe436c247e81e410cb74408d72764e
- model-response-4bab626a-7195-48be-a5ff-cbddf816159d.json；ID：59cdaac2-56dc-4e7d-b949-4e022218f202；SHA-256：5fdaba162de15a6fe6cfed7dfdd85a7b894b43bbc9bf61c76b619535ba809c63
- model-response-4c7e6e75-ffc5-4803-955a-6a8c78903323.json；ID：e3be7061-dfb6-4051-b08e-b4144201ed20；SHA-256：ccb6a43d07ee18cd246955c52f5ed585279d277456492e29bb4b98bc1b8c6612
- model-response-4ff52381-d972-4b85-bd83-ec9db71492c9.json；ID：c02cc001-4c4a-4de0-a580-e8e37c9ea2a5；SHA-256：16de3acfbfe6374640f8ad0c606362200f5625d35167822a149084430bb6770a
- model-response-50ccb05d-de33-4a12-b7d6-88d171da77f2.json；ID：49d66736-45b0-477e-8874-c2ce6bde6ec2；SHA-256：f67b8fa8f8749890d97c6186f97da9c0d812230f6d28d8fdfdd513fe54d84142
- model-response-51dcd36a-05c2-4e43-bc90-e52a64ca71f3.json；ID：8abbeab7-783b-49a8-9919-b93666ed1542；SHA-256：c70f4e84b5f74e2e42e5d079076812d48472e160fb22c694d6589e09ce5c5f04
- model-response-548dcc99-dfa0-4c02-9f77-5b9b0142405b.json；ID：cf289a59-9170-45a1-91e5-da0bc3e9d2ea；SHA-256：7c819f467f804ed729aa7427a35f3cf101554ade66e436510bbbe826f4c974f1
- model-response-560e4347-21c6-4c63-8ee7-3a5c23ceaf2e.json；ID：e213ffe0-2cc1-44ba-907b-be36c735d337；SHA-256：6b667bde66b1c1f372fcd1b52a10345add6d43bcefc888d7bb331f87188d8d4b
- model-response-5da6989e-6856-45ba-9921-226f2d76d3c1.json；ID：dbb330d4-c1f4-4b68-985a-cc4933391ff2；SHA-256：56e92c79772ed4b4931c06dc72a5b39ce6893e4418ae0611b40a2144a7cc0f3a
- model-response-6134b6e4-42c9-428c-9cdf-6c26f235b2b4.json；ID：285069fa-1393-408a-a16f-138c33cf1d17；SHA-256：e1bb7414686833846e9ac4d8982c07cf90bf13dd55cc4306bdaa5980f6e634c2
- model-response-65253d04-4918-4a09-afc2-6a099df34a97.json；ID：c2e42cea-86db-497e-b0ae-5d47b169b5eb；SHA-256：7553841aa296275eb91d07c46ffedf9645d4e31bbce488095f2c6e84917bf699
- model-response-6541f4b4-3cbc-4ee6-806e-82918dec0192.json；ID：ab3c8944-feaa-4cf2-ba89-9c9f84006fe8；SHA-256：6a8756ee97f6df8020bbc9695c3e8471514381da48e161f5fe0c325b0cedc1ec
- model-response-65c61c4b-6c05-4688-bb35-87c6128b63c6.json；ID：8fe13582-885f-44c4-ae0b-5496a2537aae；SHA-256：1846846fa4f279023fe20aaf38243df742f5929607647c8490b28aa3d08d3922
- model-response-6634aff0-0c65-47d3-8e27-1387c045e45e.json；ID：dd9fb529-16a2-42b3-ae38-0629e101bbde；SHA-256：cd7ba8e6b1b25dd6d4246d3123ce9690fb08b7c2bfda95bcbaa92d71710d9e18
- model-response-671a47d1-233e-4cdd-afc9-3f2e8824cf37.json；ID：4b614cf7-084f-40cb-bfcc-c9816d1cf56b；SHA-256：71a0d578fe265cb63ff60ec1cd4f415fed374bfb35c4e2baa23731d1044b2c6c
- model-response-692c22d0-d799-4044-b55a-0695b1942e68.json；ID：149f764c-71af-44ae-badb-46c471bba096；SHA-256：9cad87ba97b6e40a01a4d3a0145e5d4eb52140810a0f46d39f65c2755985f462
- model-response-6bde5e65-396d-4444-9bd9-01c1cfe0eb6a.json；ID：66641df9-45b0-46fe-9db9-a18a271bb739；SHA-256：39ea0e17a3464e98612fa483bfa61b8c22f5572cd6209abcecd1f27d32e32865
- model-response-6c3bd5e3-58c9-454f-9c08-31f75577751a.json；ID：50ae74e8-ff1c-4be3-bc80-5ca1fda8bd8e；SHA-256：e39c3b813be445792f8cc434acf8d247e36e53ecf89602fa126d13032f850b58
- model-response-70f3bcf6-1ed9-4da1-b9a0-0ed1b4882fcb.json；ID：c6ee7a46-9c95-45f0-8ea6-62d8c844b36b；SHA-256：c8dd3edcb78c40fd82f0c2f3748d68c10a7aeb76349c922fa882bc5811f81299
- model-response-715360ff-8379-4658-9639-b4b1d9b41496.json；ID：dcc6aea1-f93b-4a2f-91cc-fe7f38bcea31；SHA-256：1d243142db09e2f9abe1c39379f065bf57c96bd01bfd0c02c32d5be8b906976f
- model-response-726818c3-5b61-4cb1-9a2d-c669a31830e7.json；ID：248c9398-5a3c-46ba-bde2-5f544c1ba27c；SHA-256：57e3f811933edfa4695b8100d375be701e8c84c786efa492fafa9e90536213c3
- model-response-735e4caf-4fb4-4168-8957-f57fe2c3db39.json；ID：d75a07af-868d-48a7-95dc-ebd5214b8dda；SHA-256：6302e158946fe6037203bce9f768a7ff637d06a778f1ae5527984a3b357ffc30
- model-response-770ef865-5cfa-4a9d-86e3-c27b4e854150.json；ID：13c6fa1e-9b4b-49f3-b2ab-404e40186063；SHA-256：7521d265bcff3ca83599d4fcee8f8f12e67d55b1c196b67d52beed56da3167d2
- model-response-777e6d8f-9366-4340-9e69-aa1ae0a65ad4.json；ID：214ebbfb-47bd-4f69-8967-4e64f41a6947；SHA-256：eb5a1f1328710f3567fb7a675b218dfd797ef8770f212f6f7f1291fa5ad6b2be
- model-response-778f113a-dace-4ab4-a696-42caa23554cb.json；ID：a7b0b709-84ca-4113-8109-af5d763b813a；SHA-256：922a1105c81d2cfac1120b0e21b6c5fc829cc71b33c70c480b2a3851136e4380
- model-response-7c06523c-07b9-4400-89c8-574d14b2ebd1.json；ID：d4552691-ed76-489f-a20c-2a901f95786d；SHA-256：46e7088d6ad8c79f110cf2467dd756abec1269ec90c9eeed35331d3b1611a7ab
- model-response-7c535eef-7ac2-4d2a-a6b0-debc093419d0.json；ID：ad10115f-4b49-477f-8ff8-0deea0bbcfb7；SHA-256：d5a9729570b131e22f7b3db2a4840b93a754d240e66bf75965789429708e55a9
- model-response-7f5733ca-fb69-456c-a4d8-342078a30a9e.json；ID：2389eb61-7ef2-4f3f-bd73-63f832219a8d；SHA-256：ecd1e1cfa817622dfb9c007044b4c4ed8127cc68f9b730e6a214cfa33567a1fc
- model-response-84abf5fc-e5d3-4699-9c61-b85f68dd2355.json；ID：86470c8f-788a-4034-838a-8dee45d8448b；SHA-256：dc5d305c9542ca620ca2f8de8209f542ffed10c97319808023f1f0c85d0a5d70
- model-response-8779023d-b9dd-4458-8937-a8805edc9f8e.json；ID：02f13363-75d5-431b-8bbc-473086fcbe12；SHA-256：4be2c08f5c0e1b83df229c5e4fce7ae94e6a911eabc7eaae6d31d2b9bdc064a4
- model-response-8981ce5a-2f5c-4916-91d7-fc0af7ea8dc0.json；ID：ea3d636a-af0f-4931-b235-e934775c49e0；SHA-256：879b4a98b2ecc8cb92ab10bd1325fb8bdd8bca9f29d5004d2f5fd1acf6e0df5e
- model-response-8aba01c0-451f-453d-9f57-6a0313554204.json；ID：19ae9342-2ec0-4bf3-992d-54ca511a907f；SHA-256：63800b39425fc6b7b621212330c03a6ae53c5ec92dc832c21db35478538307c7
- model-response-8c9374e0-d571-416e-bb4b-a1f1b0272f41.json；ID：411d7682-2c23-48af-b4e7-c3d102bed78f；SHA-256：450f98a2dbac7c9e180ff8a5d874cc0715c58608e4e3e41df6af6fd38e26e361
- model-response-8f465952-df61-4cb1-bf4a-993cc2e5cdf9.json；ID：dfe42ffa-4c8c-437e-8c15-c3aa808d7403；SHA-256：c736e5ef2ae654671ec5fd61e6574d68ff8f467af6b1366fc59508174c7c67a8
- model-response-8f80cd46-08b6-41d5-a768-a55cb5ae130b.json；ID：788f3825-6835-445b-8afd-13fb7004307e；SHA-256：22fef613ed365852d8545805de60f53971f6e7b5fd2d7495f7def3c1b9845824
- model-response-98b9f44b-f306-48da-a4f3-c11f03601293.json；ID：c7a488f4-be77-4ff9-a93a-12cbb3902d57；SHA-256：14b0f082a5b523e0be837e205e892b0ab9d2d4da3294d604b85012b771953402
- model-response-99151304-560a-42a3-accb-7636e37a6fa5.json；ID：7cb21c5a-b2ca-4025-b6e6-fd2d006bada0；SHA-256：eafaf974ba187550bbbfbcfb60a2479d8255e9681c5343d1c676933dd56be713
- model-response-9b48627b-f374-4864-8ae7-1d06636f50b9.json；ID：1392549b-cf56-4aca-8e54-753c7c5d1561；SHA-256：370598c26b42c0eefd411f8c8b7073f81aa2b9fc84c3213c8bcaf164e4b8845d
- model-response-9bb48812-b0e0-4f33-b071-1c344f15e092.json；ID：968b4c87-ded8-4724-ab04-9b1ebcb597cf；SHA-256：a639ceb53b1f6a5c366e58920787857d14c0ac8c5e845b738281c77494592bc3
- model-response-9bf95242-443d-42f7-81e5-f1dd498f95ba.json；ID：57a2d240-1c87-412f-b752-91c4678eb116；SHA-256：99e9a052c2266a0cfd3f9c66361a01e6f99e005721796fdcf64c1217b1ae4269
- model-response-9c4581fc-ee89-46b3-a9d2-a88c2b9d4160.json；ID：8fcb5714-788e-4ee9-a251-7966dc1fea40；SHA-256：b4bffcb4750ed07f34ba2f657c3d502652f6cbbcda1bd05544f079f3240ba7b7
- model-response-9cbbe608-93d2-4a45-8a45-2717b34c4688.json；ID：36e8a65c-607a-4b6f-bb91-ad0c1acca289；SHA-256：09efd32016c5c63f50491c96a4bff3cd17a0e5248bdd84d13ce366de5e74d03e
- model-response-9eb3030d-b3a7-4ca5-be4b-f1d4f355f749.json；ID：99654914-5123-4b1c-bc5d-a03e36b1bfa7；SHA-256：cc8d1813fac3408738c974573e0e72e0906bffdc25db42e785cf4f3632eac60b
- model-response-a2856bb4-0fb0-499e-92c2-1b09b77d2d11.json；ID：42777693-7ff2-4e1e-a367-81bb4fb0abcc；SHA-256：d43c0e150809f68ef87f76ae4cc17f4ab7af53143af3256c728186ed859adbc4
- model-response-a54bbbe9-6453-41f0-8bfb-66a0b6862ac2.json；ID：910d74f1-064c-4980-bc92-7ed18732c2d3；SHA-256：c2cdb7429d3005dc9011dfcda837cb9ba4f75e737427037bf9d3445ca4fe3d29
- model-response-a91f8a66-f80f-4c92-b6b2-59ce14d3b5f2.json；ID：5c077dd7-299a-4c7c-a001-12e8d9aa1a61；SHA-256：26b34560c7c28f814f4055db8ee552614b60b9e280c27f8f54221445fe693d3d
- model-response-a97a9b50-0698-4dc4-9276-ae2096bf54ad.json；ID：06dbde99-4f9b-45f9-be0f-ad95d3c3ab72；SHA-256：45b5195dd0c3d8fd89aa84b2a3f734652d954347d864e2b2f716cc860b2d7f7b
- model-response-aa9a93db-76e2-46bd-851c-58cdb7ec1537.json；ID：04118948-23ec-4e53-aa2a-df416ac5cb1b；SHA-256：c661927e59784bd2f29a3f2c4e379e9458288fda53f93809725a298889909cd6
- model-response-ab4150e8-baf6-4e57-9c5e-6e9aa2c52d57.json；ID：be9b51c0-f000-4339-b33f-4af7505d8255；SHA-256：08077d1ec3d55a1e8b8290899431722979d249018847840b79cb7683739c073b
- model-response-ac4239ce-5f69-44e0-9cbf-a7a32af58b44.json；ID：74f273a6-5348-4f85-948c-31a6df88ca42；SHA-256：3221a9b65d7e17e5ba17a39be6d56f3b4a1d31fb6736fa32959bf6b6e656984a
- model-response-ad20e488-1bc8-4422-b419-ef9bb3494987.json；ID：2c511ebf-1b32-4d42-a2eb-33999cbad6d2；SHA-256：8f849c59f7147399da1af0769ec0272d190f3589fbcb01715081c9bf07068bdf
- model-response-b3483235-d6d7-46e3-a015-3964dd426fc2.json；ID：b2640d61-2ed9-41ca-9578-331cf7771c85；SHA-256：da1b629509ce3b1ee32c1492db2fb78472ba829608d0637b571a0180fd67762a
- model-response-b3d31641-bd3c-4e48-8ebc-901925293dd8.json；ID：247c818f-4f3d-4577-a94d-573b035847a1；SHA-256：512dfaf2d3f60842495eb02fb91c05d30aaea91171355b996f3cae5e70a3c23c
- model-response-b57365a3-23b2-4e6c-a87e-45e43cd36f5f.json；ID：86d0d0b1-5299-4a2f-978a-dddfe4183c30；SHA-256：762c7d1f846c31616267a6bdfa2bf9c85525988dc92a4c0359c62429d39cb2ce
- model-response-b5a83a5e-a22b-401d-8c1d-84b79b1d50c4.json；ID：f20dbbab-add1-4820-ab09-dab7789a5662；SHA-256：87d3b0a4fdde243fe43eb6bbd5e2396c468af1cdf8fb2d9619d03726a083bced
- model-response-b5bf20c2-878f-4a56-b706-472c552c51f0.json；ID：23b20f77-f288-4abd-a518-78b52977055f；SHA-256：cf72a2898995b2f49f643c59aee55c9f89347343570008e3444a3d59e57017a4
- model-response-b7bf651b-61f0-4bf7-be78-f62ea5930337.json；ID：9d62719d-b3a2-4547-a4f5-92ff2dc9edfe；SHA-256：8c535da4ac3a15eb70117948ca56525ebb05cd2ae42b5c0566742b818bab6890
- model-response-b81035ef-cb24-4ec5-a13d-29f3205859bb.json；ID：c4aa7b7c-5d06-4f7a-9b10-9085789f97d7；SHA-256：1a6e52dbb62c6c0c346b4e61e60b1996aa468f0d46a64446a5d39d6095168423
- model-response-b8e35704-0ed1-4708-aa57-4323191ff71b.json；ID：9e3c409d-16fa-49a7-a3ac-243bab3452b5；SHA-256：65ccbdd4d12a3d35f0eeef90b589fe57f2999d923e772e454197357d33713237
- model-response-b8fc4797-9f41-4cb0-beb3-fe7ae5b743db.json；ID：caa35140-1804-4f00-a2eb-c78b6ae24aaa；SHA-256：954ac0a117e19047a95e02db8a72c000a544f0cdbc448d8bd83b646a1e656b9e
- model-response-bbe1fce6-2b56-4963-9a46-a7ca9f433df8.json；ID：8a8e02a8-7e9d-4d30-93e7-e4159c132a88；SHA-256：d7523eac4c2415d68f45ec81d7d2941231cb165740a8224f3c43d3a3f06d15ca
- model-response-bdc5b566-74d0-4aaf-9789-11ad4a4c487c.json；ID：7ee5d048-5fc8-465c-99f4-57458bfff09d；SHA-256：707351e7729e8d76ba9368f3462b91a4d671de617b47663efa5088e8de7b5cc5
- model-response-bf06af26-ddb9-4e4d-a4cb-3407568e318c.json；ID：22205031-6ca4-4789-8683-d4ecda3d3346；SHA-256：f696eb1bcceebec7cdd9328feb33985bd4b3c3e0c7b240bc78fc0210255ba44c
- model-response-c1007b48-dce5-4dd8-83fc-a1d03c2346b0.json；ID：9b516e74-b09c-4b9d-a384-89600c769418；SHA-256：a38d0a8a4b38e6625822fdd7782a6abab9925c5014d339d03ddced1f7333c131
- model-response-c2a0551b-d6cb-4d45-907d-387edb0437f1.json；ID：815bad8c-f98d-4319-b335-9d44ea42a359；SHA-256：c9c65a3b88dda6b49cd1f75d7907a14bb2f97527bb3daf47a5049b5ef02bdd74
- model-response-c31ff282-8b26-4942-a111-a72cfce8c619.json；ID：93a4f33b-6d44-4ffc-9cd5-d402dfbc0e22；SHA-256：efe7cfcd4316ab038afb48642ffb89bc2ec32eed598bfa6c69d9491b0d71ae74
- model-response-c5240687-3e4e-48e3-a117-715423b413d3.json；ID：124a6e7d-f131-47bd-921c-51be30ffe9d2；SHA-256：de21729fb975c89eb40c1e4989d8ed7451506f6467400738f0df30adc0f2848d
- model-response-ca4d772e-033e-4edf-8fd8-ea97615413d5.json；ID：0abc74ea-8fbc-40e0-bd6f-c8ace96d242e；SHA-256：8987d08b5f787ed10e7e150268cd5b6cb49ddb5da2ada394cbeb3c8840f95fde
- model-response-cffb76e4-d6a9-406d-9d3e-e442008924f9.json；ID：890c79de-9f79-483b-8761-6f0a405e71d7；SHA-256：7281a1c8ed84e8e2691c69d4254af82009ecb13787c0242092d63d2f9f246dea
- model-response-d321ecb1-ecb0-4caa-a5bb-0d15a600e2a0.json；ID：ecebaf9b-1c1c-4de4-a9b7-d9a5196cbaa1；SHA-256：6979b81cb0c2ddcd3d6a1b5d989dfd88ea7082bac4a8cd52be615ea3c6c240da
- model-response-d3bc8859-8ca9-41d5-92be-be784661723f.json；ID：340973aa-dac4-4cb2-ad96-94d7021bb169；SHA-256：fbbf28c89f9e1c8961d6298d6333567661fd10f83ea15278abe3a63098f64c67
- model-response-d535b1ea-d5ce-471c-950f-35b0c3b6c5da.json；ID：92e8d880-5380-4f55-96a8-85afe004b20a；SHA-256：f608f43c7ce934eda20eb0647716abbc54afea8e153feeebaf48da4c61d5a73a
- model-response-d9e247f4-549a-4dbe-97d8-d8261a4e1306.json；ID：b396005e-b279-45c6-9027-8624e98c2cca；SHA-256：f9daed00800f7913a01cbde4747967c1d2a1a84ce87d422217dabab75e1283f8
- model-response-dabe122f-4a86-46b5-ae41-c7fe189a656c.json；ID：c4694a42-43e3-47b4-b156-6243c157b6ac；SHA-256：f33aa04a0286f3ab3050b4bfdd8c88f2da20ffb9eb51929c3f6f68ea243def83
- model-response-e0369798-8872-4f4a-8256-af0db46ddf08.json；ID：f5b85d8b-dbb4-4e86-b519-deb2a82b270b；SHA-256：b757f39e5cff26e0298895c5e00d4ae3e0892122ee05675a2138db1f25b5e6d3
- model-response-e4096a0c-cfd6-4f33-ac84-e922c6dce8fa.json；ID：d658780f-5988-4f44-be45-343b3addd8f5；SHA-256：088ba35d357cda7ed8881f00cf8c500bc181c04ac5441471c23186df2cc2175a
- model-response-e7286fff-552b-4ecd-95f2-ce8896c301a3.json；ID：36643092-a186-4fb6-912b-6d404b56eada；SHA-256：bdc8b58bea7d8ff8b0f3be08a6af1ca1f083c5b294261178c2c11e1425ec1c58
- model-response-e8f8b56f-20fa-4700-8f3b-c419c9f1b55e.json；ID：bd1dde56-40ef-4cd6-adaf-27cd35fbf6fc；SHA-256：0247cbca7c250cdb1457204e59f5aaa1d652c42579ce7339204752e48e7e84bc
- model-response-e9010b61-5f32-4049-b0ad-4cf745704bd0.json；ID：31a1b445-dff5-4cd1-b9bd-23ff7218590e；SHA-256：f9e386044029becebfd42621cb39fc8af954d93ccea317b75093d03155aa355d
- model-response-e9c20441-de27-4d05-933b-170a07a97554.json；ID：0221a9e6-3485-499c-a82e-f0c68f912a30；SHA-256：34596d89130e856924fdbc0e43569d3f18020e86d44ce2d052b6c300e1a67d51
- model-response-e9e2fa83-75e2-4a28-9e31-344d175539c9.json；ID：c9afbfc9-8e60-452b-a602-a49427852917；SHA-256：301f063dc4bae408911acb914e8c5b0251648bae100ce8d0b7d2867f924f99be
- model-response-ed27cbf5-bea7-47ff-a862-ade222a20613.json；ID：2bce0f91-0ef9-4b31-8812-84abe6f291e2；SHA-256：23a344e6711d4bd8f9cafc98fc1ffa6f76d406a1185e6313eb9695c853163385
- model-response-ee2fe112-18ad-4ac5-a805-647dc65d8e24.json；ID：2e97c022-4006-4508-8d7a-d2d9ff978424；SHA-256：53cc1e5746a5d1afe0340803eab7454b3c52c4cece086890c76903f111c0dc01
- model-response-ee58c0a4-559d-466e-9fc9-6e03dc6a2f07.json；ID：631ddbdf-b6d0-493b-9f58-dbf827cb4c64；SHA-256：6c5b71a44549cf06457014d3eb05d6cada1907972a67b9d42cf0d2969879b81b
- model-response-ef0e09f2-faa2-4d7d-ab13-425028912841.json；ID：1b3991b0-aec4-4770-9b43-d403315fcd89；SHA-256：dae0d1d55e65773973e95b30b5cf2bf64831ec6ac43114e3986303597aba7206
- model-response-f05aeb56-ad49-403f-b3e5-b77ef868ab31.json；ID：3c9a548a-74bd-4ee7-aacd-603ab9adf8d0；SHA-256：3d6debfdcc6ffe55a43dee087e16125c3e8125e71b6e4cba996b77e515c9b99d
- model-response-f2595365-da00-4943-a5a9-c991f78f1ec7.json；ID：4bedf933-c7ed-4af9-a484-8ba432567b39；SHA-256：4377a0ecc4654b10283ffa56df4a9d38b0af793780808d5109d9060b8cf40b48
- model-response-f393ebd0-ddf1-47a1-8ac6-9c4761e70dff.json；ID：12892a1f-741f-438d-8c0d-a6cde06ec19b；SHA-256：7db76d442d624cc21bec097d728f867b40f294648055ea2ed026c454deaba725
- model-response-f5a433a2-da37-4175-a30d-649b577719e6.json；ID：eab17c66-ecee-4ee8-a654-7d5e1a3716db；SHA-256：967e86ee305f5d155a42080374f3603aa875d44f0052bd0e41f326dc08c9501f
- model-response-f6213447-3e66-4dc3-86b3-c443b36ab1f6.json；ID：679ca8f5-c176-46e1-a7c7-793a4c8a0587；SHA-256：9c2db59abad8b09473077403d09515b829ab686d2a90a494e98705fe3627ed79
- model-response-f6343050-ecb6-473d-96cc-da3cf9e233b1.json；ID：ed892b20-6db2-4896-b866-4d73397d69b0；SHA-256：e2593c574860c9703693182c5d88c9cb1b8028314b6dc9efa7ae81b6791315bf
- model-response-f6ef6350-b222-4cdf-b07d-31323dff4a36.json；ID：2c10ea35-4884-496c-9618-d7df709b82dc；SHA-256：cd642e1b927d6605e2561cb5458562330b02f8ed62c8ff87c1a08993388181c3
- model-response-f7c81628-6ca9-4494-aa44-ef0854df6383.json；ID：3dcaa59e-2fe3-44d4-8e61-a78e46435b6a；SHA-256：132261dbe47b930818b4035dd7ce6c0b6e799f276f0468207cd25ba7d3e10694
- model-response-fad34cbd-dccf-424d-b628-e87c48e24f38.json；ID：73f13bea-1905-48a6-afd2-8c1bf82cf056；SHA-256：1602ad19403451def23771fbe6cbfbcb7ea09a28942d34625aba30625ccd82bd
- p09-ollama-zerolen-fixed.zip；ID：38236557-c977-4131-a739-224e50c8c3df；SHA-256：d19a1503b5647f1497335f11eb6a66288cd355f32476a570a4feb5947914dcab
- snapshot-manifest.json；ID：5640ac55-5573-473b-b290-36520acaf8a1；SHA-256：24d1aecabbe29d28241097a2d350e4473fac95aba490cb1737bd70f46332dcc5
- source-snapshot.zip；ID：beda4938-bb1f-4d6a-b518-a640d725aaa7；SHA-256：b783cb05475c436ddcf76b87881c58408174ec1d6dd4f8242442e7bd108018bf
