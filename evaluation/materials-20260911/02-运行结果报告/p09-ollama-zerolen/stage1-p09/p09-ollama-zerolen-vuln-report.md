# AegisAudit 分析报告

项目：对照池评测 20260911-073454

任务：fa67ca7d-fcf5-4f73-9003-416b043e3b96

状态：Partial

目标 SHA-256：e02637ce9d586cbb131ad41df32f9af31214fb823fff0e25aecf7e7e2d78eb3b

结果快照 · 数据截至 2026-09-11T07:44:43.623Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：PARTIAL；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| BatchSize | llama/runner/image.go | L98–L113 | PARSED |
| EmbedSize | llama/runner/image.go | L115–L121 | PARSED |
| Free | llama/runner/image.go | L53–L64 | PARSED |
| NeedCrossAttention | llama/runner/image.go | L123–L131 | PARSED |
| NewEmbed | llama/runner/image.go | L66–L96 | PARSED |
| NewImageContext | llama/runner/image.go | L29–L51 | PARSED |
| addImage | llama/runner/image.go | L159–L179 | PARSED |
| findImage | llama/runner/image.go | L147–L157 | PARSED |
| hashImage | llama/runner/image.go | L139–L143 | PARSED |
| llama/runner/image.go | llama/runner/image.go | L1–L179 | PARSED |

## 审计策略与优先级

目标为单文件 Go 源码 llama/runner/image.go（10 个单元：1 个 module + 9 个函数），静态结构分析，无构建/运行、无 Semgrep、call\_graph\_complete=false。优先围绕三类外部/信任边界展开：\(1\) NewEmbed 接收外部图像字节与 aspectRatioId 的入口函数；\(2\) 使用共享可变状态（sync.Mutex、maphash.Hash、images 缓存）时的并发与生命周期语义；\(3\) 以非加密 64 位哈希作为图像→嵌入缓存键的语义正确性边界（碰撞即返回错误图像的嵌入）。计划按入口与状态共享程度排序，先审计 NewEmbed/Free 与其调用的 hash/find/add 缓存三件套，再审计模型加载与规模计算函数。

1. u\_f34fa3b76ba569a25991b10ef4348992：外部图像字节 \[\]byte 与 aspectRatioId 的直接入口；同时调用 hashImage/findImage/addImage 并持有 c.mu。第71行 hashImage 在加锁前调用，操作共享的 c.imageHash，构成锁外共享状态访问（数据竞争）嫌疑，需结合调用图与锁语义确认。
2. u\_408832db78ec7e3b14c2184c1f961bb0：Free 直接释放 clip/mllama 但不持 c.mu，也不置空指针；与 U0004 在锁内使用这些字段存在释放-使用/双重释放的并发生命周期风险，属身份与对象所有权边界，需核对上层调用时机（调用图不完整，须标为缺口）。
3. u\_00277071a5df08e70f60877b5f5ab62d：hashImage 用 maphash 的 64 位非加密哈希且未处理写错误（\_, \_ = Write），被用作缓存键；哈希碰撞会把另一张图像的嵌入当作当前结果返回，是缓存键信任边界的语义问题（非内存安全线索）。
4. u\_0f306127855a96e71b64afb7283b6c47：findImage 以哈希命中返回缓存 val 切片（\[\]\[\]float32）且不拷贝，调用方若修改会污染缓存；命中判断仅靠哈希相等，需与 U0004/U0008 联动核实键唯一性与别名风险。
5. u\_e8ab6c669efeb35831f71ab37051b961：addImage 实现 LRU 替换并写入共享 c.images，须在持有锁前提下由 U0004 调用；bestImage 的选择逻辑与切片别名（缓存与返回给调用方共享底层数组）是关键审计点。
6. u\_dacf3351a6a9f1778fa60aafd35dd793：模型路径 modelPath 为外部/配置输入，经由 llama.GetModelArch 与 arch 分支（clip/mllama）决定加载路径；错误信息回显 modelPath，且未识别构建与入口，归为外部输入与信任边界审计对象。
7. u\_48a2dd9d1376ae6063ebe4efb114ff1f：BatchSize 依据 mllama 分支返回 1 或 configuredBatchSize，configuredBatchSize 为调用方传入的规模参数（外部输入候选）；与 embedding 大内存分配相关，注释自述分配可能失败，值得核对边界与零值/负值处理。
8. u\_e8da74c40e81895bcb95c0d8569fca90：module 级：常量 imageCacheSize=4、ImageContext 结构（mu/clip/mllama/images/imageHash）定义了并发契约与共享状态边界，作为其余函数的契约基线。
9. u\_9fe6a0a2dc0edbcc2414e52ac0b65ce7：EmbedSize 读取 llamaContext.Model\(\).NEmbd\(\)，依赖外部上下文对象状态，需核实空值/失败路径与并发调用时的模型生命周期。
10. u\_70937d5e95f749857c9f72802d41f873：NeedCrossAttention 遍历输入 input 并读取 input.embed，是请求侧输入结构进入本模块的入口之一；语义上决定是否走跨注意力路径，需确认 nil/空输入与信任假设。

规划限制：分析范围为 STRUCTURE\_ANALYSIS，vulnerability\_audit=NOT\_RUN、verification=NOT\_RUN，未构建、未运行，所有结论均为待验证的静态疑点。

规划限制：call\_graph\_complete=false，Free/NewEmbed 的调用时机、锁持有者与上层请求流不可见，并发与释放-使用结论必须显式保留为缺口。

规划限制：Semgrep UNSUPPORTED（Windows 原生执行器未就绪），仅有内建线索；clues 只标出 U0001/U0005 的“身份或权限边界”，未构成漏洞证据。

规划限制：工具集中未提供 llama 包内部实现（llama.GetModelArch/NewClipContext/NewMllamaContext/ClipContext.NewEmbed/MllamaContext.NewEmbed），外部字节如何被解析、是否做维度/大小校验不可判定。

规划限制：未识别构建系统、入口、输入接口与依赖清单；‘外部输入’仅依据函数签名（\[\]byte、modelPath、configuredBatchSize、inputs 可变参数）推断，非运行期确认。

规划限制：Human annotations 为空且仅为参考数据，无可交叉验证的第三方结论。

## 发现与复核

静态结论范围：COMPONENT

### hashImage 在未持有 c.mu 的情况下复用共享 maphash.Hash 实例（并发 NewEmbed 时数据竞争）

CWE-362 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：NewEmbed\(llamaContext, data, aspectRatioId\) 的并发调用（data 为外部图像字节）

危险操作：c.imageHash.Reset\(\)/Write\(image\)/Sum64\(\)（共享可变哈希状态）

防护缺口：哈希计算未处于 c.mu 临界区内；调用点 U0004 第 71 行取哈希早于第 73 行加锁，hashImage 内部也无同步/无每调用独立哈希对象

前提：同一 \*ImageContext 实例被多个 goroutine 并发调用 NewEmbed（或多请求复用同一上下文且上游未串行化）；本快照未解析调用方调度方式

影响：缓存键可能被并发破坏，导致错误嵌入被写入或命中错误缓存项、跨请求结果污染；数据竞争亦可能触发 panic 造成服务不可用

修复：在持有 c.mu 后再计算哈希（把 hashImage 调用移入临界区），或改为每次调用创建局部 maphash.Hash 并以固定 Seed 初始化、避免共享可变状态；同时用 -race 测试并发路径并明确记录所有共享状态访问都在锁内。

- 证据：llama/runner/image.go L140–141 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\)
- 证据：llama/runner/image.go L71–74 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	hash := c.hashImage\(data\)  	c.mu.Lock\(\) 	defer c.mu.Unlock\(\)
- 证据：llama/runner/image.go L17–27 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：type ImageContext struct { 	// mu is required to be held when generating embeddings or accessing the cache 	mu sync.Mutex  	clip   \*llama.ClipContext 	mllama \*llama.MllamaContext  	// cache of images to embeddings 	images    \[\]imageCache 	imageHash maphash.Hash }

复核 v2（MODEL，VALIDATED）：原始代码证实：ImageContext 内含共享可变字段 imageHash maphash.Hash（U0001:17-27），结构体注释明确声明“mu is required to be held when generating embeddings or accessing the cache”。但 NewEmbed 在第71行先调用 c.hashImage\(data\)，到第73行才 c.mu.Lock\(\)，即生成嵌入阶段已先访问共享哈希状态。U0008 的 hashImage 连续执行 c.imageHash.Reset\(\)/Write\(image\)/Sum64\(\)，全程未持锁、无每调用独立哈希对象，也无内部同步。data 直接作为参数流入该共享哈希（INPUT\_CONTROL/REACHABILITY 成立）。因此当同一 \*ImageContext 被并发调用时，多个 goroutine 同时读写同一 maphash.Hash 实例，构成 Go 内存模型数据竞争：可产生被破坏的哈希→命中/写入错误缓存项（跨请求结果污染），或 Write 内部切片并发增长导致 panic。该组件自身持有 sync.Mutex 并明文规定生成嵌入时须持锁，正是其按并发使用设计的证据，而代码违反了该不变式。

反证：已考虑的抗辩：hashImage 仅访问 c.imageHash，未直接触碰 c.images 缓存，且真正的缓存查找/写入 findImage\(U0004:76\)/addImage\(U0004:92\) 确在 c.mu 临界区内；若仅单线程调用则不构成竞争。但这些不成立：imageHash 本身仍是跨调用共享的可变状态，且注释把“generating embeddings”也纳入持锁要求；缺少每调用局部哈希对象正是缺陷所在。

待补信息：本快照只含 llama/runner/image.go，未包含对 NewEmbed 的调用方或调度模型，故“同一 ImageContext 被并发调用”是由组件自身的互斥锁与不变式注释（并发行使用契约）推定的组件级前置条件，未在快照中观测到真实并发；是否多请求复用同一上下文、并发下 maphash.Hash 具体是产生错误摘要还是 panic 亦未观测。结论限于该组件接口，不宣称完整部署已被利用。
静态结论范围：COMPONENT

### 嵌入缓存键仅取图像字节的 64 位非加密哈希，未包含 aspectRatioId/后端类型（跨请求键语义不完整，碰撞时暴露他图嵌入）

CWE-488 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：NewEmbed 的 data 与 aspectRatioId（由请求方提供，二者共同决定 mllama 嵌入结果）

危险操作：以 hash := c.hashImage\(data\) 作为缓存键，随后在 79 行以 aspectRatioId 生成嵌入、92 行写入缓存

防护缺口：缓存键未纳入 aspectRatioId（以及后端 clip/mllama 区分、模型/上下文标识）；findImage 仅比对 uint64 key；64 位非加密哈希无抗碰撞保证

前提：同一 ImageContext 被多次请求复用；同一图像字节以不同 aspectRatioId 请求（确定发生），或发生 64 位哈希碰撞（难度高）

影响：返回与请求参数不匹配的嵌入（下游视觉生成结果错误）；若碰撞发生，其它图像对应的嵌入会被返回给当前请求，构成跨请求数据暴露与结果完整性破坏

修复：将 aspectRatioId 与后端类型纳入复合缓存键，或在命中时校验参数一致性；如需抗碰撞保证改用加密哈希（如 SHA-256 截断需谨慎）；为缓存键语义、生命周期与并发访问编写文档并补充测试。

- 证据：llama/runner/image.go L71–71 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	hash := c.hashImage\(data\)
- 证据：llama/runner/image.go L79–79 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：			embed, err = c.mllama.NewEmbed\(llamaContext, data, aspectRatioId\)
- 证据：llama/runner/image.go L92–92 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：		c.addImage\(hash, embed\)
- 证据：llama/runner/image.go L147–156 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：func \(c \*ImageContext\) findImage\(hash uint64\) \(\[\]\[\]float32, error\) { 	for i := range c.images { 		if c.images\[i\].key == hash { 			slog.Debug\(&quot;loading image embeddings from cache&quot;, &quot;entry&quot;, i\) 			c.images\[i\].lastUsed = time.Now\(\) 			return c.images\[i\].val, nil 		} 	}  	return nil, errImageNotFound

复核 v2（MODEL，INCONCLUSIVE）：组件级可静态确认键语义不完整：NewEmbed 以 c.hashImage\(data\) 为唯一缓存键（U0004:71；U0008:139-142 为 maphash Sum64），而嵌入计算按参数化的 aspectRatioId 进行（U0004:79），写缓存也只用该 hash（U0004:92），查找仅比较 uint64 key（U0009:149）。因此同一 data 以不同 aspectRatioId 调用时会命中 U0004:76 的缓存并直接返回先前参数下算出的嵌入（U0004:95），该部分由参数即可触发，属确定性缺陷。但候选主张的严重部分——“碰撞时返回其它图像的嵌入、构成跨请求数据暴露”——额外要求攻击者构造 64 位 maphash 碰撞（U0008:139-142，seed 随机化），此额外能力在给定证据中完全没有支持，属未证实的必要攻击条件，故整体只能判 INCONCLUSIVE。

反证：U0004:73-74 以 c.mu 全程加锁排除并发写导致的缓存错乱；U0008:140-142 使用带随机 seed 的 maphash，离线/无探测构造 64 位碰撞困难；若 mllama.NewEmbed 实现上忽略 aspectRatioId，则键缺 aspectRatioId 不会产生错误结果（但调用点显式传参表明其参与结果生成）。

待补信息：1\) 缺少攻击者能控制或预测 maphash 碰撞（或对缓存做大量自适应探测）的证据，这是候选跨图像数据暴露路径的必要条件；2\) 未提供 c.mllama.NewEmbed 实现，无法直接确认 aspectRatioId 确实改变输出嵌入；3\) 缓存淘汰/驻留期与上层是否校验 aspectRatioId 一致性未在给定单元中体现。
静态结论范围：COMPONENT

### 图像嵌入缓存仅以 64 位非加密哈希为键且不校验原始数据与宽高比

CWE-328 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：NewEmbed 的 image \[\]byte 与 aspectRatioId，以及缓存中先前请求写入的条目

危险操作：findImage 仅按 c.images\[i\].key == hash 返回 c.images\[i\].val

防护缺口：缓存键不含 aspectRatioId 与模型标识，命中后不比对原始图像字节或嵌入来源，键由非加密 maphash 生成且无冲突检测/失效策略

前提：两个不同图像产生相同 64 位摘要，或同一图像以不同 aspectRatioId 请求 mllama 嵌入

影响：可能返回其他请求图像的嵌入（跨请求数据边界混淆、结果错误且难以察觉），或在宽高比变化时返回参数不匹配的嵌入，污染下游推理输出

修复：将 aspectRatioId 与模型标识纳入缓存键，命中后比对原始字节摘要（更强的哈希或直接字节比较），并评估使用抗碰撞哈希

- 证据：llama/runner/image.go L149–152 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：		if c.images\[i\].key == hash { 			slog.Debug\(&quot;loading image embeddings from cache&quot;, &quot;entry&quot;, i\) 			c.images\[i\].lastUsed = time.Now\(\) 			return c.images\[i\].val, nil
- 证据：llama/runner/image.go L71–76 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	hash := c.hashImage\(data\)  	c.mu.Lock\(\) 	defer c.mu.Unlock\(\)  	embed, err := c.findImage\(hash\)
- 证据：llama/runner/image.go L176–178 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	c.images\[bestImage\].key = hash 	c.images\[bestImage\].val = embed 	c.images\[bestImage\].lastUsed = time.Now\(\)

复核 v2（MODEL，INCONCLUSIVE）：组件内部可静态确认：NewEmbed 只用 data 经 hashImage\(U0001:139-143, 非加密 maphash/SHA无关的 64 位摘要\) 生成缓存键，findImage\(U0009:147-157\) 命中时仅比较 c.images\[i\].key == hash 并直接返回 c.images\[i\].val，aspectRatioId 与原始字节都不参与键也不在命中时复核；因此在同一 ImageContext 上先 NewEmbed\(data, arA\) 再 NewEmbed\(data, arB\)（arB 不同）时，第二次会在 U0004:76 命中并返回第一次按 arA 计算的嵌入，aspectRatioId 参数被忽略。这一“键不含宽高比、命中不校验”的接口层缺陷是确定的。但候选项所主张的核心安全影响——返回“其他请求图像”的嵌入、跨请求数据边界混淆——需要两张不同图像产生相同的 64 位摘要：maphash 的种子在进程内随机且不可由输入预测，缓存容量仅 imageCacheSize=4\(U0001:15,48\)，未提供任何可构造或可观测的碰撞证据，故该影响不成立；而宽高比路径的失配是否真会造成不同嵌入，还取决于目标快照之外的 llama.MllamaContext.NewEmbed 是否实际使用 aspectRatioId，本快照内无该实现证据。

反证：1\) 缓存仅保留 4 条\(U0001:15,48\)，碰撞面被极大压缩；2\) maphash 为进程随机种子\(import &quot;hash/maphash&quot; U0001:6, 结构字段 imageHash U0001:26\)，攻击者无法离线预计算碰撞，也不存在可预测的全进程常量摘要；3\) 若宽度比参数在调用侧由图像字节本身推导（同一字节必然同一 aspectRatioId），则键省略宽高比不会产生可观测失配；4\) 整个缓存由 c.mu 互斥保护\(U0004:73-74\)，不存在并发读写不一致。

待补信息：1\) 目标快照外 llama.MllamaContext.NewEmbed 对 aspectRatioId 的实际使用方式（是否影响输出嵌入），当前代码只显示参数被透传\(U0004:79\)；2\) 调用侧是否可能对同一 image \[\]byte 传入不同 aspectRatioId，以及该值是否可由请求输入左右；3\) 是否存在实际可构造的 64 位 maphash 碰撞或可观测的碰撞事件。
静态结论范围：COMPONENT

### Free 未持锁释放视觉上下文，与并发 NewEmbed 构成释放后使用/数据竞争

CWE-416 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：调用方对同一 \*ImageContext 的并发调用（一个 goroutine 在 NewEmbed 中生成嵌入，另一个执行 Free）

危险操作：c.clip.Free\(\) 与 c.mllama.Free\(\)

防护缺口：Free 未获取结构体注释声明用于保护嵌入生成与缓存的 c.mu，也未在释放后把 c.clip/c.mllama 置 nil 或设置失效标志

前提：同一 ImageContext 在用于 NewEmbed 期间被另一线程 Free

影响：已释放的原生视觉上下文可能仍被使用，造成崩溃、原生内存破坏或未定义行为；字段读写与其他 goroutine 的访问构成数据竞争

修复：在 Free 内先 c.mu.Lock\(\)（并保证幂等/一次性语义），释放后把 c.clip/c.mllama 置 nil，或用引用计数/显式关闭协议与 NewEmbed 互斥

- 证据：llama/runner/image.go L58–63 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	if c.clip \!= nil { 		c.clip.Free\(\) 	} 	if c.mllama \!= nil { 		c.mllama.Free\(\) 	}
- 证据：llama/runner/image.go L83–87 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：		} else if c.clip \!= nil { 			embed, err = c.clip.NewEmbed\(llamaContext, data\) 			if err \!= nil { 				return nil, err 			}
- 证据：llama/runner/image.go L18–19 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	// mu is required to be held when generating embeddings or accessing the cache 	mu sync.Mutex

复核 v2（MODEL，INCONCLUSIVE）：Free\(U0003，58-63行\)确实未获取 c.mu，且在调用 c.clip.Free\(\)/c.mllama.Free\(\) 后未把字段置 nil，而 NewEmbed 在入口处持锁访问同一字段\(U0004，73-74、78-87行\)，因此若同一 \*ImageContext 上存在并发的 Free 与 NewEmbed，二者会无同步地读写 c.clip/c.mllama，构成释放后使用/数据竞争。但本快照中没有任何调用方、生命周期管理或 goroutine 分配证据能证明这种并发调用确实存在：Free 只在本文件定义，搜索到的 Free/NewEmbed 匹配全部位于 llama/runner/image.go，无外部调用者可见。结构体注释\(U0001，18-19行\)只声明 mu 用于“生成嵌入或访问缓存”，把释放排除在受保护范围外，暗示设计上假设 Free 发生在所有使用结束之后，但该假设未见代码强制。因此该组件内部确实缺少防御，然而成立所需的并发前提未被证实，属未决。

反证：NewEmbed 全程持有 c.mu\(U0004，73-74行\)，故任何同样遵守该锁约定的并发嵌入调用之间不会竞争；结构体注释\(U0001，18-19行\)将锁的适用范围限定为嵌入生成与缓存访问，未把 Free 纳入同一互斥契约，说明释放路径被设计为生命周期末端的一次性调用；无证据表明同一实例会被并发 Free。

待补信息：同一 \*ImageContext 是否可能在 NewEmbed 执行期间被另一 goroutine 调用 Free（即释放与使用的生命周期是否由本文件之外的调用方互斥）；Free 是否被重复调用；是否存在引用计数或关闭协议在外部保证二者不并发。这些调用方/并发前提在本快照中不可见。
静态结论范围：COMPONENT

### hashImage 以非加密 64 位哈希作为图像→嵌入缓存键，且命中后无原像/字节校验，碰撞即返回他图嵌入

CWE-345 · MEDIUM · 复核 REJECTED · 验证 NOT\_RUN

输入：NewEmbed\(llamaContext, data \[\]byte, aspectRatioId\) 中外部传入的图像字节 data（经 line 71 调用 hashImage）

危险操作：c.imageHash.Write\(image\)/Sum64 生成 64 位键（line 140-142），该键在 findImage（line 147-153）中仅与 c.images\[i\].key 比较后直接返回缓存值

防护缺口：缓存键缺少碰撞校验：命中缓存时没有对原图像字节（或强哈希/长度）做二次比对；键派生使用非加密、非抗碰撞的 maphash（64 位）而非 SHA-256 等，也没有把 aspectRatioId/模型标识并入键。

前提：图像字节由不可信调用方控制；进程内存在多个请求/租户共享同一 ImageContext；攻击者能构造与目标图像 64 位哈希相同的字节序列（或依赖自然碰撞）并触发缓存命中。

影响：返回错误的图像嵌入：模型输出与输入图像不一致（语义完整性破坏）；在跨用户场景下可泄露其他请求图像对应的嵌入特征，构成信息混淆/泄露。

修复：在缓存条目中保存图像字节或强哈希（如 SHA-256）并在 findImage 命中时校验；碰撞或校验失败时退化为重新计算；如需保留快速路径，可将 64 位 maphash 结果仅作为分桶索引而非唯一身份。

- 证据：llama/runner/image.go L140–142 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
- 证据：llama/runner/image.go L71–74 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	hash := c.hashImage\(data\)  	c.mu.Lock\(\) 	defer c.mu.Unlock\(\)
- 证据：llama/runner/image.go L147–153 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：func \(c \*ImageContext\) findImage\(hash uint64\) \(\[\]\[\]float32, error\) { 	for i := range c.images { 		if c.images\[i\].key == hash { 			slog.Debug\(&quot;loading image embeddings from cache&quot;, &quot;entry&quot;, i\) 			c.images\[i\].lastUsed = time.Now\(\) 			return c.images\[i\].val, nil 		}

复核 v2（MODEL，REJECTED）：候选关于代码事实的描述正确：hashImage 用 hash/maphash（64 位，Go U0008 line 139-143），NewEmbed 以 data 生成该键（U0001 line 71），findImage 命中时仅比较 key 且直接返回缓存值（U0001 line 147-153），确实没有对原图像字节或强哈希做二次比对；image.go 顶部导入 &quot;hash/maphash&quot;（U0001 line 6）、字段 imageHash maphash.Hash（U0001 line 26）。但该“缺陷”要成为漏洞，需攻击者能构造出与目标图像在当前进程随机种子下相同的 64 位 maphash。maphash 的设计目标正是抗碰撞攻击：其种子为进程内随机值、不对外暴露，且哈希值也从不返回给调用方，因此攻击者无法离线定向求解某张已缓存图像的键；缓存仅 4 项（imageCacheSize=4，U0001 line 15），自然碰撞概率约 4/2^64，可忽略。故“碰撞即返回他图嵌入”的前提不成立，不构成本组件接口上的授权/完整性缺陷（无内容校验属纵深防御建议，非漏洞）。

反证：已确认的防御/限制：\(1\) 哈希实现为 hash/maphash（U0001 line 6、26），使用进程随机种子，攻击者不知种子无法定向构造碰撞，且哈希值不在接口上暴露；\(2\) 缓存容量仅为 4（U0001 line 15），仅需与 4 个键比较，自然碰撞概率极低；\(3\) 缓存与哈希对象在 c.mu 下访问（U0001 line 73-74），不存在可利用的并发重写。缺少内容/强哈希二次校验确为事实（U0001 line 149-153），但在上述条件下属于纵深防御，而非可触发漏洞。

待补信息：未观察到运行中的服务及 ImageContext 是否跨用户共享；但这不影响结论——即便共享，定向碰撞仍不可行。若要主张漏洞，需证明攻击者能获知或控制 maphash 种子/键值，这是本组件边界之外且无源码依据的能力。
静态结论范围：COMPONENT

### hashImage 在未持有 c.mu 的情况下复用并改写共享 maphash.Hash，与并发 NewEmbed 构成数据竞争

CWE-362 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：同一 ImageContext 上并发到达的 NewEmbed 调用（外部图像请求）

危险操作：c.imageHash.Reset\(\)/Write\(image\)/Sum64\(\) 对共享 hasher 状态的非同步读写（line 140-142）

防护缺口：调用点未在锁内执行键计算：line 71 的 hashImage 位于 line 73 的 c.mu.Lock\(\) 之前；hashImage 内部也没有对 c.imageHash 的互斥保护或改用每次调用独立的 hasher。

前提：同一 ImageContext 被多 goroutine 并发使用（服务端并发处理图像嵌入请求）；两个调用在 line 71 与 line 73 之间交错执行。

影响：键计算结果不确定（可能得到混合/空数据的哈希），导致缓存误命中或缓存永不命中；同时构成对共享内存的并发读写，存在内存状态被破坏与竞态崩溃的风险（具体后果未经运行验证）。

修复：把 hashImage 调用移入 c.mu 临界区（或改为在函数内构造局部 maphash.Hash/使用无共享状态的哈希函数），确保键计算与缓存查找/写入在同一锁保护下，并使用 -race 测试覆盖。

- 证据：llama/runner/image.go L140–142 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
- 证据：llama/runner/image.go L71–74 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	hash := c.hashImage\(data\)  	c.mu.Lock\(\) 	defer c.mu.Unlock\(\)
- 证据：llama/runner/image.go L17–27 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：type ImageContext struct { 	// mu is required to be held when generating embeddings or accessing the cache 	mu sync.Mutex  	clip   \*llama.ClipContext 	mllama \*llama.MllamaContext  	// cache of images to embeddings 	images    \[\]imageCache 	imageHash maphash.Hash }

复核 v2（MODEL，VALIDATED）：在 llama/runner/image.go 中，NewEmbed 于第 71 行调用 c.hashImage\(data\) 计算缓存键，其后第 73 行才 c.mu.Lock\(\)。U0008 的 hashImage 对结构体级共享字段 c.imageHash（U0001 第 26 行 maphash.Hash 值字段）执行 Reset/Write/Sum64，这三步都会改写该 Hash 的内部状态。ImageContext 第 17-19 行明确声明 mu 用于保护生成嵌入与访问缓存，而键计算被排除在临界区之外，且 hashImage 无局部 hasher 或自有同步。因此同一 ImageContext 上并发调用 NewEmbed 时，goroutine 之间会对同一 hasher 内部缓冲发生未同步读写（真正的数据竞争窗口在 line 71 与 line 73 之间，以及两个并发 hashImage 之间），并且缓存键可能由交错状态产生，导致 findImage/addImage 的键不一致。这是组件自身接口（NewEmbed 参数 data）即可触发的同步缺陷，非纯防御性建议。

反证：存在 c == nil 的早退（第 67-69 行）以及 mu 保护的临界区（第 73-74 行），但锁起始于键计算之后，故不构成对 hashImage 的保护；未发现 hashImage 内部有锁、sync.Pool、局部 maphash.Hash 或每次调用重新 Seed 的替代实现；search\_code 显示 hashImage 仅在第 71 行被调用，无其他持锁调用路径可掩盖该问题，因此不构成反证。

待补信息：未提供调用 NewEmbed 的具体上层路径与部署是否确实对同一 ImageContext 并发发起图像嵌入请求的证据；未运行 -race/压测以观测实际交错与崩溃收益；同一 ImageContext 的实际生命周期与共享范围（单请求级还是进程级）未知。
静态结论范围：COMPONENT

### 图像缓存键仅由图像字节哈希构成，未纳入 aspectRatioId 等嵌入生成参数，导致跨请求嵌入错配

UNKNOWN · MEDIUM · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：NewEmbed 的外部入参 data \[\]byte 与 aspectRatioId int；addImage 的 hash 参数由 data 派生

危险操作：c.images\[bestImage\].key = hash 写入缓存键，后续以同一 hash 命中缓存直接返回已存嵌入

防护缺口：缓存键未包含 aspectRatioId（以及生成嵌入所用的模型/上下文身份），仅在 hashImage 中对 image 字节做单次哈希；命中条目也未校验生成参数一致

前提：ImageContext 在同一 runner 进程内被多个请求共享；两个请求传入字节相同但 aspectRatioId 不同的图像；mllama 分支被使用

影响：第二个请求在未重新推理的情况下获得为另一 aspectRatioId（或另一请求上下文）计算的嵌入，图像语义与返回嵌入不一致，造成跨请求数据混淆与模型输出污染；命中即返回且不重新校验，属静默错误。

修复：将缓存键扩展为 hash\(data\) 与 aspectRatioId、模型标识（clip/mllama 及模型路径/句柄）的组合，命中后再校验生成参数；或对 mllama 分支按 aspectRatioId 分桶缓存。

- 证据：llama/runner/image.go L176–176 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	c.images\[bestImage\].key = hash
- 证据：llama/runner/image.go L139–143 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\) }
- 证据：llama/runner/image.go L71–71 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	hash := c.hashImage\(data\)
- 证据：llama/runner/image.go L79–79 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：			embed, err = c.mllama.NewEmbed\(llamaContext, data, aspectRatioId\)
静态结论范围：COMPONENT

### addImage 直接以 bestImage 下标访问切片且不校验缓存长度，空缓存时可触发越界 panic

CWE-129 · LOW · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：hash 与 embed 调用参数；底层依赖 c.images 切片长度（本文件外构造点不可见）

危险操作：c.images\[bestImage\] 的下标读取与写入

防护缺口：缺少 len\(c.images\) &gt; 0 或 bestImage 合法范围的边界校验；循环结束后未验证是否选中有效槽位

前提：ImageContext.images 未被赋值为非空切片（例如本文件外的结构体字面量或其他构造函数）而调用 NewEmbed → addImage

影响：切片越界导致 panic，使图像嵌入路径乃至 runner 进程崩溃，可被构造为拒绝服务。

修复：在 addImage 起始处校验 len\(c.images\) 或对空/零长度缓存直接返回；使用受检下标访问；将缓存分配收敛到唯一构造函数并断言。

- 证据：llama/runner/image.go L175–176 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	slog.Debug\(&quot;storing image embeddings in cache&quot;, &quot;entry&quot;, bestImage, &quot;used&quot;, c.images\[bestImage\].lastUsed\) 	c.images\[bestImage\].key = hash
- 证据：llama/runner/image.go L160–173 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	best := time.Now\(\) 	var bestImage int  	for i := range c.images { 		if c.images\[i\].key == hash { 			bestImage = i 			break 		}  		if c.images\[i\].lastUsed.Compare\(best\) &lt; 0 { 			best = c.images\[i\].lastUsed 			bestImage = i 		} 	}
- 证据：llama/runner/image.go L48–48 ；产物 a9c94386-2d6b-463a-a74a-054c0da98816；引用：	c.images = make\(\[\]imageCache, imageCacheSize\)

## 关键逻辑与人工修订

- u\_00277071a5df08e70f60877b5f5ab62d · CRYPTOGRAPHY · v1（MODEL）：调用 hash/maphash（非加密哈希）以图像字节生成 uint64 摘要，仅用作图像→嵌入缓存键，未见用于口令、令牌或完整性/认证校验，因此不构成认证或加密强度的安全依赖；但共享实例的非并发安全与其 64 位键空间必须按“正确性/并发”而非“密码学安全”要求处理。
  - 原文：llama/runner/image.go L139-L142；func \(c \*ImageContext\) hashImage\(image \[\]byte\) uint64 { 	c.imageHash.Reset\(\) 	\_, \_ = c.imageHash.Write\(image\) 	return c.imageHash.Sum64\(\)
  - 原文：llama/runner/image.go L71-L71；	hash := c.hashImage\(data\)

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
  "audit_coverage_gap": "共 10 个可读单元，完成 5 个单元的语义审计；其余未审计",
  "audited_unit_count": 5,
  "edge_count": 29,
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
  "finding_count": 8,
  "function_count": 9,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "PARTIAL",
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
    "target_sha256": "e02637ce9d586cbb131ad41df32f9af31214fb823fff0e25aecf7e7e2d78eb3b",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 94,
    "cost_cny": null,
    "measured_tokens": 468126,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "a9c94386-2d6b-463a-a74a-054c0da98816",
  "reviewed_finding_count": 6,
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
      "finished_at": "2026-09-11T07:34:56.557Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:34:56.554Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 10,
  "unresolved_calls": 29,
  "verification": "NOT_RUN",
  "vulnerability_audit": "PARTIAL",
  "warnings": []
}
```

任务错误：智能体响应再次未通过校验：存在未知或被反证的必要攻击条件，不能判为 VALIDATED；请使用 INCONCLUSIVE 或 REJECTED

## 证据产物

- aegis-report-fa67ca7d-fcf5-4f73-9003-416b043e3b96.html；ID：b6bbca85-4423-4730-b5d6-b79c54de0098；SHA-256：11df954ab0d979a75cb1a3cbe604f686f32d41b2b68a08eb9d9de1b54db179b7
- aegis-report-fa67ca7d-fcf5-4f73-9003-416b043e3b96.json；ID：9c85294b-8199-466b-9bff-b7b6357b347c；SHA-256：540bde59412fcd8acec68609d13b886fa5d30ee586392107e182c011fed67446
- agent-AUDITOR-0af59e06-bba2-4c08-b9ba-bff4a705f57c.json；ID：d0653b69-cafd-4b40-8304-03d9b91c6dc2；SHA-256：3bc576e0095c6c0882ef1f60552654582620ea5e62a8496c4080a1d2cdba5faa
- agent-AUDITOR-5118808f-c0bb-4e94-a299-2d9c6d9a914d.json；ID：88b07206-e37d-4afa-8eed-e47d05f01be0；SHA-256：d81ac2aa3bb857906209837c96998cdda855bd7296832a5ca07e89672a85914c
- agent-AUDITOR-790ef21d-c10d-4f35-a66c-39ab0c8cf2ae.json；ID：46431187-e30b-43bb-94e2-240eb9a35814；SHA-256：3472ea15b77616b372490b772f5ab752512900c2bd6f3db743e3f0ffc82fcdf1
- agent-AUDITOR-79dab6ad-0da9-4975-8f25-feb12889fb3e.json；ID：23fafcc4-3670-4c9d-a238-421c4732eaf4；SHA-256：487f3a8f14f5756ba56d017dc092448311a8b61aaeb8b2363dffee2fa1cdc7bb
- agent-AUDITOR-e79721fc-5efe-41ab-b5e6-d5dd3c008f25.json；ID：a1534952-d9e2-4a82-ad0a-efa4c5ddaf6f；SHA-256：484581daf97859f692f71e13b3e7c4599e078489500fd58013b355e998b58d1c
- agent-PLANNER-0f2c5604-1019-4e7c-9f46-bf77d3ea982a.json；ID：77322a72-c9be-4c55-a786-2352eb18c419；SHA-256：3b1509db787122e6b5d7c1c615135c66aecaeb2fa98ff6f3381b35a4e15cf781
- agent-REVIEWER-3bbe6462-23cb-43b6-9616-5257fa0a9b5c.json；ID：47c9a07a-fe2d-4791-b938-3e56d1eefa0f；SHA-256：f661ba785ac9e1f0f93ae38aa50edb84170e847526c6269fa6b24977d6514b8d
- agent-REVIEWER-45b30af9-8904-4272-961b-46ced631362d.json；ID：2ae6cc08-d768-4dac-a30c-18f5610d8c16；SHA-256：a4e937409aef19ec2c5c7bb6219901e540ec634f859177c21b3a92c10ab250a2
- agent-REVIEWER-474b9ddf-904b-4b90-90a9-ed100155356c.json；ID：fcf333d9-ee28-4cd8-b9c6-a8025c112e37；SHA-256：3bd5cd1ba6da8ae7cb49d5f624d958104fe9952111968360fb3bb295625d0146
- agent-REVIEWER-62adcb5a-fa2f-417c-b37d-371315b50a1f.json；ID：b59a211f-d1a2-47a4-8d07-5c3ab88e6515；SHA-256：44c894b031905c1158f8bd163a61425cd878b54f796760455df88f573752ab2b
- agent-REVIEWER-ba1e3c7d-f6d8-4b2d-a42a-0d0299a826e1.json；ID：150ae2d3-743f-4afa-8cc8-05add52065ed；SHA-256：0cea29f148e5cd738b5244bc0592bd94fbadb5b88b0b204eb732c9f0a14fb868
- agent-REVIEWER-f124e309-0ddb-408a-bad2-3b8c60e3a906.json；ID：52636c26-f4fd-4d2f-adb3-3cee9ec7fd92；SHA-256：ee743bfa9a65c2f654020afe115d5172dc23421608e5c753a7e7698aa5cf0864
- analysis-result.json；ID：a9c94386-2d6b-463a-a74a-054c0da98816；SHA-256：b2f140c6ed9c9f276c66613cc1d28c9cbb4b88b4fbae716e71ec0c29e5349215
- model-request-02a3d777-9d23-4981-9df7-7af8673e1bc4.json；ID：2624c91e-e910-442a-8c7f-d6ce4f057a41；SHA-256：5a72dd1b7c0d7c17744b03df3f9e8cf967fb774fa84493de969734299ac5311c
- model-request-0ceb60e1-bbc9-43bf-92a5-fe1652d721d8.json；ID：f699a753-28f4-4704-9874-b30a2db5f65b；SHA-256：93893afe62314874fac0cb1f6f54280e7f7cc895a888d121dbdf78778157d1f7
- model-request-0e516ddc-f9ae-4a57-9e47-2dfe8733adbe.json；ID：fb51e02e-36cb-4afb-b3f1-31a6e14951f2；SHA-256：366563c533c9fa3e57c5f3c7b4fa11372096f475a9fb5cac3826b7f3c5267f38
- model-request-0eb25a09-c55c-45a2-82fb-a2da6f0595f9.json；ID：c4d7d83f-313d-46b6-8c1b-9a586153a030；SHA-256：903551028110805fd9df4612dfadc7b6beb56cc566375f72c389e30b6a0200ec
- model-request-10a1f7f9-c9c0-474d-9664-73c10d59bd15.json；ID：39056da5-bf66-4f7b-b5da-feb830d7b7c9；SHA-256：6ddfbd62baa8e5f25ad35805a19b495083c4818e5b104b6f45baf17aeebb38a2
- model-request-16642317-55c4-4e41-ade6-d7b8e5d81eda.json；ID：814f4ac8-f12f-4b21-9c83-30bdac1bb707；SHA-256：d7eb96c9f6b6b0b5b0001e8652ad384b81b2a7d22453dc0f6b25ba417f12aa83
- model-request-16b2640b-e666-43cf-adaa-275580ea822b.json；ID：efe627e7-144e-4c9c-869d-6aeaf83af428；SHA-256：f4fad91b801b72bd1106a482bce7932f9f63e0a22cb1fb4124df3c220ae7f83e
- model-request-16c83a60-55cf-45e7-9265-d7eba484b087.json；ID：5feb2826-d797-4696-a50b-b4f087513b6f；SHA-256：3486d72cf66e5b41e79ddace7097f0ab7af7a7173b9b23740a6478cfdaa2fc62
- model-request-17827ac8-9d0e-463e-9676-7029b3c7415d.json；ID：9fab8559-2cf9-48f0-a327-36c5266f1fec；SHA-256：34c13cd49fc888d2081746b847fbecefdacd3024715c89d5be06c31e7f995393
- model-request-1a0afbdb-d412-4af1-bf42-d425fd5e6afd.json；ID：5a79d9a4-c247-4421-98c5-f2c330412a31；SHA-256：e79f23033074aca0728383bbc1b10e00bda49e93cf340d7b42308761070673d8
- model-request-1c72e015-9b44-4503-86a6-9cb2761769a0.json；ID：4a55450e-91bc-49e0-89cd-50d528bde8d3；SHA-256：af26d2d1ddd879ccb3d16ff85630a45e73666c95130d34c57ce3ca7dc98d689c
- model-request-1cc88424-06d5-4daf-bf50-dbb7eaf4cedc.json；ID：ec38b1aa-0fc6-4bfa-b9bb-fb3021c24dbb；SHA-256：e2a401fddfbe2bc8522eef9c92eb078448bcc958ee3f350225dbd5469ebfb428
- model-request-21495ce3-9a5e-4997-b397-859ec2e48d79.json；ID：67eafa3b-90cb-40f2-b3a4-d8df0c45cbb5；SHA-256：ed93a6030989463bfb337514a18fb1f6b46a063227756a3dc14e1990908922e3
- model-request-25b74d22-6574-4930-af01-d4af156cab3b.json；ID：ecc6c7bc-4a77-46a5-b333-0f9b561afa2b；SHA-256：ca1bd976f8eb8344f5d11d9f17fb4d2780df3ef76cb0b9a90892896718f7c198
- model-request-26843ce8-cbb2-4a7d-bb9e-06acda22b2e6.json；ID：9176be6e-59d7-4e3f-b3d1-3dcdb7c5eb17；SHA-256：8238a39ed201791a7b45b387626bf1ec421512303f3d87855cd7b4f24d2f5e9e
- model-request-26f41311-e730-4bf6-a8f1-8815ac3f6644.json；ID：66088ce7-cc3d-45c4-9f68-ff6fcd7c63b9；SHA-256：0544802ac9efa066e2e84070e3cc61cd73fd9ba33bfdd16040baa497c5a64d2a
- model-request-2f8706a8-708d-4146-a149-3d1bdaef9e29.json；ID：709b2074-8b1c-4b1d-95c8-dbf173bcddb9；SHA-256：eda51299f708ba237c72eed2aec4fda0b705cb609a34d8fff2cdef26242d6940
- model-request-2f8e97df-5c24-42b1-b75a-429bc79771ab.json；ID：1c149f39-50eb-4153-9255-9291fd08efef；SHA-256：07e36e5c20cedf48350b260002bf62fed8d69eea691cbf99dff13c37871bed75
- model-request-329b124b-3c04-40b8-ac9d-53e926e07cb1.json；ID：497d32d6-1752-4a33-95c1-3c4ea725cd62；SHA-256：ec9e43c36c294abb74d3a3217d157c4ace35dffc8d9b01e3725dcff556a68d26
- model-request-35a15001-27f0-43a6-bc05-4f1cccc9bfa2.json；ID：19e861b9-def4-4f0b-a824-b4bc4c433d17；SHA-256：e29fb695f7897d384425aaaadbc0894cf09505a4105aae6f3e9f8b045b0b3c56
- model-request-36c9ba14-72c5-49f4-95ae-cdec7de09f8f.json；ID：c6b14e41-2f0b-4def-b5bc-83d21cd99c54；SHA-256：54be1ad40785e9b5d8db3f0e68f87860e3cb1a1901a1c4a21a59d8a0df2db655
- model-request-36e2c671-c794-4b8c-8cc8-42873df6434e.json；ID：c96666dd-dd38-4de4-8f8c-f7f538250d0b；SHA-256：0759b97d2afa6e554b2a146ebc182279f89367dc04438cb265c3a231b9c1e5af
- model-request-3ace6cb2-4d30-4e79-8b42-4ac23f31f43e.json；ID：9112c878-2b9e-422f-8346-a2bf38db8e27；SHA-256：dcc5357f1976273110c8aa7587ce4174d17807e549bc55f609fb57f3063e271c
- model-request-3adf3945-b208-4065-a9cd-541f3ba6478b.json；ID：977cc5e7-e69d-4f63-8802-d12fd705fe5d；SHA-256：585fa837abde7322c1dbb631647a2d87ce1c75cfeba55c13404e21170f8b32e0
- model-request-3b0a6ce0-16e9-42d2-8908-bd81a22cf937.json；ID：101adeee-6bf6-4150-ba3b-c08eeffe5e07；SHA-256：82686f0dce317dbbad022efcbcf54a6b987a9a4e9589c58b3ac940b5a471dd4b
- model-request-3cc5b2b3-f73e-4842-aa1c-bb81f3226cbc.json；ID：0aeafcc5-c95b-466b-8736-b97246b7055b；SHA-256：f6da7560795fb2c815104db09117fd647fe98712fbced3ef1ad32bc68cd68e03
- model-request-3ebc7ad0-c508-43c2-ae5e-7b3b6d34083f.json；ID：8b623314-2fb7-4977-9eaa-e79726328250；SHA-256：93c8fc7d97001d9c764cf94ad6efc1241d5415579178b03e1999c4e9c3844635
- model-request-3f94941c-fd1a-45ef-9afd-9a73075b0c4c.json；ID：faea0009-4b72-4e91-aacb-d4a8564f3268；SHA-256：daa1b7279fc8a371c0638d4169b6bd9495b4e7ea8244ba389dac2a62b2e79082
- model-request-4098f7ee-b5a0-4f3f-ba8d-96653c55ee6d.json；ID：3f379393-732d-414a-a497-e538fbab1c7c；SHA-256：69e3b603f40194febd67154154a6f407b54b061edb603ec3d50892ce738df3b5
- model-request-430913f5-20b1-4305-bf6e-78cfaec0ab4b.json；ID：ddf72c72-5285-4a5f-8e4c-8023c16b9e38；SHA-256：73ce2154c6a0d08eff9b7b7a0749fd4e95b021a095342e8d3469736e48926750
- model-request-49fc1eac-3249-4cfe-bb89-4d317e62ce22.json；ID：cdcf1294-2077-42d6-b1fa-b3cde41a2b41；SHA-256：62a1258f3276eb385b984e0801dbe17180796543c6cfbe759c860ba6224928f1
- model-request-4b20ad68-6d42-4b5f-916e-79e2475211ae.json；ID：50536814-acc2-4c9e-9a9f-0274f230723d；SHA-256：b8d13d99e5078303e6700feb098d5be0ec6fedca3e3268e3d30fbd4c05eb54bc
- model-request-50eb8ed3-2d2c-44cc-b855-c312ee1f840a.json；ID：244c6dcc-93c3-4111-ac02-6698c5beb14e；SHA-256：a6b566bcd64c80763b17845d69f93e8941a4b4b9ee26f3c680e26534e8941e24
- model-request-51631dfa-9c5b-479e-a8ac-332312e60ce0.json；ID：7dc32fa7-61f6-454c-a7f4-bbe6ed79e671；SHA-256：638af4985295813ac7c8e1786c4025596b5bd22d6ab8f86facb5b03405bda47a
- model-request-52828d67-f00c-4fc3-89b0-57f3c5a5470f.json；ID：f092ca0a-bdc3-4d4a-884c-f834542fda49；SHA-256：b8505a456612a69ba13a5e19f2e9500e78956eb3129798954ec25038d9edb44c
- model-request-576c7cf8-591e-4c66-b788-b9295d21da47.json；ID：60071153-bf73-4730-a298-ed1b65f24088；SHA-256：ac8174953ca7c76ce9a1f3186b86b65ab384e61ec2aaa015ee5d15cc7b40aaec
- model-request-5780798b-c410-40c4-8ef5-42e5b58797b1.json；ID：9744cc74-2ec4-4530-8eef-0de8de8bdde3；SHA-256：aebbf1414599f31fef4d02e35d0f2a39ccbbeb379f4b50cb9d3425b0625d3f5a
- model-request-5858bcea-9742-4638-9528-70a2e8b0f72e.json；ID：9683db47-d617-4f5b-b5f9-25625527a69e；SHA-256：66600812faaf21ff16e87d37688aba14eabe0765805bc9ee1012f901a4513177
- model-request-5949f724-e591-4211-b5dc-5cb80413c3bc.json；ID：380b86dc-232b-48a1-99bc-5e194a81c21f；SHA-256：c23d9aecb3b589110d12dfe7a92611f85067f2410b5adf365918c661f4424b79
- model-request-5d28665f-8874-48a4-9ddc-ab67552d22c7.json；ID：6540921e-5d9b-42b9-b94a-7226f916827d；SHA-256：fa9d85bdf2c5d4c1cb1ea850bd0ea44e30620dc871c44baeb8c59febb8734432
- model-request-5e2ec5ff-4a49-4637-973d-3a1ef025cbf7.json；ID：adeef7f3-88b2-403c-9f5e-bcb1b0c2eda8；SHA-256：0c50f9e85709f43ed1a7dd239102b86f733e61427f559514d02c181eb75eb621
- model-request-6075dfc3-7179-4085-ab7c-a02e209903da.json；ID：68e05176-635e-409d-8207-402e5b712c32；SHA-256：fb007c3c3966c478b2510e05f9dd634c7902747cbede225ba349e96c70fa633e
- model-request-60922c4f-7d08-4b93-89ac-8665d784e71f.json；ID：de7ef84d-7911-48b9-9487-069f6fb28989；SHA-256：f9490072047b20b2fb0de6f5f06792a0845611bdf10c069607a41b1456766e93
- model-request-64282330-a9d5-419d-8af1-9f27114cbcce.json；ID：8875d44a-4ab3-493a-ac30-90e00ad480d0；SHA-256：f28625db36c8c0a44d5eee04d59f3e405ea50cb3e41633aa64a14fa4f44d7c4e
- model-request-66e76e18-dd83-4286-af76-039365581499.json；ID：f3d0217f-8065-415e-85e2-b11991b51386；SHA-256：3e91a8901d707e849c04ddac46322f98595d89347261a0a57c54bfc04c8ad0b5
- model-request-6cfd0f19-6a09-43c6-bc05-169a6755ed3a.json；ID：e336c0a7-72b2-411c-94c2-a9c93b44f5ce；SHA-256：bd6759ac3e96762ca75e0cd4e8147a96ab8700499d56b8fa3f43a7c55b536b5c
- model-request-6d5e8e29-51dd-4db9-9ca3-cdaaf27528f0.json；ID：84a9e959-1bbc-40c5-82e0-4efb1e0f888d；SHA-256：1ee6ae35824e11fba0355db8659939b21d2bae360b3c6332035c6347987ae781
- model-request-6f86bd8b-b526-417d-b346-30165ccfe445.json；ID：626279cd-a7a3-4967-8741-72f8243eb56c；SHA-256：f0c632b27529548633d46bafe0f48f4385515bcf9f2824bd1e610566811ba850
- model-request-7100d414-a04d-40b7-bc80-5d260343f453.json；ID：95d5f01c-8994-45f9-b22f-74e6e9595c92；SHA-256：d80b0146f8b20b8fd26ab27f1598a674f648beba8efe7eb7059119bae6719c0d
- model-request-72439b19-2621-43a8-8d1d-b295f496d2a9.json；ID：46466282-a797-4b69-8c8c-aeffc7fdd87f；SHA-256：85a012403af90fbf2245083ab4afbceea0d3eb531974d67581a8aa250e4bf981
- model-request-79d77707-4d42-4b85-9940-6f706ff1cf46.json；ID：5ab46d2a-c6a3-40e8-883b-ad19cd6d3a83；SHA-256：c52717b3a9e3525a47d6c55b33cee7a210b6c2d3b3b3810535d48ece46b303d2
- model-request-7a67262d-8025-42ff-8447-083eb3d47ef1.json；ID：9fccb61c-2fd3-4c2e-9b79-0c211a2621bb；SHA-256：c5007b29054349d05ff49622b34fdfe94285b00bd50dbbd14c2606b9ca7522ca
- model-request-7c882718-94a2-4c56-a4c6-6b84509f9658.json；ID：5b8563b4-339a-42df-9df6-99eb4282cb1f；SHA-256：6870d7016df779166c51f53575c3aba5cf914f19d0809d2d388d0a2f2069ba3d
- model-request-800ff36e-225b-499f-9ae2-760060d7e0a8.json；ID：961c03f8-1b7b-4d93-97d2-66a714607a45；SHA-256：9d9f0a872635023f80bf624c5ef0e1f7bc24f0be8aa6ee097231eb65bdb7b008
- model-request-8024cbce-0a2e-4693-9e41-75b3b148e61c.json；ID：71bf83bc-d0fc-4331-8b96-c0232e649c24；SHA-256：95ac680da15e5fd98cfc012549c9381918d8cce005bc6cd372fc37d4acb6f123
- model-request-8283a53a-8ba6-4215-8cc2-b5ac7d914dfd.json；ID：545d3ff6-9434-4b5a-94cf-6c3d4efdcbe4；SHA-256：d6fe646414f007b61904d60a208d72bfaceac20aa1dc04820a6d37c7b01425d4
- model-request-83999274-dafa-4e10-9ce3-466ede9e98a9.json；ID：404b5178-4b3e-4f40-9eaf-64c24a12a307；SHA-256：8b52a994af6c83f4fd85f853da8c767b6cbead170e10f98ccc755d299dd60ed7
- model-request-87fdd2e2-d8cb-4555-897f-c0a1c301d3bc.json；ID：d31650de-ff07-4f2a-b0c3-ef3b7847d921；SHA-256：fb3d9a149c333d6648f50552ac6455a6b0cd48ae8e4930c610b71f270ebd4c26
- model-request-88623e4d-f34d-45f2-b01c-e433420123be.json；ID：95108f86-4159-4adc-ab7b-83e93154edbc；SHA-256：cb58a93e9a0828cd8d9e7d2e586fe1fb18a94f5b9063f80ac8c01e90e91cd710
- model-request-8deb60fb-08de-4c2d-803e-73b915f82570.json；ID：f31acbc9-f2f7-439f-9152-e122f32a5b02；SHA-256：40fc88dcb582f51f84cb1fa68778152aa4b79bb361f40f4474f4c4419b6e6058
- model-request-9034ab7e-cb75-42e3-bfdb-6cd5cc424979.json；ID：36b42574-f3ec-4d48-aa95-ad9e61e1be27；SHA-256：e91686f2f1787fa432241ee5c4995fbd0e8e3b4117b1683987e338e9ec601fcf
- model-request-91a07947-e1a4-4f2a-8938-33715b48f9c9.json；ID：958708a3-70c7-490e-a553-bd5b44bb04e8；SHA-256：b0ae893abbf7e26fde5b009c5cee803dfaf79e7405608064e5d59d277634988a
- model-request-91d63157-5d97-49ef-a97a-7131ce07f48b.json；ID：d61cf0f8-8dca-4deb-b04a-0e085e19be3f；SHA-256：9985016d44038d64d38b3cd40b44d57fbf658608a8234a3d5e63f3db4f36cc14
- model-request-9901a96f-a952-4420-adb9-5fc425d3dffb.json；ID：474c7ac3-ab07-4651-bae4-f5bcffedfc16；SHA-256：7cd25ee1d8cd46cd005f64ea70869a864354aec0588333339653c2071dbd6060
- model-request-9bec4213-623d-47f8-ad55-79bdd000c70a.json；ID：9c064526-5d6d-415a-8da5-f47ac7403e3b；SHA-256：57b88205cbeffcd39f9b23bc63fd9bf6b3c40487161340f36f733a0edb8fa9c1
- model-request-9e5e81f3-5405-4d54-b9f6-3e655b40c3bf.json；ID：6a749d1b-c101-4ca6-9709-f6d30794bbe7；SHA-256：6385391a7dc178e7786c80a479d5e809bf1fdad66f3b39d64c75fbb9b34f52d8
- model-request-a04185ca-7f6d-40b0-a5e5-4c0dd19cc1fc.json；ID：e416a1cc-e36f-42ff-9d4a-85cccb573631；SHA-256：9880c19aea379bc24154c972dc1cb0803e0cf5c6a2d36e1f11836f48e11efe95
- model-request-a8d66fa5-ffbb-4d3a-b211-8b0b55f5f510.json；ID：068c46a9-2478-4941-87f1-b4331d8e7e92；SHA-256：977505922e771783deb60e1368595ceaed21f24364b7e4934cd6f3257ddf0ee5
- model-request-aa576f9c-4e15-4094-9782-58b97b17235a.json；ID：3da70a0b-5fa7-4234-9b2f-c4540f819d27；SHA-256：0a056581847b0257658697786e749b3d4c2be19722f3b6bc4ba5f30a23aa97d8
- model-request-aa804327-65e7-4220-a338-ad6535fcfe6e.json；ID：c8a10046-20b0-4abb-b010-b3143d0c19cc；SHA-256：a3b8313f9eceaff7b64d66f1dda7efc56deece37f3a21ea5159989ab6642066e
- model-request-aaf23687-a9ad-425c-b498-3e4838ef67ec.json；ID：2add8e62-c864-47ee-89fe-78b14eabc6ca；SHA-256：1af344f20eb472bc42fd2eb90658ef16d770e62f8cf77601b15c8910fe1bbd18
- model-request-ad63bc66-8ef9-4356-bfc7-c6d5176b0262.json；ID：17e1ac1a-bfd0-45b7-8c9b-af15b8b324ca；SHA-256：95bd7edcba859967d71c2409c8b0e8f507d09d40f5a53cdaff37368ddd61b16c
- model-request-add94ed2-c36b-43b7-866d-f8f511231234.json；ID：5a083d2f-8cac-4aab-ab2b-b90cfc8cb645；SHA-256：d46c32fe8f3f27088838d31cfe7d8a07aa0c36bd04ddfd123eca96a387aae6b9
- model-request-afa62dec-71a7-42bd-806c-0806a3839057.json；ID：bd146bfd-bc44-4d82-825d-8519f89fd362；SHA-256：69b8c79c99c13c4cca43f8061ee70385cf406d84ca6fce3e2fcbc94cd212d92e
- model-request-b124b62a-74ea-4ba9-97af-49dac8ac7cc5.json；ID：d0b0ee02-951b-4c62-be0a-0fa0990e652e；SHA-256：8056054938b490519601c729121500cd540e0d6de56abf5ac19330e876c9c3e1
- model-request-b6b4baa3-21ab-4ca2-b29b-063192c9fd3f.json；ID：9a216edd-8b68-4421-b13f-bb66f9a85e14；SHA-256：9886bd788c042c1ca978c7bebedf5e83e934cf88c8c29b3db2e2054f6d056543
- model-request-b7517126-0036-4db0-af05-893f1231930f.json；ID：d0345a84-f75c-48be-9108-44cc298990d7；SHA-256：24057a2741ddf8b81cb10be4ebbac842d397916cc108b2bfd16bf5147a4eda8b
- model-request-c0f60af0-1368-4b32-9559-7dffc6345d56.json；ID：e21a4b09-a2ef-4c74-b8a9-784345d515b4；SHA-256：8ba534db4fd82faf6ab5a183001e566db9f787cd902154da652c04f043a8d575
- model-request-c864d478-9c7d-4452-89a1-68b22129b191.json；ID：75c2ebfe-fa9b-422c-869e-95e19c35656d；SHA-256：1c5b1f8912e7eeeddbc739a5d7a3f24d748abd297ae977a0350f3283d0380e9a
- model-request-cf350158-4957-4c2b-9e25-8c9c2ae4283c.json；ID：8d2fdf16-92d6-49c2-a1c6-7fdbd33ba354；SHA-256：e95aad97def8c3f21b9aaaed59de9cda3964a91233114c1d4df5f8398c13d25e
- model-request-d01f2d66-0eb0-4688-90e3-d135786ef1e1.json；ID：2ed583a5-2923-4885-a4f6-677aec10ed0d；SHA-256：42a6841fa2579a28e063150d490fd555716538f13f84199c8a0122d7e6b7c643
- model-request-d11c4cb4-3087-4183-806a-9b757db8e1a4.json；ID：3caf6ffb-feee-46d3-8308-a10d0b5a95c6；SHA-256：e291390abd9996c850aabfbeea0b2caf4d7df0f039dc1831dd620fea1796dc27
- model-request-d2e82c2a-a3c4-4da7-bcbf-da1e734ca1c5.json；ID：85c6eb61-bf2f-4ec9-a0b8-c059aebcaa4c；SHA-256：101a3a9a4c9828338f0e93e44780ce5a41aa2280973c15c7ea7d86c5987c7ad1
- model-request-d871f85a-a5bb-4590-b690-dca46bb26934.json；ID：23e40685-1050-49b1-8048-386aa2df1f09；SHA-256：0b4f7c000f9f5a793192b06b3cd3e39ff84481693be3da8cccdc474637b36241
- model-request-d8af42fa-ba05-435d-97b8-ca46774ddd82.json；ID：f39abd59-e1da-41a6-9751-c692ae8c14ca；SHA-256：ee51184f136bd96a0449947b48cc21ab9f2cb1815f4f04e632ea665b3858cebc
- model-request-dcb52a11-f08a-46f8-b7d7-a520c83be73b.json；ID：2f274a81-6fb3-4002-a4ee-1907e8f03e8c；SHA-256：45783b5ba4da06cc0419bef9be0e36ea975a336bb5550c3e2f9d2a4903877277
- model-request-de208a62-8c6a-4753-a602-54684bb67c23.json；ID：c072e989-41c6-466b-ab2e-a9099ba67ce1；SHA-256：967f19ae4a8573dbba5810ab3e686865920a272a26888bd7e93d8451195e673a
- model-request-e0d7625a-86e3-478f-8710-132bdb25eef2.json；ID：cb1760c2-3536-42fe-aff3-eb6fd2a06736；SHA-256：4595d5dadfee123e328b469b85177810b0a859ac4c3c6805da187ebc928b345b
- model-request-ec53d221-d908-4456-9276-92d3b22d75ea.json；ID：9f3bf05a-8be9-4f8d-bf7c-37713ab8921d；SHA-256：b982435070ed819877f4f9c692697fa52743b27a6d6db41985b3afd9ab24b0b0
- model-request-ef6543f0-64e4-4f37-ac7d-6e3bfff6e519.json；ID：342dcb0f-3834-4668-b756-8a1909dd9e0b；SHA-256：cef30d261a5042e5a565a67be390c75d4b550a45a1ee8163051487b9ce2a98de
- model-request-f629cab0-131e-404f-b892-f9ea0f31348e.json；ID：856200aa-1471-4f27-b7c7-2c4cd7ed31ca；SHA-256：7f102832b1efbaac0b78c3beebedeedba8b3e31b71e817a4a7a60aec913f7913
- model-request-f9ab1744-346c-48ab-ac39-35e0a47185fd.json；ID：d9be009a-101d-4c40-9fc0-4b35a1ba7089；SHA-256：4d7a1d905f2f4a45e66c0e44d107a3b66fed0df03b5ecab21c07a476b99118d3
- model-request-fc0ccd88-55b2-448d-b95f-a100373eab19.json；ID：2fa3ca20-b4e0-4bfa-aacc-61600366dd2c；SHA-256：acd17eba1e11202d3800a5768ee6d8fbd7bf846bdd010af8862421d11ff25877
- model-request-fe23a130-0b63-4e34-9b09-a64a6398ad1a.json；ID：96c7aba3-3e13-4c3b-bd16-d9d74bfbfba5；SHA-256：d36138cc9f3553e352d3a880e8b9b4ebe12cf1ca47b762d8a53dd3ff9a1a47dd
- model-response-0123acb6-aae3-4326-bfab-5d5acb13bd88.json；ID：baf8f0ff-424a-4968-b0bd-98f4fd8245a2；SHA-256：024eb4ea0c92b4cda716928c83664763969a97a51bb05ef19b507c40ea198861
- model-response-042eadfc-9d7c-40dc-bf50-acac6adf29d0.json；ID：03856138-9180-43fb-bb65-67a7ac2eb933；SHA-256：21ad36070171872eaef0a7bacb416b3f63736c9e48f6c5b6d980024653a42ad6
- model-response-064916f8-5924-4dec-91f9-003d37978af7.json；ID：b0fc244a-4a7e-4eee-a3e9-c648c26eda68；SHA-256：984d12cb1d91aa053917b334abc9a934266e8cceda90ed515f2dd5f2a5458baf
- model-response-06c246cd-7a38-4a75-9587-49d78528efb9.json；ID：8b8e7129-f850-4924-903f-90832547fa02；SHA-256：2d7f4f67f4f83e5b00180d5bd5035db34a3ad7df01b7cc470725d166bb5ffcc8
- model-response-0988a4de-0db3-4d11-8e0e-317850d10bc8.json；ID：5acdb28f-d7b1-4342-86b9-7d7fa2b8e41e；SHA-256：14e28a3c76ec0b785f6ad775a436c25ee6900b351da5978397be4ae6e5b949e4
- model-response-0c9f835a-5420-4cdf-b0c1-32d02e73534d.json；ID：2b375c63-0aca-46f3-ba36-ec25268002a1；SHA-256：e8332636fc779a731dae781ec524f97e905ad47aab6177262dfea53f7cd9c16e
- model-response-0d27f95e-fb1c-44a9-b58a-1e6494be89ac.json；ID：88004622-2d97-478c-9b72-925d486b86c3；SHA-256：605a10347bbeea3c2e496fc309e5f9171d5f2dc314cc8d5bfff348fdec5bb335
- model-response-0f3aff6a-9ced-4f8a-864a-5f866b0b773b.json；ID：ad9dce15-2134-46d3-8b8d-722866f44500；SHA-256：ba551b14121043ad33e2af909026f12864ad3fe02a41ee1cac072340e9c45bf5
- model-response-1316c2aa-6d09-432f-b2f3-7a0f2709e11c.json；ID：092bacf9-f4ad-4381-b36c-17b1f3d504a0；SHA-256：7457970e44d26c462ba2fde9d3c2ace9a1653b3717ede198f07a5fd6b9c692b5
- model-response-1342fd80-f19a-45f5-9f2c-470413191775.json；ID：117ffbd0-55da-4cf2-b3e1-7c8708a97b00；SHA-256：8a1dfa9a7a202c7759d7f6934b6d42f739a8021a48a549211abfb97916980fbd
- model-response-14dd60dd-c215-4dd6-aff0-a6d5d4ff8012.json；ID：0fe92d2a-4af8-42bf-97f0-a6c010f5c5c0；SHA-256：b78fb44e653f10feb7c2d3b89430f2ff67b26c895d376b425fb127f72e9cff68
- model-response-16a34cba-c448-49bf-b825-0187045911cc.json；ID：f0ae0c17-7aa1-4b5a-8a18-6191276d8999；SHA-256：a5ece6ceb0d1df80a9d202b55f5769bc8f205590b3cc4c6f8d66af18567f9c18
- model-response-1717cea3-2754-46e2-9de7-7b1993c472d9.json；ID：692d2e77-999b-4bc7-bb37-bf0f821915b2；SHA-256：c669c789a33708f7544d546a654f23d8cbb103628956cf1dc6278c72065541b9
- model-response-1bbdeb8c-437f-404b-a634-fa294e1af28b.json；ID：2f59dc3d-cbfc-47e1-9919-7f3efdc8eb4a；SHA-256：b55c01b034b10bf52a725afa6bd0bece94302d4ff49ee28175af125707725da3
- model-response-1f6f6dbd-8c40-4192-92b5-05adb2c6af47.json；ID：35c01272-674b-4d30-92a6-9deeb8d19cc1；SHA-256：0eec3e99d4115f336c3eb75ce8681ba597968ce22e46512250e6659282b70727
- model-response-2106346a-befa-46ef-b423-0a052a888e84.json；ID：9bc88995-32ba-471a-b542-69d5fb407781；SHA-256：4653759bd75be8f8470fcb391440b155dd9605a177c559e5c9506bdc1dded4f7
- model-response-21a55d37-b42e-4f6c-962b-a72ada6bd8f6.json；ID：8af2d61b-58ed-4636-850f-a8cfe6f52f58；SHA-256：1404a377480da2c7573d3243d4a6cd54af2643cb74ce57c8a87e7f50d65cf1c5
- model-response-23e53670-f8ef-492d-828b-095260ee2607.json；ID：5133f825-d803-44f0-8806-01a59ac3165b；SHA-256：239e3e30ee02cfdd1e9149faa89bcbe0c4aab327bb9dd9592cb8a30ae30e535f
- model-response-266c49f6-ec7d-436e-a5fa-ed102b576afd.json；ID：df57f1b3-4507-4c8b-b77a-c606c7d758a1；SHA-256：953c16a28636ee47f2a2a2e199e58094ee291d56c32fc1e54d4cd1aec2f109ca
- model-response-2ef61a20-656e-406c-bb7c-7e9a53be7275.json；ID：51af47f3-7426-4ab5-b1ad-4988da318446；SHA-256：15fcc2b33ad2f1c733f40793db2cc7a9fefd018706db4a6f9bb73a1a7a3e9a97
- model-response-307699df-75f7-4980-ada5-80e25e0e4326.json；ID：43c391e2-13d9-433d-aa44-25a1c6c2349e；SHA-256：faa732bee885adb4c02cf3420ac93bf01606fbd50fe347a55579f394f73c7bfa
- model-response-3295b924-0945-4ae4-af26-250ec7236698.json；ID：0b0e2988-9384-415d-829d-8c9550bb85d3；SHA-256：442a6b84bf2e30224c27ebda1c6d71b46a49f6bd0ec453500f35779872b45807
- model-response-3772c94a-7054-45ef-8879-0178f6c64f32.json；ID：ab1af46d-b76c-4477-89aa-a284f8f7c0b2；SHA-256：80b8bd038309ea5f28e4893a036e06b8aae0c25118bd4ea1af22c3b65e78c3b6
- model-response-37f1cd9e-cf20-4641-aa5c-ab217e26d2a1.json；ID：c91164cf-fa8c-4f29-a0d3-577815e2ed31；SHA-256：a6a40d317cc7994966ea29bd87d6f617ad34f92956ee5da3afe634bc61a629bd
- model-response-3acadf01-13ed-4642-b4a8-28ec1f0d1e69.json；ID：691e9f22-1a4e-4aaa-823c-88437a876d02；SHA-256：10bcb9971e3656e58eedc8475963902cbf7cc8d73346f2a4f4b419996288740a
- model-response-3c8d5b7b-3367-4f94-9204-0a12e8fef6eb.json；ID：655dfd77-e3e1-4edc-8024-f838ad7df551；SHA-256：8d2370994e96940dc02eac2e4375ca66747591893a1fcbd4bbf9241691a129f4
- model-response-3e5c977f-6792-40de-8389-98c66fe6f4a9.json；ID：22b0c4a6-d00c-413c-88a1-4ab7c847f0a8；SHA-256：a007cd0639fd4789fa29f1d64a1b41bb5484a73c9b3a2b58bcfa00d38bc784f5
- model-response-41f55ddd-31f9-455d-87ba-0b05e063398b.json；ID：c0c3e4c5-af02-47d7-b6fe-347a6608a898；SHA-256：ab665afa7902576a688d0b0730a5435fa53a0badc6e4d8297510a954a08ac9ec
- model-response-451ad775-df18-43ee-aa33-88f0ba0dc77a.json；ID：1479d8dc-4faa-42c7-8714-fb55c184ce12；SHA-256：b5b93f445d32b995e28c20dd7ffce1908a944d7c027d722abdade752cd803380
- model-response-45ccc7c8-5dae-4f89-99e5-4777b6edc350.json；ID：b5d8ab1d-1bc9-4f22-b0a3-b5bf2e5da0c3；SHA-256：db7fc4d936f2ccf0dc6f1a679115bb036df0c2fc91f59491fd3740719cb0804f
- model-response-4d963d79-00f6-462d-820c-5e1e447227bf.json；ID：0b722123-8692-4344-8bfd-c69cc78d5e2e；SHA-256：728623083247c6629bbe888d28d57b8cfcd2206f712fcdeb3e7bdd8c4a864fd1
- model-response-4ed34a4a-307d-447a-8bc5-578ecdf1c148.json；ID：95f929d7-2bed-4602-af5f-f9420fb8d2d9；SHA-256：8a3e2ed9f6c797a749931e68d3fd808e2ed16e2fb9a6eb1c0d6e55f5f3f90b2f
- model-response-53057ed7-3b2e-4058-8ae4-0fcd5561fb79.json；ID：4c5a7e64-0230-4b43-8dc8-2f46bc66275e；SHA-256：5b843789675fde0058fc1a72aba4cc790b6403f565810a8fc0ee36a8669e0d29
- model-response-53830573-13dd-432b-a3f2-1c4a7aa61b85.json；ID：737f2d21-12f7-4174-a9a1-40666f67d3ac；SHA-256：d650d9a53d8a1ed67d1ea020f91bbbceb17be3a9aeaae4e0acd52d9351ac705c
- model-response-53c0b833-1695-44d7-8ead-c205ba0005c5.json；ID：22f71822-beb7-4763-97d6-df6af23a68a0；SHA-256：a930bb0e9edf671019f6f4fafe8933a48f397c60e5943f088b489b72483afd39
- model-response-53ccdf86-fe1c-402c-b786-76e9fa5f0b66.json；ID：f2e6aeb7-3b35-4f40-859c-19c7b33e8436；SHA-256：ef139ee6e448c450321313e7661bfe0304b58e8b737a2bbba0960f902d80be9c
- model-response-5517beb7-0782-4b96-809b-d9ba64683a36.json；ID：7cadc934-5999-4833-ae87-301f8b7e0396；SHA-256：bcd92bf981297b5486238b3851aefba1bd849bc2afd6d300e9fb17a4f1266c0c
- model-response-5648b8dc-0c7d-4906-a75b-02ae30d3c71b.json；ID：8bb1133f-6087-4ac2-83b3-a65e569dc727；SHA-256：b7783ef1916051bbc9be4aa5d56bbbf67d704142f81e47c35d227a6df0c20a69
- model-response-58727f7c-a973-49e9-9f37-658bc8a9a83d.json；ID：fd8b2052-f553-4afa-9cb6-9015ea8effb8；SHA-256：0a355cdb9d3d7b0ce2120ba7b9e25b1326595c908409f3cacd9818e7542c9b4c
- model-response-5f03c0f7-5623-4034-9dcd-deeafd8ae233.json；ID：c9694ca9-d22f-4891-96c6-88d51451c269；SHA-256：8a0f679ec9caf44fc631888e8c628071832dbb0893dc9414da25b0cc17989e9a
- model-response-618518bd-2d07-44b5-8f63-b3580b7a1cec.json；ID：6b72c039-e6b2-4805-bd59-ada43bc4be72；SHA-256：eb8e2382106ef11b076771c5ee40240d5fc93142e1a6286b8bcf69bd58ad38ed
- model-response-69d4adff-ce86-4533-b1bf-43ccd7f83162.json；ID：3d7764b3-40c1-4814-ab56-c34a7bf4d597；SHA-256：2900381a55798ec39c188a6b7856c8b7deebef0bfe67b83b165a0ad5e3edba1b
- model-response-6dc2fe55-343e-49de-99b2-581e6fafee03.json；ID：fdd1f28a-cbc7-410a-b7d0-ffb64fec083c；SHA-256：25dcbeea7a83828b520343b8c104546dfdcc5a29fb0c22d49b17cb0678ceb262
- model-response-70f3f26e-f9e8-4183-be97-6c0079df5cad.json；ID：b79f3008-9630-430f-941d-05fca1a12574；SHA-256：9f602e01a2fe2e0e2734dd1f1f12891628852133bcd0cbb4f1b24b6d539793f7
- model-response-71030982-f90d-4994-b246-6d41ae266ca3.json；ID：5141cd9f-4b3e-4f95-b6cd-100591536d35；SHA-256：050b2c6b86e1edde9a42a87ae8c2a7e422500ed0347607cc2c760916dcc7731b
- model-response-72fb88d2-5cdc-488b-a779-de2cf49b7079.json；ID：5f513693-4678-4496-8760-87f0accb559f；SHA-256：1598f45aad71094fe47a71cb9f659e6fff10ec1afad4b0699684fbaf5f3b60b6
- model-response-78b79bb2-778c-4dd8-a684-cb8492a7ffc5.json；ID：16cf49bb-b054-4312-96f3-5a89689165eb；SHA-256：c682e6c2d9c7501da8448ec684c714bd932235947d67556d50d5541cb35e0d65
- model-response-7963f1e3-9c8c-4989-b35e-41ba6939553a.json；ID：3e6bd789-ca92-4d8d-abf2-b09aa7bbcf23；SHA-256：dce5601a39f64bcdfabdb2401d466246580c7300a3e77fcf9c6eb7eb3be1f39b
- model-response-7bf09013-ab47-4a16-a78d-f7f3d1432a85.json；ID：28497496-8bc6-469c-a398-1377b22805bc；SHA-256：a5216f6df3dab9a35eb7b4d9b4a9405c5bdbb16bef99df9b4a9c0eca22ad0727
- model-response-825a7bb0-9387-44dd-9d6c-f0ea9a884336.json；ID：1fce6095-09c9-4717-a91e-8ad27f50d991；SHA-256：ad9acd615b1c2d7cf73d381c4073b48bc53d7aac7e3186667305821e503bdc7a
- model-response-8446c655-b509-49a0-94b7-dade041050f5.json；ID：3218d6d2-2d16-4c7c-96ea-f7cef4f1577e；SHA-256：3c6d4a484e0df0ee1433b55e8f857836bcc85ca9da8306e876eaa07e984f0370
- model-response-8575b64f-602b-49bb-a952-12e74b72782e.json；ID：48cbf3d9-b235-4a35-ad07-fe19340ff39f；SHA-256：0539b2c616d93768fcb66186772889f298f075d18e2772820018faaecfdd5d52
- model-response-884ff235-87f5-4d6a-bf65-248ef97a8de0.json；ID：974d2bc6-c2b5-4d1e-8b76-0496ea6ae074；SHA-256：ab3eb767e5b39e0bd8a00032d128e442a482d4e7a03e21d4ccb595aa6a510287
- model-response-8b651921-6483-486f-98ca-de2426509ad8.json；ID：e4b38746-0185-435a-a1f0-7c61d0f361d4；SHA-256：23b03bed56ed648b31324f9ec334052a1457d7b518da669e93e33b2f9f28ba69
- model-response-8d33dad6-ad5c-472d-984a-db621c279974.json；ID：0bfb4265-1e32-4695-ae8b-16604a3cd834；SHA-256：9172156d31ed79d217c0a72d03905a43025a26f3a2be2202872764e08cb19ede
- model-response-8eb55a2b-a1e2-4b26-aa78-1e5c69a870ea.json；ID：b04f28b4-7340-45c0-b665-c0c3d9c71536；SHA-256：119c278ac7a6f24bce75a13e01a0861c5f7ad9db7ac94aac1cc29df0aa9ff344
- model-response-90cb9e25-b998-438d-bfd9-07ad527fcfd0.json；ID：e6a4e02f-2a06-44df-a335-20fb2653f33f；SHA-256：4f3a6fce23e8956a4b7e3374b7d1f62ebc05afed7744f9fd47d96159733fc835
- model-response-957fb580-591f-4797-8341-03efd48f6a06.json；ID：d1797a2b-062c-4b01-96b3-8bc1d199caf0；SHA-256：fbe6100e03ce3f9bd1d2ae8b9f32b56d7c563003e3d00a32496fc7a94d82078b
- model-response-96485b59-1f15-4bda-94ed-ff411a01aad0.json；ID：357cf34c-f70b-4a80-a533-0addcaee4619；SHA-256：7c7aaaa0bd8bedeeaf6bee36ae288a860608474cf606c2040ba92f8c3734a489
- model-response-975a29fe-1b4a-4935-b5e7-e241834d8ff8.json；ID：8246a3f3-f2a8-4c3f-a80e-3d00f283e549；SHA-256：7d36b934784a5ebf0b5f44d1b732b452e5533e6ffe4439d8951a0acea2fe89f0
- model-response-9ff6db99-f1b8-4802-b11e-445fc5c28400.json；ID：b94b44f9-8bf8-46d2-83ff-ff9e8e7b95c7；SHA-256：cb397115de5d96a851adf0d629988d834d4243cdcd286198cabb95ac1dd24fd9
- model-response-a0b109a0-bc70-4c76-a7b5-430adb01fe6a.json；ID：5e4d6993-6ae9-404a-bad9-2d67a8d24370；SHA-256：070d23938e7f5491429c2dae75947039c578e9471e29dedd1d0f6ff3d1dcadba
- model-response-a2e464f2-74c0-4f46-bd2f-3da8bab38ce8.json；ID：844d6f38-8afd-4245-baa3-7eea3208414e；SHA-256：60bd2006daf16494851dfa65ce7cb1b036e9be319127ebc5c339c242e87df7e2
- model-response-a54bb91b-aa4f-4d96-a6b6-da0b1727e9d1.json；ID：bcfc5f18-b3e2-4d3d-8e2d-e119dc487e1f；SHA-256：2c56871d6d701758ca0b292c61ad094445ade0926c2d76257b8461b36823bb51
- model-response-a79dba35-1789-4012-bc26-f54e47782846.json；ID：f898e3a6-99d7-4a86-9681-16177134d104；SHA-256：48252c22ebe719972a90696b2671da56e326812f013a696064c0b18be7ff6c33
- model-response-aa2120ae-2a52-4e0d-a1be-97cbde87b9c5.json；ID：a3273a2a-ad72-4235-bb13-bcc667f5376b；SHA-256：4c562c43078fa545158178da2956ddee457a835e7c6b9ffcad4d0e07aa94f581
- model-response-b1c3614a-c635-4029-a8cf-7b7e28452e01.json；ID：f06d1d42-274f-4a77-939e-f758ad6eddca；SHA-256：b3302860265642f26a7b93c67422e659100a5553f43accff5267327e2d4028f9
- model-response-b5afe464-c64c-4458-8beb-bf617eb16497.json；ID：a021c0c0-de78-4d94-b6fd-0924d0f240cd；SHA-256：f1e2ee4c8ec06a847cbd9ee14423ed5b57646dad3aa997e1afa92202e28396c0
- model-response-baa41aae-20bc-4bfd-b6d5-30c5b50f1db1.json；ID：9fde27d3-2895-4c74-b5b2-3f13309a649a；SHA-256：6e39e5fbc8245a6f4ef3b2a48c0b2e4bcda71bbeefa49e2e098dbf99865062d1
- model-response-bb03f851-607f-4ff1-8c80-d33f66a26322.json；ID：3e8e4a20-a34f-4ddb-8fc4-d2cb03fdeb55；SHA-256：680c9ce37c31caa169a1c9ecb5b749ba4e09e5824ec2266ca0e5a3ebf403dddd
- model-response-bb4b931e-dc16-412e-97ed-2fac63b596c0.json；ID：7981eed0-f302-4866-9821-5283bb03458b；SHA-256：2427148339351317c700d41a0f49c99707c9ebbb7dd3e84f01abbf61c8a4ccb9
- model-response-bd4b5fea-474e-4606-a097-134fac862454.json；ID：c9006d19-2ea9-429f-8df2-8f982a1e5eaf；SHA-256：5b33e1dc62df58ccd9f495d6da7b1edae58e16c62f31f93e570bd4c37924e6ab
- model-response-c1a498cf-b119-482f-a553-dd756d9cd83b.json；ID：0d8b1791-41e4-4f84-8dcf-6ff576cba9cb；SHA-256：c935de68b8dbcd72e03b3e702095e328ff6b661a32b3a7de10878a7f153a47d7
- model-response-c3787813-a09e-4dc2-ac76-0eef867a2842.json；ID：6cc176cd-c0a1-4843-9c7a-e585c6280c39；SHA-256：5ad497537fc8f6af263484532916811f89fab18da88b2f4e3e3c342519a3398d
- model-response-c59c0840-c8f4-4c1b-ba48-759caaf05618.json；ID：7eb15470-e861-4d08-ae00-5bbcfdca7c23；SHA-256：7d42aa8d2ed0489486e63d011f36c5219e10f172a2907500bea69e284261d60c
- model-response-c6b00fd1-0e21-4372-a061-a89c20795063.json；ID：c4c5ebe2-9e2e-4eaf-a436-42f9b7642c22；SHA-256：647ca4dccfa7735847010c568dc99fc4e5541ea00f65e7178c0ce9ccca3001af
- model-response-ca01a7e7-1ceb-4c6c-a407-ca63420db124.json；ID：fcc98330-6397-449a-9932-2529f3f4f24b；SHA-256：b0c6ae4c5a3247a457146a7dd5d9988be8405f2eb1f8b56fb3e4ffeb53a55a0b
- model-response-cb3d5d9b-93f3-4954-8644-448493f3d27e.json；ID：2b7d7956-2441-46c0-a098-38532c8d35d0；SHA-256：503a38e5e5db13ba26995825308f3cced33a962e6d665d7d6d8390862490663e
- model-response-cef96d00-2934-4aa5-91b1-698e16ad7167.json；ID：6f3da921-e9f8-4c90-be95-aff0f514da64；SHA-256：3a4ee72476cd0813e0deae45715183fa638263c3c6c1cd984ce8b2c602408526
- model-response-d0927641-534f-48d1-8fa9-daf689dad4cc.json；ID：98246cf7-11b2-4dbc-8c20-5ecc68fedb1f；SHA-256：d72d9fcf60d13292ffb24c2d70ae8a0c67891acac1c2a48639278b811c70007b
- model-response-d719814b-ef5b-4eca-9b27-df4feea0e50c.json；ID：617d1847-6546-4f36-a113-e6645777b71f；SHA-256：01d2924fd77cfd66e80baad7f58bf101806d5ca7f7c6054b70a51c3844fe9c02
- model-response-d73a131b-0356-4356-a5cd-f03f1c7769ec.json；ID：79464266-e50a-4e05-9349-ea3590ca7f0c；SHA-256：d585b5489a0f1d1311fbe48e33f04677edf57e0816aea839e3254b46ab7a5998
- model-response-ddc60afa-bbda-47b4-a743-2a029244da05.json；ID：137b10f6-97cc-48c7-bdee-4f32534cbaca；SHA-256：1824f22564f3c141321feaeb1ba134b6be24dfd1cf56d5912e43ad58b801d6d1
- model-response-df1fe0d3-b0d6-4830-aeb7-9822e62fb47f.json；ID：d95b085f-07a6-4d4e-9c71-3360a37dc162；SHA-256：223c6664a605b86417f729d76db006b0f69fa22f20c34fde70704b99cee78867
- model-response-e04645b3-6805-4945-b564-232f1a733c48.json；ID：1de901c0-22e1-4a3d-aab9-f7520ad2d31d；SHA-256：86e55bf31f82176788d185d52405f5f40879cb374bb5c2ea6a7f3578edf3fe63
- model-response-e56bd287-ae7d-4e7b-a1dd-25533a4d6e5d.json；ID：8fa9d2b8-71d9-4b96-86ef-26066bf9cf45；SHA-256：30c3f3f505492849de7b9761fcbedc97658e9d3c8397f32229e00bb3100bddfd
- model-response-ea3f1b02-f8b5-4a6b-b53d-1bb856616c9a.json；ID：47b0132f-8d21-4216-88c1-94a0b679c90e；SHA-256：bf1e08a7f02197a675bbd82399fdee4fbd510efe40fac45d6b84ba4ebf9628ea
- model-response-ecd463a7-8209-4473-a08f-a510e20d1e0a.json；ID：86f29896-feda-4dd8-a023-3e686bf62eae；SHA-256：317864638997cb690619b947be5aa0eaa52b891e3bb1f83103cdb17240226c9a
- model-response-f1edbfa6-0e04-418a-a022-ac778bdfbad0.json；ID：72e20963-8819-467e-a76f-5f14782b95ef；SHA-256：79d803fc574feed622bed7583cc001ddfc6a160a35782005bb5104fd3d550e56
- model-response-f3b15633-7516-46f9-bd32-be6ccfe0f391.json；ID：cd2a6764-94cf-488d-b924-7447579daf39；SHA-256：8c20261f3ba680401eb786f8bc8ff6a7446680ab8732ea8b9853e870e5ad1008
- model-response-f66700e2-2014-407b-b5cb-ba438ab6676b.json；ID：2589c5b6-eeb3-4ede-a7d0-3c6b80b0c643；SHA-256：9ce3f69ed16ef1b8080637eb8b1c6ab405939646ff7ab40c1fa83f3832d79404
- model-response-f7a6c848-459e-4512-b16c-599f0205965b.json；ID：af7548c4-d774-4a97-ba74-feb404233dd5；SHA-256：d29faf9cac5d90668471fe333e75a165fd10c40fadeee4d32b6256ccd0b6b020
- model-response-f91324e6-331e-47b5-abfa-270ffea80882.json；ID：c23fe4b5-0cd2-4e22-a004-7ed7e23b8ba1；SHA-256：bf8280265f1e683b3c6177ad7ffeaa45f71ddd6a1b31138485cd601414babd6e
- model-response-ffd84813-5e6b-4516-b550-66f1818c30e5.json；ID：0b5c5a50-5ab4-4f10-88cc-0e854dac345a；SHA-256：e28b270e6bf2f31ba5615cd36b2458740e35fa0730b514ff202f9b00f98cd1af
- p09-ollama-zerolen-vuln.zip；ID：2a69eb84-5c21-4016-9e2a-016e592742df；SHA-256：b3d50f5958f4727a6ed599a06ef54f99cd8f02a900a00c6e5be8efd478059724
- snapshot-manifest.json；ID：8712ecfd-62ba-4565-92f1-a01447259ae9；SHA-256：4c66c05090557f8e2882febc98284ab308feb9b6d49aab920366da91482bab90
- source-snapshot.zip；ID：5988ccc6-354b-402d-b74d-7711287ef73a；SHA-256：e02637ce9d586cbb131ad41df32f9af31214fb823fff0e25aecf7e7e2d78eb3b
