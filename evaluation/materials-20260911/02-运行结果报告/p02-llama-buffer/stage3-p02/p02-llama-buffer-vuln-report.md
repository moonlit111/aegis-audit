# AegisAudit 分析报告

项目：对照池评测 20260911-093538

任务：045e52b6-0a05-4154-933a-a094780e95df

状态：Cancelled

目标 SHA-256：6d94318d39fe5fbfaee8187b6c97589021d40a6de0974b218e19debdb1dea839

结果快照 · 数据截至 2026-09-11T09:51:30.111Z · 导出时任务状态 CANCELLED。漏洞审计：CANCELLED；独立复核：COMPLETED；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| \_\_call\_\_ | llama\_cpp/llama.py | L1357–L1425 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama.py | L199–L200 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama.py | L189–L192 | PARSED |
| \_\_contains\_\_ | llama\_cpp/llama.py | L55–L56 | PARSED |
| \_\_contains\_\_ | llama\_cpp/llama.py | L152–L153 | PARSED |
| \_\_contains\_\_ | llama\_cpp/llama.py | L99–L100 | PARSED |
| \_\_del\_\_ | llama\_cpp/llama.py | L1557–L1563 | PARSED |
| \_\_getitem\_\_ | llama\_cpp/llama.py | L90–L97 | PARSED |
| \_\_getitem\_\_ | llama\_cpp/llama.py | L141–L150 | PARSED |
| \_\_getitem\_\_ | llama\_cpp/llama.py | L51–L52 | PARSED |
| \_\_getstate\_\_ | llama\_cpp/llama.py | L1565–L1586 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama.py | L36–L37 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama.py | L206–L378 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama.py | L170–L182 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama.py | L1706–L1707 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama.py | L66–L69 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama.py | L118–L122 | PARSED |
| \_\_setitem\_\_ | llama\_cpp/llama.py | L59–L60 | PARSED |
| \_\_setitem\_\_ | llama\_cpp/llama.py | L102–L108 | PARSED |
| \_\_setitem\_\_ | llama\_cpp/llama.py | L155–L166 | PARSED |
| \_\_setstate\_\_ | llama\_cpp/llama.py | L1588–L1609 | PARSED |
| \_convert\_text\_completion\_chunks\_to\_chat | llama\_cpp/llama.py | L1448–L1485 | PARSED |
| \_convert\_text\_completion\_to\_chat | llama\_cpp/llama.py | L1427–L1446 | PARSED |
| \_create\_completion | llama\_cpp/llama.py | L859–L1280 | PARSED |
| \_find\_longest\_prefix\_key | llama\_cpp/llama.py | L44–L48 | PARSED |
| \_find\_longest\_prefix\_key | llama\_cpp/llama.py | L75–L88 | PARSED |
| \_find\_longest\_prefix\_key | llama\_cpp/llama.py | L128–L139 | PARSED |
| \_input\_ids | llama\_cpp/llama.py | L381–L382 | PARSED |
| \_sample | llama\_cpp/llama.py | L507–L653 | PARSED |
| \_scores | llama\_cpp/llama.py | L385–L386 | PARSED |
| cache\_size | llama\_cpp/llama.py | L125–L126 | PARSED |
| cache\_size | llama\_cpp/llama.py | L72–L73 | PARSED |
| cache\_size | llama\_cpp/llama.py | L41–L42 | PARSED |
| create\_chat\_completion | llama\_cpp/llama.py | L1487–L1555 | PARSED |
| create\_completion | llama\_cpp/llama.py | L1282–L1355 | PARSED |
| create\_embedding | llama\_cpp/llama.py | L789–L846 | PARSED |
| decode | llama\_cpp/llama.py | L1714–L1715 | PARSED |
| detokenize | llama\_cpp/llama.py | L437–L458 | PARSED |
| embed | llama\_cpp/llama.py | L848–L857 | PARSED |
| encode | llama\_cpp/llama.py | L1709–L1712 | PARSED |
| eval | llama\_cpp/llama.py | L472–L505 | PARSED |
| eval\_logits | llama\_cpp/llama.py | L393–L397 | PARSED |
| eval\_tokens | llama\_cpp/llama.py | L389–L390 | PARSED |
| from\_ggml\_file | llama\_cpp/llama.py | L1718–L1719 | PARSED |
| generate | llama\_cpp/llama.py | L706–L787 | PARSED |
| llama\_cpp/llama.py | llama\_cpp/llama.py | L1–L1719 | PARSED |
| load\_state | llama\_cpp/llama.py | L1641–L1651 | PARSED |
| logits\_to\_logprobs | llama\_cpp/llama.py | L1689–L1692 | PARSED |
| longest\_token\_prefix | llama\_cpp/llama.py | L1695–L1702 | PARSED |
| n\_ctx | llama\_cpp/llama.py | L1653–L1656 | PARSED |
| n\_embd | llama\_cpp/llama.py | L1658–L1661 | PARSED |
| n\_vocab | llama\_cpp/llama.py | L1663–L1666 | PARSED |
| reset | llama\_cpp/llama.py | L468–L470 | PARSED |
| sample | llama\_cpp/llama.py | L655–L704 | PARSED |
| save\_state | llama\_cpp/llama.py | L1611–L1639 | PARSED |
| set\_cache | llama\_cpp/llama.py | L460–L466 | PARSED |
| token\_bos | llama\_cpp/llama.py | L1678–L1681 | PARSED |
| token\_eos | llama\_cpp/llama.py | L1673–L1676 | PARSED |
| token\_nl | llama\_cpp/llama.py | L1683–L1686 | PARSED |
| tokenize | llama\_cpp/llama.py | L399–L435 | PARSED |
| tokenizer | llama\_cpp/llama.py | L1668–L1671 | PARSED |

## 审计策略与优先级

目标为 llama.cpp 的 Python 绑定单文件（llama\_cpp/llama.py，60 个函数）。优先审计外部输入进入点与信任边界：模型/词表文件路径加载、tokenize/detokenize 的 ctypes 缓冲区与索引换算、eval 与采样中的 C 层调用参数、文本/聊天补全的请求反序列化、以及 pickle/序列化状态（\_\_getstate\_\_/\_\_setstate\_\_/save\_state/load\_state）与磁盘缓存路径。所有结论需结合被调用的 C 扩展实现与真实调用点验证，仅凭函数名或线索不下定性结论。

1. u\_24d54c928fa9f40b030fab624731fbcf：Llama.\_\_init\_\_ 为模型加载核心，涉及 from\_pretrained 路径拼接、n\_ctx/n\_\* 参数、ctypes 句柄与资源生命周期，是外部不可信输入（模型文件路径/本地文件）进入的主要信任边界。
2. u\_65499a708edd98544f6315743acfc79a：tokenize 接收任意文本，涉及 n\_ctx/缓冲区大小、add\_bos 逻辑与向 C API 传入的指针与长度，是越界与长度不一致风险的重点。
3. u\_b1409472f9347cb84bac39ccfec7368d：detokenize 标注含内存或索引操作，输出缓冲区大小、token 数量与 bytes 解码路径需核对边界与异常处理。
4. u\_9e3f4978c2c3cf6fd6a86a3511355f13：eval 为执行/解释边界，token 批大小与 n\_tokens 计数、n\_past 推进直接决定 C 层索引是否越界。
5. u\_59151986866761d5cfd9ea2d8ca20da2：\_sample 含 logits 处理与 C 采样调用，涉及 n\_vocab 索引、top\_k/top\_p/temperature 等外部可控参数与概率数组索引。
6. u\_7e748741c52c76fd65f62468a8e26eec：generate 是主生成入口，直接消费用户 prompt 与生成参数（max\_tokens、stop、logits\_processor），控制流与迭代终止条件需审计。
7. u\_e5f1e692037268ca018b96561c949d5b：\_create\_completion 体量最大（859-1280），处理大量外部可控补全参数、stop 序列截断与 prompt token 缓存复用，是逻辑与语义不一致的高危集中点。
8. u\_9f3ca46dbd3d7f17621ab12702d01e43：create\_completion 为对外 API，输入校验、默认值填充与 streaming/非 streaming 分支分派是下游所有逻辑的前提。
9. u\_126030382afa9fd92b59a0e802df74ee：create\_chat\_completion 处理外部聊天消息与工具/函数调用序列化，涉及模板拼接与角色信任边界，语义授权错误风险高。
10. u\_2847896b3a0e329837c5a429024fa265：\_\_setstate\_\_ 涉及反序列化信任边界，若状态来自不可信来源（pickle/字节流），需核实反序列化内容如何被用于重建输入与缓存。
11. u\_e4e5ee480e58eb0342603947e78c1cde：\_\_getstate\_\_ 与 \_\_setstate\_\_ 成对，需确认导出状态是否包含句柄/路径等敏感信息，以及二者契约是否对称。
12. u\_bcdbe94b308d09f4a8159c98f3f1bd21：load\_state 标注内存或索引操作，从外部字节流恢复模型状态，长度校验与指针/内存拷贝是越界与内存破坏的关键点。
13. u\_7b3bc8de7600bc7bf815feafde6a5115：save\_state 与 load\_state 对应，需核对状态大小语义与调用方是否校验，避免恢复不一致状态。
14. u\_3fef5bb98f5e1d7575c0a613d199312a：longest\_token\_prefix 被缓存键匹配多处调用（U0010/U0016），其比较逻辑影响缓存命中，需确认不会因前缀误匹配返回错误历史状态。
15. u\_86e67d807b341f10d80cb8697065718e：create\_embedding 外部输入进入向量计算，涉及 n\_embd 尺寸与 numpy 缓冲区映射，需核对形状与内存共享。
16. u\_07eccacb2ab7a2c68b5e1a528a253ef6：\_\_call\_\_ 为统一对外调用入口，参数组合与分派到 completion/chat 的语义边界需要核对。
17. u\_bf5f76b7eec7adefdb309fa8ce003d7d：LlamaDiskCache 使用外部可控 cache\_dir 构造磁盘缓存，涉及路径与磁盘写入，是文件系统信任边界。
18. u\_ad6581449af6b985c9d2f708b93abf08：磁盘缓存 \_find\_longest\_prefix\_key 遍历全部键并调用 longest\_token\_prefix，性能与键类型不一致（注释所述整数键问题）可能引发异常或错误命中。
19. u\_f07626db52b775643a9f3bcfec300210：磁盘缓存 \_\_setitem\_\_ 含删除/写入/裁剪逻辑与调试输出，容量计算与键删除路径需核对是否误删或残留。
20. u\_2821a56a95ac6198d095074919aec2f7：LlamaState 持有 llama\_state 字节与尺寸，是缓存与序列化之间的数据载体，需核对其一致性校验责任归属。
21. u\_2625cea68895686142f65e6d6552306d：encode 作为模型 tokenizer 对外封装，输入文本与返回 token 列表的边界处理需核对。
22. u\_1465c6bc31347802bd00384ffa92ab63：decode 与 encode 对称，token 到文本转换可能涉及缓冲区大小，需核对异常与越界处理。
23. u\_bd67c252c4d2d4dbfb1e7126e598811d：eval\_tokens/eval\_logits 为较薄包装，需确认其是否绕过上层长度校验直接调用 C API。
24. u\_a00dcc163e0a2d4af90390f3d7a82eed：eval\_logits 与 eval\_tokens 同层，输入 ids 数量与返回 logits 形状一致性是隐患点。
25. u\_bb46040833d457f3f6f3f296b3babb8b：\_input\_ids 属性暴露内部 numpy 数组，需核对是否造成共享可变状态与外部越界写入。
26. u\_f11cbb4d9470695a7bb058f473f933ac：\_scores 属性同样暴露内部缓冲区，需核对形状与生命周期。
27. u\_0f7944b006bd4b367961554ef71c8ee2：sample 作为 \_sample 的公开包装，需确认外部可传入的回调与参数是否被无校验地转发。
28. u\_6307452299c403cc05805e168f2e24a1：set\_cache 接收外部缓存对象并影响后续前缀复用，是跨请求状态污染的语义边界。
29. u\_1407f6ef1224c3b100c5acb39818e2b1：reset 清除状态，需与缓存复用逻辑一起核对是否导致状态与 n\_tokens 不一致。
30. u\_82a9cf9fede8389874eed2c3a0a28586：logits\_to\_logprobs 处理数值输入（softmax/log），需核对 zero/NaN 处理与数组索引。

规划限制：仅解析 llama\_cpp/llama.py 单文件（61 个单元），导入的 C 扩展 llama\_cpp.\* 与 llama\_grammar/llama\_types/utils 未提供，跨语言调用的真实语义与参数校验不可见，属于显式缺口。

规划限制：分析元数据显示 call\_graph\_complete=false，调用图不完整；动态分派（如 LogitsProcessor/StoppingCriteria 回调）目标无法静态确定。

规划限制：Semgrep 状态为 UNSUPPORTED（执行器未准备 Windows 原生 Semgrep），仅有内建词法线索，线索不是漏洞结论。

规划限制：未构建、未运行目标（build\_executed=false、target\_executed=false），所有结论均为静态推断，未经验证。

规划限制：未识别构建系统、入口、输入接口与依赖清单，请求来源与部署方式不明，无法确定这些函数在真实部署中是否暴露于不可信输入。

规划限制：recovery 为 null，本目标为 SOURCE 类型，无可用的二进制恢复/加壳或混淆元数据，不能对反编译质量或保护缺口作评估，也不存在已记录的脱壳/反混淆转换。

规划限制：禁止 CVE/版本比对与项目特定答案模板，因此不对具体版本缺陷作断言；路径与缓冲区风险需人工结合 C 层实现复核。

## 发现与复核

静态结论范围：COMPONENT

### 初始化分配 token/分数缓冲区时使用未初始化的 ndarray

CWE-908 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：不适用：该分配由初始化路径触发，取决于后续写入/读取顺序

危险操作：np.ndarray\(\(n\_ctx,\), dtype=np.intc\) 与 np.ndarray\(\(n\_ctx, self.\_n\_vocab\), dtype=np.single\) 的未初始化分配

防护缺口：未使用 np.zeros 或显式填充初始化缓冲区

前提：后续代码在写入前读取 self.input\_ids 或 self.scores（需在其他单元确认）

影响：可能向后返回未初始化堆内存内容（信息泄露）

修复：改为 np.zeros\(...\) 或在构造后立即填充，避免把未初始化缓冲区暴露给调用方

- 证据：llama\_cpp/llama.py L375–375 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        self.input\_ids: npt.NDArray\[np.intc\] = np.ndarray\(\(n\_ctx,\), dtype=np.intc\)
- 证据：llama\_cpp/llama.py L376–378 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        self.scores: npt.NDArray\[np.single\] = np.ndarray\(             \(n\_ctx, self.\_n\_vocab\), dtype=np.single         \)

复核 v2（MODEL，INCONCLUSIVE）：U0023 第375-378行确实用 np.ndarray 直接分配 self.input\_ids 与 self.scores，不做零初始化（同单元372行对 \_candidates\_data\_p 使用 np.zeros，说明零初始化是可行写法），因此“存在未初始化缓冲区”这一事实成立。读取侧进一步核查：eval（U0032）在 logits\_all=False 时只写回每个 batch 的最后一行（offset=n\_tokens-1、rows=1，第496-503行），随后把 self.n\_tokens 前移（第505行），而 \_scores/scores 按 self.scores\[:self.n\_tokens, :\] 暴露未写入行（U0025 第385-386行）；eval\_logits 更会把 self.scores\[:self.n\_tokens, :\] 整块 .tolist\(\)，即把未写入行读成 Python 浮点数（U0027 第393-397行），但 maxlen=logits\_all?n\_ctx:1 只保留最后一行（已写入行），未初始化值不会经该出口返回。因此 CWE-908 语义上的“读未初始化资源”在内部分支可成立，但候选声称的“对外泄露未初始化堆内容”缺少把该值传给不受信任方的通道证据：logprobs 在 logits\_all=False 时被显式拒绝（U0001 第921-923行），sample 只取 self.\_scores\[-1, :\]（已写入行），input\_ids 的读取均按 \[:n\_tokens\] 截断且 eval 在自增前先写入（第494、505行）。故组件级事实成立、泄露影响待证。

反证：1\) \_\_init\_\_ 自身只分配、不读取这两个缓冲区，泄露点不在本单元接口内；2\) input\_ids 的所有读取都按 self.n\_tokens 截断，且 eval 在 self.n\_tokens 自增之前把 batch 写入对应行（U0032 第494、505行），故 input\_ids 不存在读先于写；3\) eval\_logits 虽然整块 .tolist\(\) 从而读到未写入行，但 maxlen 在 logits\_all=False 时为 1，返回给调用者的仅是已写入的最后一行（U0027 第393-397行）；4\) 唯一会遍历全部行的文档化出口 logprobs 在 logits\_all=False 时被抛 ValueError 拒绝（U0001 第921-923行）；5\) 经 scores/\_scores 属性读到未写入行时接收方是本地库调用者（组件契约内的可信运行时状态），无证据表明其被转发给不受信任方。

待补信息：1\) 是否存在把 model.scores/model.logits（logits\_all=False 时含未写入行）序列化或返回给不受信任方的调用者/服务；2\) 未写入行在实际分配（大块 numpy 分配可能走 mmap 零页）下是否真含可辨识的堆残留；3\) 缺少部署参数（logits\_all、n\_batch、是否多 token 批评估）以确认“读出未写入行”在部署中确实发生；4\) 部分工具输出被截断或前后不一致（同一单元多次返回不同行文本），结论仅基于多次一致的 search\_code/read\_span 证据，未穷举全部读取路径。
静态结论范围：COMPONENT

### 外部可控的模型/LoRA 文件路径进入原生加载调用，仅有存在性校验且无规范化或目录约束

CWE-73 · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：Llama.\_\_init\_\_ 的 model\_path、lora\_path、lora\_base 参数（可能源自调用方的不可信输入）

危险操作：llama\_cpp.llama\_load\_model\_from\_file\(self.model\_path.encode\(&quot;utf-8&quot;\), self.params\) 与 llama\_cpp.llama\_model\_apply\_lora\_from\_file\(...\) 的原生文件读取

防护缺口：缺少 os.path.realpath/abspath 规范化、基目录（如允许列表）约束或类型白名单；第 311 行只做 os.path.exists 存在性判断，且该判断与第 315-322 行的实际加载之间存在 TOCTOU 窗口（路径可被替换为符号链接或不同文件）

前提：宿主应用将不可信字符串传入 model\_path/lora\_path；进程对目标路径具有读权限；verbose/非 verbose 分支均会调用原生加载

影响：可探测任意本地文件是否存在并让原生解析器读取攻击者指定的模型/LoRA 文件；若 C 层解析器存在内存安全问题，可能进一步影响进程（本快照无法验证 C 实现），单纯数据文件加载不会直接执行代码

修复：在调用本单元前对路径做 realpath 规范化并限制在配置允许的目录内，使用 os.path.isfile 并在加载前重新校验（消除 TOCTOU），仅从受信配置接受 lora\_path/lora\_base，必要时在低权限或沙箱进程中加载模型文件

- 证据：llama\_cpp/llama.py L316–316 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：                self.model\_path.encode\(&quot;utf-8&quot;\), self.params
- 证据：llama\_cpp/llama.py L311–312 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        if not os.path.exists\(model\_path\):             raise ValueError\(f&quot;Model path does not exist: {model\_path}&quot;\)
- 证据：llama\_cpp/llama.py L337–343 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            if llama\_cpp.llama\_model\_apply\_lora\_from\_file\(                 self.model,                 llama\_cpp.c\_char\_p\(self.lora\_path.encode\(&quot;utf-8&quot;\)\),                 llama\_cpp.c\_char\_p\(self.lora\_base.encode\(&quot;utf-8&quot;\)\)                 if self.lora\_base is not None                 else llama\_cpp.c\_char\_p\(0\),                 llama\_cpp.c\_int\(self.n\_threads\),

复核 v2（MODEL，REJECTED）：该单元的职责契约就是“从调用方给出的 model\_path/lora\_path 加载模型”，model\_path\(第208行\)、lora\_path/lora\_base\(第223-224行\)是库的公开配置参数，函数把该路径直接传给原生加载\(第315-316、337-343行\)。代码中不存在受保护的基目录、路径拼接\(无 os.path.join\(root, user\) 形式\)、允许列表或任何被绕过的前缀约束，因此第311-312行的 os.path.exists 之后直接加载并不是“越过边界”的路径穿越，而是该 API 的既定语义：能提供该参数的调用方本来就有权指定加载哪个文件。CWE-73 类缺陷需要“文件路径跨越信任边界/逃逸受限根目录”，本组件没有这样的边界，故主结论不成立。候选提到的 TOCTOU（存在性检查与加载之间替换为符号链接）需要额外的攻击者文件系统写入能力，且在“已允许调用方指定任意路径”的前提下该能力并不带来额外越权，不能支撑 PATH\_TRAVERSAL 结论。

反证：存在性校验第311-312行（虽不构成安全边界，但排除了明显的不存在路径）；model\_path/lora\_path 均为显式命名参数而非从 HTTP/文件内容解析所得；代码中无受限根目录常量、无路径拼接、无“仅允许某目录”的声明性约束，也无任何被绕过的前缀/规范化检查；实际文件读取发生在原生 C 层，本快照不包含其实现。

待补信息：宿主应用是否把不可信外部字符串映射为 model\_path/lora\_path（调用方/部署形态不在本快照内）；原生 C 解析器是否存在内存安全问题（快照无 C 源码）；是否存在调用方之外的攻击者能并发修改文件系统（TOCTOU 前置条件未证实，且对已允许任意路径的场景无额外收益）。
静态结论范围：COMPONENT

### tokenize 仅用 assert 校验模型状态并对 C 层调用缺少显式长度上限校验

UNKNOWN · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：text: bytes 参数，来自外部调用方（如 U0036 create\_embedding 第 819 行 input.encode\(&quot;utf-8&quot;\)、U0038 create\_completion/prompt 编码）

危险操作：llama\_cpp.llama\_tokenize\_with\_model\(self.model, text, tokens, c\_int\(n\_ctx\), c\_bool\(add\_bos\)\) 将外部文本写入固定长度 ctypes 缓冲区

防护缺口：除 assert self.model is not None 与 n\_tokens&lt;0 时的扩容重试外，未见对 text 长度、编码后长度上限或 C 层返回计数的显式运行时校验；assert 在优化模式下可被移除

前提：调用方将超长或构造性文本传入 tokenize；或解释器以 -O 运行使 assert 失效；且底层 C 函数未对给定缓冲区长度做充分截断/拒绝

影响：若底层 tokenize 未严格以 n\_ctx 为写入上界，理论上可能导致缓冲区溢出或进程崩溃；在当前证据下更可能表现为 Tokenize 失败并抛出 RuntimeError（行 432）

修复：用显式 if 检查替代 assert；对 text 长度与所需 token 数做显式上限校验，并在扩容重试路径中确认第二次返回计数不超过已分配缓冲区

- 证据：llama\_cpp/llama.py L412–420 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        n\_ctx = self.\_n\_ctx         tokens = \(llama\_cpp.llama\_token \* n\_ctx\)\(\)         n\_tokens = llama\_cpp.llama\_tokenize\_with\_model\(             self.model,             text,             tokens,             llama\_cpp.c\_int\(n\_ctx\),             llama\_cpp.c\_bool\(add\_bos\),         \)
- 证据：llama\_cpp/llama.py L411–411 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        assert self.model is not None
- 证据：llama\_cpp/llama.py L421–435 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        if n\_tokens &lt; 0:             n\_tokens = abs\(n\_tokens\)             tokens = \(llama\_cpp.llama\_token \* n\_tokens\)\(\)             n\_tokens = llama\_cpp.llama\_tokenize\_with\_model\(                 self.model,                 text,                 tokens,                 llama\_cpp.c\_int\(n\_tokens\),                 llama\_cpp.c\_bool\(add\_bos\),             \)             if n\_tokens &lt; 0:                 raise RuntimeError\(                     f&#39;Failed to tokenize: text=&quot;{text}&quot; n\_tokens={n\_tokens}&#39;                 \)         return list\(tokens\[:n\_tokens\]\)
- 证据：llama\_cpp/llama.py L819–819 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            tokens = self.tokenize\(input.encode\(&quot;utf-8&quot;\)\)

复核 v2（MODEL，REJECTED）：该组件并未缺少&quot;长度/容量上界&quot;这一防御：第 413 行按 self.\_n\_ctx 分配 ctypes 缓冲区，第 414-419 行把同一容量 n\_ctx（c\_int\(n\_ctx\)）作为参数一并传给 C 绑定，因此 C 层获得写入上界信息；第 421-430 行进一步表明底层函数采用&quot;返回负值表示所需 token 数、不越界写入&quot;的约定：当返回负值时按 abs\(n\_tokens\) 重新分配并在第二次调用中把新容量（c\_int\(n\_tokens\)）再传入。这正是所声称&quot;缺失的显式上限校验&quot;在组件边界上的实现形式，SINK 的调用契约由调用方（组件）显式提供容量来约束。候选把&quot;C 实现是否遵守容量&quot;当作前提，但本快照中不存在任何推翻该契约的证据，第 421-433 行的失败分支（第二次仍为负值则 RuntimeError）恰恰显示设计预期是拒绝而非溢出。断言 assert self.model is not None（行 411）只涉及模型是否已加载的调用方前置条件，与写入上界无关，把它替换成 if 属纵深防御建议，不构成独立缺陷。

反证：行 413 分配 n\_ctx 大小缓冲区；行 414-419 将 c\_int\(n\_ctx\) 作为容量参数随缓冲区传入；行 421-430 的负值重试路径表明底层返回所需长度而非越界写入；行 431-433 在无法容纳时抛出 RuntimeError；行 435 的切片 tokens\[:n\_tokens\] 对返回计数做二次限界。

待补信息：llama.cpp 的 C 实现源码不在本快照中，无法独立核验其对容量参数的处理；但该实现属受信依赖，且其负值返回语义已由本组件源码逻辑间接反映。
静态结论范围：COMPONENT

### detokenize 未校验 token id 取值范围即传入 C 层词表转换函数

CWE-20 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：detokenize\(self, tokens: List\[int\]\) 的 tokens 参数，由外部调用者（U0001 中 LlamaTokenizer.decode 等）或模型采样结果提供

危险操作：llama\_cpp.llama\_token\_to\_str\_with\_model\(self.model, llama\_cpp.llama\_token\(token\), buffer, size\)（第 451-453 行）

防护缺口：循环内缺少对 token 的合法性校验（0 &lt;= token &lt; 词表大小）与异常返回值处理；现有唯一防线是第 454 行的 assert n &lt;= size，该断言在 python -O 下被移除，且它校验的是返回长度而非输入 id 的合法性

前提：攻击者或上游代码能控制传入的 token id（例如通过公开的 LlamaTokenizer.decode / 直接调用 detokenize 传入任意整数），且底层 llama\_token\_to\_str\_with\_model 未做同等校验

影响：可能造成 C 层词表索引越界读取，最坏情况是进程崩溃或内存内容泄露到返回的 bytes 中；断言被禁用时返回长度异常仅表现为静默截断/脏数据

修复：在循环内显式校验 token 为非负且在词表范围内，非法时抛出明确异常；不要把 assert 作为唯一长度防线；同时处理返回值为负（错误）的情况，避免把缓冲区残留数据拼入返回值

- 证据：llama\_cpp/llama.py L451–453 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            n = llama\_cpp.llama\_token\_to\_str\_with\_model\(                 self.model, llama\_cpp.llama\_token\(token\), buffer, size             \)
- 证据：llama\_cpp/llama.py L450–450 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        for token in tokens:
- 证据：llama\_cpp/llama.py L454–455 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            assert n &lt;= size             output += bytes\(buffer\[:n\]\)

复核 v2（MODEL，INCONCLUSIVE）：U0029 的 detokenize 确实把调用者提供的 tokens 逐元素经 llama\_token\(token\) 直接传入底层 llama\_token\_to\_str\_with\_model（第450-452行），循环内没有任何 0&lt;=token&lt;词表大小 的校验；唯一的运行期检查是第454行 assert n &lt;= size，它校验的是返回长度而非输入 id 合法性，且在 python -O 下会被移除。就“函数参数直达该调用”这一本地边界而言，输入可控与可达性成立。但候选结论声称的后果是 C 层词表索引越界读取，这取决于 llama\_token\_to\_str\_with\_model 的原生实现是否对 token id 做上界/非负检查；该 C/C++ 实现不在提供的制品中（search\_code 仅命中两处 Python 调用点，无绑定或包装源码），无法证实底层会以未校验的 id 直接索引词表。因此这是一个依赖未提供原生代码的前提条件，属证据不足，不能静态确认为真实越界，也不存在可据以反驳的证据。

反证：第454行 assert n &lt;= size 是对返回长度的检查（非输入校验），且可被 -O 移除；第431-434行显示同文件 tokenize 对 n\_tokens&lt;0 有显式 RuntimeError，而 detokenize 缺少类似的返回值错误处理（仅此一处对照，属于防御缺口而非越界证据）。未发现任何对 token 范围的显式校验。

待补信息：llama\_token\_to\_str\_with\_model 的原生实现：是否对 token id 做非负/词表上界校验，以及越界时返回 0/负值还是直接以 id 索引词表；该 C 侧代码未包含在目标制品中。另需确认 llama\_token\(token\) 是否本身产生截断或范围检查。
静态结论范围：COMPONENT

### eval\(\) 按 rows\*cols 读取原生 logits 指针且无长度一致性校验

UNKNOWN · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：self.params.logits\_all（构造时可配置）与 llama\_cpp.llama\_get\_logits 返回的原生指针

危险操作：self.scores\[...\].reshape\(-1\)\[:\] = llama\_cpp.llama\_get\_logits\(self.ctx\)\[: rows \* cols\]

防护缺口：没有校验 C 侧返回的 logits 缓冲区实际长度是否 &gt;= rows \* cols，也没有长度查询/断言

前提：params.logits\_all 与底层上下文实际分配 logits 行数不一致，或上下文状态使返回指针指向更短的缓冲区

影响：numpy 从原生指针读取 rows\*cols 个 float，可能越界读取相邻内存并写入 scores

修复：在拷贝前查询/断言 logits 可用长度，或在 C 绑定层暴露长度接口后据此切片；至少为 rows\*cols 与 \_n\_vocab 组合增加一致性断言

- 证据：llama\_cpp/llama.py L501–503 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            self.scores\[self.n\_tokens + offset : self.n\_tokens + n\_tokens, :\].reshape\(                 -1             \)\[:\] = llama\_cpp.llama\_get\_logits\(self.ctx\)\[: rows \* cols\]
- 证据：llama\_cpp/llama.py L496–497 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            rows = n\_tokens if self.params.logits\_all else 1             cols = self.\_n\_vocab

复核 v2（MODEL，INCONCLUSIVE）：U0032 的 eval\(\) 确实把 self.params.logits\_all 与 n\_tokens 推导出的 rows、以及模型词表宽度 cols 相乘，并用该乘积切片原生指针 llama\_get\_logits\(self.ctx\)\[: rows\*cols\]（496-497、501-503 行）。因此在本组件边界内，rows\*cols 完全由参数与该对象自身状态决定，拼接与指针切片这一步对符号输入可达。但候选主张的核心前提——C 侧实际分配的 logits 缓冲区行数可能小于 rows（即 logits\_all 与底层上下文布局不一致）——在提供的源码中没有任何证据：llama.cpp 的约定是 logits\_all 为真时按 n\_ctx 行分配、为假时按 1 行分配，恰好与 496/499 行的 rows/offset 逻辑一致，cols 亦取自同一模型上下文。这属于对绑定契约是否恒成立的外部未知，而非本组件可独立证实的越界。因此既不能凭现有代码判为已验证的越界读，也无相反源码证据将其直接否定，标记为 INCONCLUSIVE。

反证：496 行 rows 与 499 行 offset 的取值与 llama.cpp 的 logits\_all 语义（真=每 token 一行、假=仅末 token 一行）自洽；cols 来自同一上下文的 \_n\_vocab（497 行），与 logits 行宽同源；切片上界与目标 self.scores 形状匹配（501-502 行）。候选自身也承认“C 侧实际分配的 logits 数量不在此快照内”，未给出失配证据。

待补信息：C 绑定/原生库中 logits 缓冲区的实际分配长度查询接口或其不变量；是否存在任何部署路径能让 params.logits\_all 与底层上下文分配行数不一致（例如上下文状态被外部改写或绑定的 get\_logits 返回更短缓冲）。这些均超出本组件快照。
静态结论范围：COMPONENT

### eval\(\) 将未做范围校验的 token id 直接序列化进原生缓冲区并调用 llama\_eval

CWE-129 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：eval\(tokens\) 的 tokens 参数（Sequence\[int\]），以及 tokenize/生成路径经 U0035、U0036 传入的 token 序列

危险操作：llama\_cpp.llama\_eval\(ctx=self.ctx, tokens=\(llama\_cpp.llama\_token \* len\(batch\)\)\(\*batch\), n\_tokens=..., n\_past=..., n\_threads=...\)

防护缺口：既未校验 batch 内每个元素在 \[0, self.\_n\_vocab\) 范围内，也未校验其类型/非负性，直接按 llama\_token 强制转换后交给原生代码；同样未对 n\_past 的下界做检查（仅用 min 取上界）

前提：调用方能够控制传给 eval\(\) 的 token 列表（例如直接调用 eval，或通过提供 token id 列表的公共 API），且底层 llama\_eval 对越界 token id 无自身校验

影响：越界/负数 token id 在原生层被用作词表或嵌入表索引，可能造成越界读、错误内存解释或进程崩溃（信息泄露或拒绝服务）

修复：在进入 ctypes 转换前显式校验每个 token id 的类型与取值范围（0 &lt;= t &lt; self.\_n\_vocab），越界即抛出 ValueError；同时对 n\_past 增加 &gt;= 0 的下界断言，并考虑在 \_input\_ids/scores 写入前统一走一个受校验的入口

- 证据：llama\_cpp/llama.py L484–490 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            return\_code = llama\_cpp.llama\_eval\(                 ctx=self.ctx,                 tokens=\(llama\_cpp.llama\_token \* len\(batch\)\)\(\*batch\),                 n\_tokens=llama\_cpp.c\_int\(n\_tokens\),                 n\_past=llama\_cpp.c\_int\(n\_past\),                 n\_threads=llama\_cpp.c\_int\(self.n\_threads\),             \)
- 证据：llama\_cpp/llama.py L482–482 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            n\_past = min\(n\_ctx - len\(batch\), len\(self.\_input\_ids\)\)
- 证据：llama\_cpp/llama.py L494–494 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            self.input\_ids\[self.n\_tokens : self.n\_tokens + n\_tokens\] = batch
- 证据：llama\_cpp/llama.py L765–765 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            self.eval\(tokens\)
- 证据：llama\_cpp/llama.py L821–821 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            self.eval\(tokens\)
- 证据：llama\_cpp/llama.py L298–298 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：        self.n\_batch = min\(n\_ctx, n\_batch\)

复核 v2（MODEL，INCONCLUSIVE）：eval\(\)（U0032）确实把调用方传入的 tokens 参数（Sequence\[int\]，第472行）直接切片、构造为 llama\_token 数组并传给原生 llama\_eval（第480-490行），在本组件边界内没有任何 token id 的类型/范围校验：既未检查 0 &lt;= t &lt; self.\_n\_vocab，也未检查非负性。\_n\_vocab 在同文件初始化（第352、497行）可用于校验但未被用于此目的。因此“函数参数未经校验直达原生索引操作”这一本地组件事实成立。但候选所述的越界读/内存错误解释属于 C 层 llama\_eval 的行为，本快照只含 Python 绑定层，不含其 C 实现，无法确认底层是否已对 token id 做边界检查，也无法确认负值/越界值会实际用于词表或嵌入索引；故只能在组件层面确认缺失防护，不能确认最终内存越界影响。此外候选关于 n\_past 可能为负的推断被反证：n\_batch 在 U0023 第298行被限定为 min\(n\_ctx, n\_batch\)，故 len\(batch\) &lt;= self.n\_batch &lt;= n\_ctx，第482行 n\_ctx - len\(batch\) &gt;= 0，n\_past 下界自然非负。

反证：第482行 n\_past = min\(n\_ctx - len\(batch\), len\(self.\_input\_ids\)\)，配合 U0023 第298行 self.n\_batch = min\(n\_ctx, n\_batch\)，可推出 n\_ctx - len\(batch\) &gt;= 0，n\_past 不会为负，候选的 n\_past 下界问题被局部逻辑否定。第494行 self.input\_ids 与第501-503行 self.scores 的索引均基于 self.n\_tokens 与 \_n\_vocab 列数，而非以 token 值作下标，故这些 numpy 写入本身不因 token id 越界而越界。

待补信息：1\) llama\_cpp C 层 llama\_eval/词表与嵌入表实现对越界、负值 token id 是否已有边界校验（本快照不含 C 源码，无法确认）；2\) 底层 llama\_token 为 32 位有符号整数这一类型假设及其强制转换的溢出语义；3\) 实际部署中调用方是否可提供任意 token id 列表（组件边界上 tokens 已是符号化输入，但完整服务链路未提供）。
静态结论范围：COMPONENT

### generate 的 token 序列未经取值范围校验即进入 ctypes 原生采样/评估链

CWE-129 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：generate 的 tokens 参数（调用方提供的 Sequence\[int\]，例如由外部文本经其他路径映射得到的 token id）以及生成器被 send 回来的 tokens\_or\_none（第 784-787 行先 extend 进 tokens）

危险操作：self.eval\(tokens\)（U0035 第 765 行）→ U0032 eval 第 486 行 \(llama\_cpp.llama\_token \* len\(batch\)\)\(\*batch\) → llama\_cpp.llama\_eval

防护缺口：缺少对每个 token id 的 0 &lt;= id &lt; n\_vocab 范围检查与非负/整数类型校验；仅在切片与 zip 前缀匹配处做了长度处理（第 744-756 行）

前提：上层把不可信文本或外部输入的 token id 直接传给 generate，或把外部数据通过 yield/send 注入 tokens\_or\_none；native llama\_eval 对越界 id 的行为未知

影响：越界或负数 token id 传入原生评估调用，可能造成 embedding/词表查表的越界读取，属于内存边界与未定义行为风险；在本目标内表现为把校验责任完全交给 C 层

修复：在 generate 入口及 tokens\_or\_none 合并处对每个 token 做整数与 0&lt;=id&lt;n\_vocab 断言，越界即抛错；并对 tokens\_or\_none 的长度设上限

- 证据：llama\_cpp/llama.py L765–765 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            self.eval\(tokens\)
- 证据：llama\_cpp/llama.py L784–787 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            tokens\_or\_none = yield token             tokens = \[token\]             if tokens\_or\_none is not None:                 tokens.extend\(tokens\_or\_none\)
- 证据：llama\_cpp/llama.py L484–490 ；产物 4ee153c1-a639-4558-a3b7-914db952f314；引用：            return\_code = llama\_cpp.llama\_eval\(                 ctx=self.ctx,                 tokens=\(llama\_cpp.llama\_token \* len\(batch\)\)\(\*batch\),                 n\_tokens=llama\_cpp.c\_int\(n\_tokens\),                 n\_past=llama\_cpp.c\_int\(n\_past\),                 n\_threads=llama\_cpp.c\_int\(self.n\_threads\),             \)

复核 v2（MODEL，INCONCLUSIVE）：在组件边界内，generate 的 tokens 参数确实未经 0&lt;=id&lt;n\_vocab 或整数范围校验即被转发：U0035 第765行 self.eval\(tokens\)，以及回灌路径 U0035 第784-787行将 tokens\_or\_none 合并后再次进入循环。eval\(U0032\) 仅按 self.n\_batch 切片并用 len\(batch\) 构造等长 ctypes 数组 \(U0032 第486行\)，随后调用 llama\_cpp.llama\_eval \(U0032 第484-490行\)。Python 侧只把 token 值作为值写入该数组与 self.input\_ids，并未把 token 值当作 Python/NumPy 索引，因此 Python 层不存在自身的越界读写。是否发生越界读取完全取决于本快照未提供的原生 llama\_eval 对 id 的索引方式：若原生对 id 作 embedding/词表数组下标且不校验，则该 id 可越界；若原生内部已做边界处理，则不成立。该关键证据缺失，故不能判为 VALIDATED。

反证：wrapper 内唯一的长度类处理是切片与分批 \(U0032 第480-481行\) 以及 U0035 第744-756行的前缀匹配；这些都不限制 token 取值。未见任何基于 n\_vocab 或非负性的断言/异常。n\_vocab 仅在 U0032 第497行用作 logits 列数，未用于校验输入 token。

待补信息：原生 llama\_eval 的实现（本快照未提供）对 token id 是否作未校验数组下标；若作下标，其可触发越界读取或返回错误码 \(U0032 第491-492行仅检查返回码\)。上游如何获得 token id（是否来自不可信文本映射）也属调用方契约，未在本组件内确证。

## 覆盖与错误

```json
{
  "audit_config": {
    "max_model_calls": 1200,
    "max_output_tokens": 0,
    "max_tool_rounds": 16,
    "max_units": 100,
    "model_timeout_seconds": 900,
    "reasoning_effort": "high",
    "timeout_seconds": 7200
  },
  "audit_coverage_gap": "共 61 个可读单元，完成 6 个单元的语义审计；其余未审计",
  "audited_unit_count": 6,
  "edge_count": 411,
  "eligible_unit_count": 61,
  "exclusions": [],
  "files": [
    {
      "language": "python",
      "path": "llama_cpp/llama.py",
      "reason": "",
      "status": "PARSED",
      "unit_count": 61
    }
  ],
  "finding_count": 7,
  "function_count": 60,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "COMPLETED",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 60,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "6d94318d39fe5fbfaee8187b6c97589021d40a6de0974b218e19debdb1dea839",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 111,
    "cost_cny": null,
    "measured_tokens": 848004,
    "unknown_usage_calls": 1
  },
  "result_artifact_id": "4ee153c1-a639-4558-a3b7-914db952f314",
  "reviewed_finding_count": 7,
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
      "finished_at": "2026-09-11T09:35:41.031Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T09:35:41.000Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 61,
  "unresolved_calls": 411,
  "verification": "NOT_RUN",
  "vulnerability_audit": "CANCELLED",
  "warnings": []
}
```

任务错误：审计取消或控制服务停止；本次模型用量未知

## 证据产物

- aegis-report-045e52b6-0a05-4154-933a-a094780e95df.html；ID：ae69677b-5197-4790-a0a5-4f3c4197bc8c；SHA-256：279c3f70ca8b14ab676b185d985bc757ad510858b08ceb8dd9a7782672fccabb
- aegis-report-045e52b6-0a05-4154-933a-a094780e95df.json；ID：4b20c2a5-a9c5-49e3-af37-61252821e3cc；SHA-256：7fc3e0febfa3e92b029182b1f0f2c104ef27900e20819e64e5a48cf772d90e6a
- agent-AUDITOR-00f540f4-11a8-4282-8277-c111b19e274e.json；ID：30efb8f4-980f-4b52-b519-b16720cdad4a；SHA-256：2169cc640b27072aa3a60841467b235a8ebdc8b424cf8ef985ce7582ead693e7
- agent-AUDITOR-227a4d7b-d1aa-41a1-8570-73316fe4f4be.json；ID：bc6e1a62-355c-476e-8523-11328c80714d；SHA-256：4220fa1f10a238472b40b995d4de7b3165abd4e1379eb492faf422355d3e69fe
- agent-AUDITOR-520537b7-f149-43a8-aaaf-16b9114e2175.json；ID：cd832b15-56ab-4ced-913b-f4dfb8c85a02；SHA-256：57965f24fef56ed8878f4b4551c8927f388ac1cb6de863f56b957a737c38d141
- agent-AUDITOR-5e3265b3-e95f-4007-bf1a-6cf2c6312bf5.json；ID：1569de5f-e3a8-416a-8506-707ddf50cb22；SHA-256：523bf2075cdf59b8cb45d5ce0c3cdd4a9d1e7cc0f5c05a0728848b402d0cea32
- agent-AUDITOR-a92fe819-375f-4e67-bd6f-debf2eac6029.json；ID：ea613046-2ae7-4165-9ea2-5b237aeeb7bb；SHA-256：26dd01f8ecfb798d0b1d9d8779bfaea9b2c9597e1ae2bca05365bf1ca918f5eb
- agent-AUDITOR-eb37416a-7f71-4cdb-9516-7d30ce7c7f15.json；ID：54967e7b-1268-4a48-a0ff-5c4282868692；SHA-256：ab09b67ae459aefdc26a5bf8b08c3b477ec8bee10943e9f93809fcce98f50d3f
- agent-PLANNER-b69f5784-8b74-4a9c-8a3f-4a3a5b5bf4d8.json；ID：aa0ed50a-83d2-4f4b-8ad7-ce797a1480b5；SHA-256：65b7414a2a8d2f60c04f90274d369ec9570347b55b23585d69df3c8697329038
- agent-REVIEWER-0ec763db-4ee2-4a96-8a79-901f93a9cc38.json；ID：efa11d69-a0d3-4f81-89d7-a2f4ba373b44；SHA-256：583788fd6558d4464c4c8bcb8b8db3d075312508aca89c48e2bef2780efb25c9
- agent-REVIEWER-5ecf31d1-7369-4e55-a563-394d8a8029dd.json；ID：edfff0b1-2062-4623-add7-a4b485e6c173；SHA-256：24d876258a44900c8938803f348a4b6c9c14459ff56a649ad3700dacb29d5252
- agent-REVIEWER-6cbe37eb-bb9e-45b5-975f-481bd20075c2.json；ID：5480c9db-c597-4559-b106-4f9017e223c0；SHA-256：b094a13ccda0577ddcc94a2fc7394c0c554e785c78a43603c0d2e6f8ad572878
- agent-REVIEWER-96f7f4c3-0b06-4249-86fb-ba130043893e.json；ID：401a45fa-eb0c-4336-b98a-2def42dcda1e；SHA-256：6955c3473ab7bef195ee7671cefbecbccbebfc0043079a3739f9889419fea899
- agent-REVIEWER-a563f38c-dc8f-492b-9301-c3bd78d1febb.json；ID：391bdf34-644b-45b5-b1c9-41cf46e0f326；SHA-256：3b2974398af6744d3e529cee934008ffe7843dd37af46933ffadc8ec76f26efe
- agent-REVIEWER-d0dfb2a1-37a0-4351-b46d-a4577b14cd07.json；ID：9e1e7e37-99a1-4829-81b4-1649a1768745；SHA-256：8ac5a0091043658ba5e5291eb663bcfcad99c865df3089474d653b3323655992
- agent-REVIEWER-e2e831c7-aef9-4967-a87b-68d87893a3da.json；ID：fbf55805-0fc5-4ee2-b8d2-39ce50de9ee9；SHA-256：fc734643b7e1364d24ec9769d222532df50be5bc1458f613244772b89c5880ef
- analysis-result.json；ID：4ee153c1-a639-4558-a3b7-914db952f314；SHA-256：4f58c915fcbaa078a3ceba579ddb9fdf12f181f312bbc063da9f68a22d35d22b
- model-request-02409c4d-c39c-4760-8398-2f734925f1f6.json；ID：0d623a14-3002-4205-b892-115c1a4c6cbe；SHA-256：b91d543a303ca8fefb0faf9082821d4f339a11794a3ddd88193f9c4391f26f8e
- model-request-0701dac1-83a1-43ae-875a-e3f93ac1c83b.json；ID：fd134363-471a-42e0-a9b1-be0ddb55d119；SHA-256：053f1aa3659328dc8c33a4b8a092ef7b7889cc1dfcbd71bf15ca11d48dd6dbee
- model-request-084d4106-ec19-44e8-9a39-2ac610e3f786.json；ID：384c53aa-5a42-4c21-8d21-80510b27dbd6；SHA-256：5998059941f6aa285e64f9f5f3e1dcebfcc60ba93def6f5745302810e4066938
- model-request-08a7bded-3897-42b3-a4f3-afec47aa3aee.json；ID：49afac6b-43dc-4ec1-9aba-eb766a17b827；SHA-256：829c28f66f0b471b2ebffe2a6362dc80f39698385d2dab58d198781ee10fbdfa
- model-request-0a331cf7-ea4a-40b9-9065-1cf03bff7c69.json；ID：6f540264-d4c7-40c8-8031-5b9f9eecd404；SHA-256：f925ad3310c08e38d4a172b246a6decc032ca0ef694d05d557cefc3237fe6559
- model-request-0b9e3d7f-f376-4309-ba59-2a6397cd7858.json；ID：d3ad3346-abf6-421f-98d0-fa7fef73d4bc；SHA-256：7441025fc57de78246eabd29129166b9e07b97db5389d1ddca8b7d3dbaa21401
- model-request-0c9a3893-924a-46af-8e32-2513636f1962.json；ID：5cdb644d-be69-481e-9f98-c17dd358d180；SHA-256：cba70de00b36f17ffdc885aac04a2fa03c4bfcba6456e3e3ecadb83414ce2803
- model-request-10802800-22b2-4742-977d-1305ff1aaad8.json；ID：fe40e3d7-e3a7-4d9b-b222-230e088f6f8d；SHA-256：4b75c287da0deab22400de58c7c98e0f3f0b54726255c6c55234a1e2b9e83acb
- model-request-17d644cd-a9bf-46cf-bdff-73fde5dc3193.json；ID：2f3d4a24-3aec-42a9-b539-cc4b3043a472；SHA-256：d3fe7245578f084ceb225e8e47b6e42da2972678f09e3557640eb313f59542b5
- model-request-1995e8af-2ebb-4366-b70e-421f39bf727a.json；ID：a94c2ea3-3ca9-4d24-be92-88d167a1137e；SHA-256：0ed52d3fb17b17c94e61f6fb5c8ec685f90bc0462c66006ce3ee6e68755213cf
- model-request-1a006b7f-ca52-492f-92d7-b5c7f3139d5c.json；ID：5eec34f4-bfd3-43c2-a176-ff0b4f4f6ffc；SHA-256：ef54c325e126db58beda4a275362ca619638b276d4329964ccbb3d9905416117
- model-request-1d943b59-072c-4431-b7b5-ce7aebcc69ae.json；ID：f85cada9-d26a-41b4-8dec-97df8021cc9b；SHA-256：213cccae5962de7f292e7e5bfb259ac2f02cfb190f9f605b8a8949b3af5d2af8
- model-request-1e906b2c-17a0-4e91-b401-35b4dfaf5675.json；ID：5121f67e-aa6d-4de5-a332-e5e66081a581；SHA-256：e30b0a4c297d8a5d41950bb5c4f9d1e5320e7a0ebbbe81db0d3f0ad8360a148e
- model-request-1ed1bf16-f777-4017-a5c0-f7b0dea0bd9e.json；ID：4a6478fe-59ab-4c07-84f0-3b1c6d245c9b；SHA-256：a3fea2b9f32a24835df251399761b4975af3da2f9ce8834daede147561b07ebb
- model-request-20aab4df-5de0-48c5-b700-4aefc20ce60c.json；ID：85e54a04-e9cc-43cc-a85f-e4d4e91c8bf1；SHA-256：b51266527e896a793d564e69997866807c655f27349a0f1827a0dba0ab3b5b26
- model-request-20b75b7e-6a83-4665-a515-f07568587645.json；ID：7dc435f7-8821-4635-ac31-9b0d98393bc1；SHA-256：099e89277c501d707b91c5cc844f20165234a1f6ee5446aa41595785b84c9f99
- model-request-20ffb5fa-8abe-4d56-b9d5-0abd2a1adab3.json；ID：1656c997-6064-460e-b85a-5a204b54bdb6；SHA-256：5e9ff818f3c6df893b555e50ef8ca5b1eb65f860366a13138974b8b77f614148
- model-request-2956dc40-61ca-4b7d-b5fc-a51e89302898.json；ID：faaf8ea3-ab1a-4c27-8c0b-6befeab575e4；SHA-256：6ad7ad6c1554a4ca4b0eae0a4de5de799b10b46c015a01b5d6d4eee9fc302c54
- model-request-2b403e31-3af2-4401-b6cc-e0d654363a2d.json；ID：bd7bd99c-02d3-4399-9b1d-3a4ef3cb1f80；SHA-256：d8ee088cf8ab92797733f7ddfe303bfb413973183a619b807dd750c13f6db4c5
- model-request-2e78ef77-6b4e-4150-a9b1-212d460336a0.json；ID：606b62d1-2990-4fd0-b58c-65149c4d8a13；SHA-256：2e65e9290477abba3f749794cae0ad8be5d08600f7551fd550fb5765a64c3d67
- model-request-2f075921-a5ad-4d8a-be4c-1a4e561fc658.json；ID：883eeefc-f0a0-4ba3-9923-7023d76ada58；SHA-256：cf8fd8dd4865209d4bc803027f69b38c9e4435938dee544200f1fbec7b2dfb7c
- model-request-2fd36279-0426-4725-bec1-5111fa020661.json；ID：75509cef-83e3-47d9-89bf-c16c3015af86；SHA-256：df9538f276e68ac3ad0dfe0bef7c03ac082e55b0f5208e8192d4800518721a09
- model-request-3253702f-885a-4e9e-9701-0ac602a54fe0.json；ID：b9724e86-5f12-4676-8e49-bcd92045d268；SHA-256：75fa34b4ea71a24fa0324bf6229d5b9faaea783a8568a926d47a9bfde041546e
- model-request-354b8735-e7fc-4c2b-9663-998258f6039d.json；ID：a119d19d-dc6a-48e6-9377-2aa422899e6d；SHA-256：e58ff5e351617f6b0a288db6bf7f8b46a48c3a5fcae94693f2b404e3180297c9
- model-request-36d42e02-2224-4ef6-8eb7-63c186a03e46.json；ID：98cb12c4-9958-44e6-882f-c1644485aedb；SHA-256：9d54cf251a66765af98d0b2268d1bb70e77b859ca2b773aed08954695a999b03
- model-request-3931ce19-1069-472d-a669-9b45f10378e6.json；ID：8d15435c-f7d8-4134-a1ad-49e4de2c7cf4；SHA-256：e4a36dfc0bc73bef58c375e5b9f1f05a2f3f8bdacfbe13107277d75af3e08982
- model-request-3a86653e-1643-4f1f-afd2-a17a560ea4ed.json；ID：6f318ca0-e192-432c-a509-2b0bf4d25fc3；SHA-256：231a6a2989a4a11dc501034bdead46cd34eb3445a7c87af4698bae05b3c80ecc
- model-request-3a8943c8-4e1c-40fa-9f1f-9338598d3daf.json；ID：d04e4dce-aba0-4231-9b23-e2aac7fbae0f；SHA-256：6c7157c1f86ea164ad0a1c19434855b2a32ef0e2d4c199d1ec085288926d3d2f
- model-request-3acf01d7-be20-4911-898a-424678841c98.json；ID：76241d57-e5bb-43ca-a7fb-6dbd333b7ab4；SHA-256：6e243ad0ff9b1460346f3c25825aea61af85563b2d959d032bae2bd5347cc033
- model-request-3c64c1a5-ed02-41b8-a343-eb7e75e6bd17.json；ID：c0ae875b-47f3-4db2-a3ce-1fb26999a335；SHA-256：ad733a4a9ec564ffc51f223fe08a8e82034590166b258bfd403e25801c028881
- model-request-3cb56ef9-d47a-4845-a028-70407731d143.json；ID：3a79a39a-bed5-422f-9a7d-3438fdebae32；SHA-256：9d4925e3dd4dd8562126194571e430960d8201716d8245db9dce46eca537e03d
- model-request-3e636218-d295-42f9-8bec-8b5ffddf348b.json；ID：c38b9f3f-3a61-4360-ac27-4a61abfb7fce；SHA-256：6c6ccd5935f882c9a4a92248ba6cc31e9ba43948c070becc1213c281f15cfa9b
- model-request-3f37e72e-4955-4323-a8e9-3c92acb3ba89.json；ID：7ec691fa-4346-4b45-91be-95ff2a96a95b；SHA-256：c9d463bc6e2f24c734ca860fcd032ebfbb7228434b0a5cc2d672d64939ce4bc9
- model-request-4041cba1-8dfa-4824-acaa-a619387ebeec.json；ID：777f7df4-043d-45f7-8c85-32ce5193a319；SHA-256：5d0a0d5636557e9f32c02d0b21f773c68a51854197749a3d8391f29e47d1465e
- model-request-41baea1a-503d-439f-8357-2d5934cdad45.json；ID：08e12936-19c6-4216-b150-80d6b0a520ef；SHA-256：2961cc5685175128a6fc4ed08bdb5185ff353e77750adf1da6365bfa7d432d7d
- model-request-42fb0936-059c-4616-b544-0d8eba488cd9.json；ID：0cc88388-6b43-48d9-a282-683edfdf02a0；SHA-256：8fabe3a17525e010ff52766f96c474ec45086c0c17651485b65910cdeae21c96
- model-request-44cd16e2-d41c-4956-9d5a-d824f2524b52.json；ID：557e6554-c45c-4eed-b46e-fb380ed61a5c；SHA-256：ffc5f9fc776b1dc59e9334bab0053884895e59ea4bfc4cee7a89903195887529
- model-request-4a8c75bc-cc4d-4637-af5c-e09206be02a9.json；ID：c2bedccb-4345-4219-8ab3-70c1bd862db7；SHA-256：b1cfde2d16453043c3d723197a1c2e3fb3413cfd55ed601152a012aaac8e11ef
- model-request-4bb73562-40ae-456b-b0c7-023a6ba1bba7.json；ID：6c3d5832-cb19-4a5b-b883-e5e66f6b03c4；SHA-256：f8b0942de9837fd64d5e103803f5ae5dea67be890d81ec14a4652d09c5fa3c66
- model-request-508e2f31-7d5b-4399-af1b-c2576293d866.json；ID：af9479da-8929-4454-aa5a-fbe2ea914d3f；SHA-256：a9127e228d4cf493c12444e53ccd51e044aa30730cd2d26952a8ecb98581e594
- model-request-50f32c23-a452-4549-8caf-63dba557159b.json；ID：83a1ef8b-5116-4daa-b2f6-f62dd7f39433；SHA-256：bcb04e1096b9c62dbeda57369f06b3f189edbf4952f1d34e92c98d200b9d24be
- model-request-5300b07f-889b-4ac4-b509-c36f0a54d697.json；ID：a7f6e99c-25be-4489-8ad7-124f00609768；SHA-256：7025d38f5bbefdaecc0a07622280328047f17aca5e466c4d9ea38e8fe9ce801b
- model-request-5432d6cd-e2ec-419c-b5ec-335d525b56c0.json；ID：0fcc1ce9-93f5-4077-9a7e-60944eb4832b；SHA-256：348fb5e50e0dba4b4b4cefeb3497d3852100d8cef0bde0977031420e647a94e9
- model-request-56829277-3794-42e1-b1eb-025d3ac77faa.json；ID：873d7746-c4f9-4029-8b73-8169b69ecffe；SHA-256：8865606693ff19a46632ca7ebd2bb927aa61667021865e7ccf5316f84fefbdeb
- model-request-56d9269f-0e78-4266-b134-1bdec9188abb.json；ID：1a028c9d-e844-44cb-9151-f7473f5e7691；SHA-256：b4ceab3b1c2781702b54a412d5b10d63ac69e65af9f715a46828bea5ec44f7f1
- model-request-5881f8c2-3efc-4e7f-b432-e3bd98ee2d51.json；ID：280217dc-4c12-49c5-b0d2-bd8a924024da；SHA-256：697328455cc7a68f1f7737403b29dbe4e6c29e580244aed9554708c3713dbf48
- model-request-5e0dfcf4-54b3-4858-ae38-0464d0a6748a.json；ID：ff421f19-4093-4e11-9849-99455032ebff；SHA-256：5e3d261147c34eee8cf80f0329f8a6db6b8a9d56e13f351d818071ea4ef77831
- model-request-5e2fa24e-ee31-4811-878b-deb832206605.json；ID：bf650e76-db71-4175-b6ef-08bd8612ed53；SHA-256：a950db3652b40e39e374ce5e3b4e254823292edcd97856df150edc511f0ea3bb
- model-request-5e49a124-64b5-48fb-b135-57854e2ccdb7.json；ID：db45af1c-afe2-48fa-b801-ba7af5d97743；SHA-256：0ff041ac151af607b0e8549d316807d80f4e4d340fa4907a69b9495d77d05762
- model-request-61903fe9-9f2e-45e0-b859-3a749658ac57.json；ID：d716791d-ed7c-4a19-8a0f-7800cde23678；SHA-256：f85217ac97aedfc068ba185a6165e2be78eaedad0763467918940ccf22130aac
- model-request-6b86492e-0915-46f8-b82a-84aefcc6a13e.json；ID：507c33e1-2d00-4230-84ac-468fcf636205；SHA-256：8a8d7e4c285da319f24a03d88a089cda8db097b52a94a010ad3d2c2d3610d7dd
- model-request-6ccaeb40-7aed-41fd-aef8-295ac550acfa.json；ID：a5eeb191-4e8c-48f0-a97a-1bdf805c487a；SHA-256：25ac84c68ecf647f028cb97919c69aa655ef723e4433a10b7a80f4eab3caac6a
- model-request-6fa0eba8-80c4-4adc-a450-18bdaf262b34.json；ID：c64c4710-255b-4e9b-be36-d600a9cc2ce3；SHA-256：4fce864a3c5e6a19fc3eff0a93f30d20963284a315958a7bf67b4e117ee76348
- model-request-706fab28-db2d-4557-bd08-cfa3feb43011.json；ID：7eaa490c-9d02-416a-a525-8dd20f769f17；SHA-256：e65b6d4f34e4be15724989771bcbd875090118660ac0a3d3a16fb2b792548364
- model-request-70db796e-2c9b-4b74-840f-9089ad759203.json；ID：deb143e0-74f6-4ffb-ba06-f1e6562041b8；SHA-256：8f5fa0f31311157301c922dfed450c151deb099ebf717d9691080daab0eea312
- model-request-720017ea-f361-469e-b53c-2d2fa2146701.json；ID：89eb5c52-fd04-49d8-aa82-501ae908e346；SHA-256：2b31707e38dc8ddacf14b304588be01d614c843597b32f768a69eb2e5bfe6418
- model-request-74789849-5468-4c0b-a6d9-08fdbad3739e.json；ID：65d26cc4-85ad-4144-8f0f-de187e1a3f09；SHA-256：3794e5e5f7931f03429dffed28a7b6da982d9201c6b15e5b7e274c2eccb52712
- model-request-75897325-6ff5-478a-a92e-08c847c6d003.json；ID：86b2a400-429a-4b03-9714-9eda70d413ad；SHA-256：fe7caeff98d80687822aa0bdc8864f6baedce57019fd15479d0a36653e9ff9b4
- model-request-7a7b360b-cca4-412f-82d0-84a409639302.json；ID：727178e4-db26-4e01-a1b0-5eb47cb37551；SHA-256：1b3d7a05d420ed1b52ef8d5aa61c124ad9d34039fde1f3a66dab43364db0fa3c
- model-request-7ae48511-972e-431a-8a73-01c566f24b97.json；ID：d34e792b-2182-4377-a85d-ae8e0e580023；SHA-256：308b9456649554f345d4200c43001d079e973f4ed4587dcc91029870bfa84226
- model-request-7dee7a6f-fbe8-4a21-b4cb-1337d13970cb.json；ID：1e9c82d8-4784-4bb6-b176-7e866f8e09b1；SHA-256：077e02353de07b4fe423b8f1ceb03adc9c318493ccc2c69574c2417e7e9ece6a
- model-request-7fe7a955-1f18-4451-a413-ef01f48f606a.json；ID：3f9e6f3c-de12-48aa-a579-9a995b78494b；SHA-256：15c48bbe599e0dedba6a46139c15c307ccf69e6376263519c17f181e8945c947
- model-request-81652fbd-3a75-454c-a5c4-029b34816c23.json；ID：540df935-f745-4c7f-a083-800ad7d89237；SHA-256：90dc91a345c537962975f36b5b7c8eb9fc274f3cae8b150eb383c15f275157e9
- model-request-82628653-7602-436b-84f5-4daf5a21ad90.json；ID：920f4c15-5c14-4ec9-bc50-45c5394253d6；SHA-256：25b75c14dbbdb21fb87644313c3a6674f24e4d7af59629549e2c27d88bf5628d
- model-request-86cc700e-2b72-4661-a298-6d52926319f8.json；ID：8cb7daf4-4af1-491e-8651-681fc16869cf；SHA-256：db9bf8360e5ef2f16e11d82d4844195371279e513537b2c113e44272516fdcb6
- model-request-8a115005-294a-4f71-a4b1-c25691c654d1.json；ID：f6b6643e-c9e2-4fe2-bb9e-8cdb9630e173；SHA-256：7d04435bec1e9581641fed752575719cf1a8dcf2f4ba94d312741d11e3d9d585
- model-request-8b326726-732c-469a-8420-fc6ce5684a52.json；ID：d674ccdd-9aad-4bc2-8d29-729d13837e3a；SHA-256：f59d8abbb4324e337cc4e5683a3270ec7e319fe725239a3b0082c1de0a8d18e9
- model-request-8db5c6f0-356e-4d6b-9582-8496bf797f97.json；ID：032873c0-692a-4af7-8661-85265cd6c0de；SHA-256：146ca8cca269487fa791dfa470d71bd7bd993e583dc5073d32911c726e700fb1
- model-request-8eff5b74-ac33-4bb3-a479-4d6498c7b120.json；ID：3131799d-5b09-4710-9b1f-bcd219616ca5；SHA-256：ce5c22d90f7aeb6a6058d061d633fd3a10ea0bb1742da035200133cf61eba171
- model-request-923fd5ff-703e-4fe4-8942-15d9cd04528d.json；ID：c5c73976-bb68-433d-9849-ffda94f1e137；SHA-256：6a7dbbc504de75c5acc04a43e70a064d6e2ffc01ff17c75339b94416a0240ebb
- model-request-9301497f-cffe-4498-b76f-87ec9567a3a5.json；ID：ebb63479-6ffe-41ce-932e-5ec7f8933a7f；SHA-256：e8f64a19a7908e25468674dcd15dab8c31ff7b7a4064b5a13a7b0be0c4d6990f
- model-request-93d3a80b-1390-4966-97b1-2fdbf374ef8a.json；ID：20de5fdf-16fc-4246-8b28-9f040014d45e；SHA-256：b0eb007de435dd9b7549ba1cb6de99d57e31f80131dc9dac406e4f3cd69a02b2
- model-request-9768921b-d557-4652-a19f-36185cf0cfd2.json；ID：07aefc0d-22c1-430f-ac6e-d396e3ffaec9；SHA-256：ab649267d61dd2ebfb16fb0ce4319720c8a610e01091fe7873fdf4f642957f23
- model-request-97ebbcac-974c-494a-b22b-457f2b570dea.json；ID：0e951b9a-315b-47bd-b619-d55cc80e12d7；SHA-256：d7c2e6f452782a721ec45349df10eb23a3e023e5737dbf7bfbeeffef5d838be8
- model-request-999c6c84-3d26-41a3-bbc7-455db039add4.json；ID：2d3ffee8-8088-406d-8127-6faccacab293；SHA-256：dd4cff4b533f3bec6abf7e534dc295fc685ea7ddf9cdd5c74f7b055a6c9a0196
- model-request-9b923725-d36d-4159-9569-4e36b689f6c5.json；ID：68ad4afe-008c-48ed-87c1-e27ba9bb9fc2；SHA-256：b20f92badfa77cd64c57551631e275cc88376534f681743154a8224f3b9c871b
- model-request-9dc21e69-2a3d-4ff7-9a17-6264f32a37c6.json；ID：97336b45-7156-448a-ae5f-91df43f762bc；SHA-256：e0be42d9893d798b1aa6990204e5d96e45b843d9df8a27c105107e492fd5ee3b
- model-request-a093c7e4-54b2-4ad7-85c5-df669c96abca.json；ID：e1679027-70a5-4937-a2a6-449daf0ec945；SHA-256：77bf2bf06201e80dae8cc304798c885ea35a769fa5e4822d78bf80889b91a59d
- model-request-a3571ec3-7733-447e-8573-f307617ab9ea.json；ID：d6a0f722-bf86-40e2-a7cd-392a7075d1ba；SHA-256：6a2b8ee2647cd9b306d81e6992b3e55f7744a5e1389e2f99d33046bf3b20de8f
- model-request-a64a00f9-6607-4f56-8b78-053b76748bf7.json；ID：04163f7e-4ed8-42c8-9205-7d255d3e95ad；SHA-256：159c3e8886e578d9d1cd115b8180aea70694d2a1a7972132bfd1d1f5dda1734d
- model-request-a74a74f8-dd7d-4f25-99cd-ffc7eebbd363.json；ID：faaf6ee6-3dfb-46db-bfa2-30c43c199131；SHA-256：e71b122c2f3b6746682854400efd156fdc22279a48826df4d6f6e0df7023fc74
- model-request-ab747c0e-d6ec-41b9-ac5c-4ca8f6cba197.json；ID：2f0e30d4-4cd0-4bc8-927d-7b4515e74cfa；SHA-256：1c464e5ae2d91dbcfb2a224dee2d996f3968c45f90c60261e7a742fce0b3fd35
- model-request-afc1589b-d66a-4566-b5b1-5b0938d5d706.json；ID：d5ee7c31-4452-40e0-b376-eccdaf43e3a1；SHA-256：334b9ad06b5456a7930c39536cd2e56b53abc6c2f0e7665c5cda6cf318a70703
- model-request-b2492d2d-e7cb-421e-b8fd-e95ffd81688d.json；ID：c6af0acf-9924-4d3d-9754-fad023cc593b；SHA-256：264b31d44a952db46d35f29243e4d73c0f18b603cd67480c9ff7a9bc2d742fa8
- model-request-b72dfb7a-1ba6-4ab3-bdf2-52be18d14a29.json；ID：485beff5-75a4-4d62-8f2b-b43cad1e502b；SHA-256：904631babe3991c16ce896ab458cb9fe8f54ddb173156bfc35fa5f9710c58563
- model-request-bff7f9e9-7aa0-42b8-8eda-8187bb5ba747.json；ID：af62cc24-76c4-4af9-95b8-25ab00799552；SHA-256：8162d559f73beac9ea8e0f45300f0f02cb3924264adc9a5cb0e5572e1bb64179
- model-request-c1e32f23-7b32-463c-afa9-b3d058ec6729.json；ID：6e0f5364-b12d-4c69-83af-f5e7194dbef3；SHA-256：8a36f6e110bba1e65dd3862ea42b72a7643b235113bab793e5a740d26fc56113
- model-request-c221e8d2-1af4-410e-8698-19e2ec725cd2.json；ID：03870fbb-d3a9-4d36-bae7-d33e0bd31bde；SHA-256：16f325d622c0760a8bc3a18c187c1c6fdca1492cb094c50559d8ba86e3d6246c
- model-request-c87cf41a-453f-443f-afe7-a64537d51500.json；ID：62601ea7-e431-4c86-a2f7-5a4763c97491；SHA-256：da0fdfdc8d60e3429adef9a17fd58526f53767e42ed0f8c7366d496baf4af741
- model-request-d1465a67-025a-43ba-95d0-8710174b2c8d.json；ID：b5907e94-b2f7-4d55-b9ea-e7e0dc03f3bd；SHA-256：3d2325b1d762840ce2c7633132972a4d0ba079e246a0770b5d3f866724387b00
- model-request-d38f3bbd-e4d0-44b7-806d-8d5f55f706f0.json；ID：9935b2a0-b924-4b4f-a142-8fbefa64392a；SHA-256：ce75e49d6ccf9efdd4eb906b319d7fdebf987d080966384ec89f850bb4f79632
- model-request-d3ea2d21-ba4f-44a6-b203-3aaf48692504.json；ID：3fe576b5-7c9f-44bb-ba21-9edd53fdd2aa；SHA-256：2b78e6c347c70f410a6e07b31b10a7903a98002794f9ba03311a4407a0b3d42c
- model-request-d897e899-4098-4f31-aa07-42806750fa27.json；ID：cc0b7c65-5a7c-4002-95a7-3f55641d7fb6；SHA-256：80532f5d7a8096acd74f28a617f5420665204ad144aee07d8fe1d5c29e95ae71
- model-request-db3ba412-1b3c-4c9b-84f9-930b9bead863.json；ID：caedfd87-e801-4e88-87dc-a0f59714b49e；SHA-256：03415e7f2914849ff0ce0b1f6b73ef47e676128988eec209c8fc6f7421b43cfd
- model-request-dd102918-757d-4f8b-94d9-2a344e702443.json；ID：575858b5-b542-4675-9764-e5c6b8b549e5；SHA-256：09960a3c8b6e115825631cb7055583a2aa81879b635fbe8d3413a773d3efa779
- model-request-dd3cf603-ae19-4c84-b4ec-d4098b64a4b6.json；ID：f0c56404-159a-4d27-bb1b-51bee87facf3；SHA-256：982120ccbfefaf3f6e76a3d28233ebf04e69dca5dd7d1063a65fb838dbbabe85
- model-request-e13b0de4-7e79-49d1-989d-f5026e53242f.json；ID：e501d39f-cd13-4958-8929-8d762ddb73bb；SHA-256：9df074c9289f3a75d9290a6f0ed60dc000310eb848aaf721412a900a60ca8524
- model-request-e2bc3b32-5d71-470b-bce1-897ae8d2b746.json；ID：192a1e5d-f2c3-4778-95be-af50bc28d7b6；SHA-256：36ce011254462572fd8342f989efb84e07866c45a19595cafbd65c270b998ce0
- model-request-e41dcb39-eeb6-4c80-aa66-ad6a8bc73487.json；ID：96dc0dfa-3d85-40d6-b9da-8e636db0e7bf；SHA-256：ec776ee0d5a3f13902112aede59095af3f624f6475c421f12987c8eddbbfb0f4
- model-request-e53183a3-faf7-4f7a-841a-a781fda44466.json；ID：4f69f3f0-4df1-43b6-8edc-45c5b75a324f；SHA-256：4ca0297b7782d0f48dfb94d5f94cc3b4515ab44c6b4fb3939748bb0b306b1b5d
- model-request-e9f2e7fe-2bd9-4797-ba7e-792edca2261d.json；ID：be696851-b1a5-40b7-827b-4562af818837；SHA-256：8f673cfde3824b335a93b60bab1a26065c4bdcbf7c4a6260aad899bd9adea711
- model-request-eaf91553-0c11-4bdc-b630-39f74fb21831.json；ID：6424d5bb-d352-405d-85cf-fdc6f981ead5；SHA-256：fbe0520ad6505ebddf2503d843a80dcd7c37d440a8401a69ce7d23c2dc2cb4ae
- model-request-eea7e721-90e5-4464-9cfb-2e7e6e8f37d3.json；ID：19dacfc8-2538-4cfa-bd6a-0e012a3c6b79；SHA-256：80c103931a0d9e53797530ca291852f8d737664b50328b912dcf3ddc30913d58
- model-request-eeb7b54c-1a49-497f-b4a0-0d9d5d0033ac.json；ID：aeeff905-d99e-4d2a-bf79-0515a0f28778；SHA-256：c9da6bf1d84010553bc379ea7185e15f9861eaa039744d8b8e9ffae1ae693999
- model-request-ef7010d0-f84c-43a2-b091-2fd429bd894a.json；ID：e9f63992-74fa-4b81-8dc1-66cce361a913；SHA-256：ca85e27e37ad2d2d33d83b7e9d86a793122ed92fdba08cdb35e52b21901aad70
- model-request-efd78c32-1339-44d5-92df-1df8cffa942b.json；ID：879a0d0d-6e31-4ec3-a214-b536d0da0624；SHA-256：f8142fb8dd631a3f976f3155226c27b9df4c40f6bb8dc8901108434304b10054
- model-request-f05f6c6b-9269-41e8-8acb-c516a0ec560a.json；ID：2cc3d39d-3ab2-4bb5-8d0b-189d482e4598；SHA-256：57afba9860914e5eabf6020393dbe508933be132f1debddb41e42135b4f4142a
- model-request-f70d9898-c667-44d7-b526-145b96f78977.json；ID：fa13331d-9d0a-480a-9600-1f281337b79b；SHA-256：531ca8c52034ebe9ed3640cfc9d0358cea9ee6f214d64459eeb6029c5fd3702c
- model-request-f9c9ce8e-c182-47f6-8e05-849f2681abae.json；ID：11cfc63d-13d7-4ef3-866a-1adf577eb2c0；SHA-256：845b2a5227d8fb4935a86f3aeed4d798dc6eabec9c258485dc2eed6d161af528
- model-request-fcff6495-0f0b-407e-bb8d-69ceb3fdba63.json；ID：de6d2e8b-d4c3-4717-bc2d-e07a707b4179；SHA-256：540147f585daa12d5e7d9a396885846d6a914927972a812e79588be05b9d1832
- model-request-fd1a462d-4aac-4333-b9eb-0a96fbf30ed7.json；ID：61669919-9e3e-4f56-b98e-8b9ebb3c7f26；SHA-256：302ae0cc4ce5f8c5e76c0354cbb2cf032cb0f6d37e302f9ab5485b9e885d11c5
- model-response-018a61d5-edb3-4d9f-be2f-18c55a8bac82.json；ID：7006577e-fba0-473d-a1ea-ed251cc8375c；SHA-256：95a0cfcd78007aedd0b833c69c9840d17cd9312576456b3fd477d3404af5cadf
- model-response-035bc67b-21e3-45ba-9e94-aaeca7492a83.json；ID：c4d420e3-0e59-4e8c-987b-5b38d8f8278f；SHA-256：074074bcc72cb068a13df4a638e4503be66b74f52292133de4610550ecb0b0e8
- model-response-051e69af-2482-4aaf-afd0-1d5c7d173ca6.json；ID：70cd5603-7c4b-41ff-b84e-49359fe4714b；SHA-256：21bc1b89e03aaca0b74e484069ae2ef0184dc422c7d21d1daf6229d68ecf5cb9
- model-response-0540820e-5efa-4045-a4f8-c5deea8ce25a.json；ID：75035ef8-7538-4bde-98d8-a2bb58272def；SHA-256：b363ca1c597562ae745557a83b34f1db4890187bc1363fa31c222d3fa4331e0a
- model-response-07a70cda-f718-4e47-9453-cd373f24c294.json；ID：99415bcb-dc64-496a-a9eb-188f505f703a；SHA-256：98f0e9688b9141a79de2f8b43b76098472b949a8e89e78fa5d7b2f46675ca1f6
- model-response-0a868633-38c7-45d7-b994-d1fd709feba9.json；ID：59125959-1805-4ade-ab1a-a80cae0a8420；SHA-256：bd27925596a5e96e19137de1ec65435381bf9b439e9f80b4ce909b0956c51b5e
- model-response-0e277eef-85c0-4042-b738-9825c166984a.json；ID：7be51fe0-af57-476a-a28d-a341bbcc8a37；SHA-256：b0e8ce35b13a553675d8b3d7578122a96fbdc9871d6263d498fc404012f4e01d
- model-response-0f6886b9-b190-496a-be3b-60b3b8ab3768.json；ID：8e91e4ec-c6ec-4ef8-8aef-9b3eb9f436b7；SHA-256：b7ae46288bea710993c1dd0689d5706bddfefa14712c4de71e401cdd70bba83e
- model-response-10d434d7-3e04-460c-9643-43a7bd6ff8de.json；ID：3538e2f7-1374-4e2f-ada6-b22661b16aef；SHA-256：ac29fc4252231fe61f76c761d4e50dda2a1ec9b63281e3d43d916bfb2bbe801e
- model-response-165e104f-f6ff-4606-9056-bfc3c7be5b35.json；ID：32b8fcee-df63-4c4e-9024-2662bb8c8a74；SHA-256：c1d614e795989f4d893e8d12048fa4229821cb9522e9028b3386ddb30aa1f63e
- model-response-17b40f98-5186-402b-ad3f-cb063975e1a9.json；ID：e535f34a-8bb2-4bd8-a900-eb7ba72df74e；SHA-256：ff3935d8929f441b61ea38871339f2ec83e92bc4df9df1ffb2cd6f39540700f6
- model-response-18214421-8cdf-4065-a585-5d53921abb04.json；ID：b32a896c-0e7d-4657-9d4e-d395453bb3e2；SHA-256：763639ad32019d2d1b5057d13ff6126b30a7f94808b6d5c931bff00995dc7e78
- model-response-1b612079-0d55-4e92-bae5-29bacf5b556a.json；ID：3dd161b6-6415-4ed8-a62c-0dea079b1a9a；SHA-256：a23f17604b7c5cea08ee168aeb378581e2d313c6ff55ddec6d90e35e43517bc1
- model-response-1b93f419-438f-42d9-8546-aad15147cad8.json；ID：32dfe981-c0fb-499d-b699-9db11c2db9b2；SHA-256：0f30d564727383f260ba08a463fe88dec1881657dbf3f6ebb49d627156eb9680
- model-response-1bedb10b-03cb-4f06-a5e3-f93952b9dbf3.json；ID：41015c08-6392-4b44-b085-5113e5b0e72f；SHA-256：1df062dc246c3695fd3b6b69dd7ee3b1d607775a21650482458b3039ccaa6712
- model-response-1d1c1678-3f60-48c4-8457-6e00acb79b2d.json；ID：c12a7a80-0e64-4a33-9686-04da2e3e1298；SHA-256：53c8011cf91cd1f00fa73bc27497ac055974012a779b40fa2dd4dfbb7052686c
- model-response-1de95961-1ae5-4d8c-85d5-307f3b933b27.json；ID：051a0ad8-7195-4c41-83d0-e782dde87cf5；SHA-256：4e739195adc0d12f496cf2cf98ac524112c6d3fbc3228fc5b07c6150f4a413de
- model-response-1fcbbc1a-c33a-4b81-b295-13b2c9d21bb5.json；ID：ad78f959-d3c1-4d99-a6fa-990c8efac8b1；SHA-256：ed95140910366faa54b424fabf7b0bd2a8ac89be1e73f2d320a385fa3b27052e
- model-response-208d7bb8-29c0-4a85-ac53-9191db6e1d07.json；ID：327d5560-d4e5-45c5-8497-11719db595ae；SHA-256：7333f63c87b2357d2292eccb506a2f60b3aeb0545ae40fa3ee812deb55afe98d
- model-response-2139c98f-1625-476d-b04b-323b1e29ca59.json；ID：4725c3ec-5883-48cd-b2e5-73f84f5976c0；SHA-256：b9e7ce9ac6547eab7d81302a1f88adca708d6122d61d631a29fd9065165b384d
- model-response-23f3bfcf-b225-4304-a37d-10e8d51f3c13.json；ID：9354c37c-217c-4673-aed9-2c9667754db9；SHA-256：4e0f12dcb431d9c154d478465338900e09dc9a278feac9c635824537dcff5f86
- model-response-29968172-5dab-4c69-af32-2cccb99433e9.json；ID：d31d93e8-f2b3-4dbc-ac73-12d0dd810c99；SHA-256：9a234a9e50e81ad5923ea33129901495a750924a10179ad213adc77ffdac4217
- model-response-29a2a063-ee11-40d5-8fde-c98c168ecc77.json；ID：467b8f8b-ff2e-4cbe-96fe-0b034862b869；SHA-256：3bc2b5efbc6db2dd1174fb83ceda4af17d893dc2f59765d843c0aec95c54232a
- model-response-2a76255c-40a3-4fe3-b180-3f75d04073af.json；ID：9c6934e6-971f-4cf0-8f80-01b88c11ee1c；SHA-256：2010d03d5f7bba85a0588fa998502d2a1f128b45f23185b015f8d3e4b5b21088
- model-response-32da82a0-4fc2-494b-872d-8a38281bce79.json；ID：d1ae137d-3377-4fdd-a016-31d690eb9f76；SHA-256：7269702854b3121d4359ef14097b91e03e0f406559227d5f8b6409002313b94a
- model-response-3485963c-fb0c-4998-8ea1-7e4d6df6a9a5.json；ID：9ffb9d08-a4db-4ed5-958f-7efa521f75e3；SHA-256：495468dd59d817877cc8cf75990fb4e8b9cc300abac05e7a06f0edb251e16710
- model-response-3d18f0ee-58e8-44e5-84bb-cdd557c89985.json；ID：69d918f4-b6cf-4f61-9303-9e123dd93e26；SHA-256：d76e014dfe8717814fd9b10301c488a3e0eb83579210a1ef9324b239a4d7c57e
- model-response-3ea7c3a3-1dfb-49ff-90fc-2ea91567c588.json；ID：199080ad-ee36-4dbd-8849-9094c3e62185；SHA-256：b0f68c876d461edcd848becac05902221f75399e5f4aba1ffa9aa0c3460a1645
- model-response-407a6d1a-0e85-4f46-b98d-c35fd8a25ac1.json；ID：55dc56df-f279-4431-bdf6-ca7370e099f5；SHA-256：914fa63f534ad52e9d6d88057378b64c572b6ae407817a16a0142d855cd04fd3
- model-response-457fd9c8-12e7-4302-af80-31c6111e465b.json；ID：4f295348-8709-47a0-978e-b09b2df8baab；SHA-256：43a2af1458bb7eb4c07f15bf9f5a96231e437407f7809f052ee3575342521aee
- model-response-4bc53078-fc1a-475c-8e7b-4b89e2c60aec.json；ID：0dc28fb2-c8e4-43b5-b54e-d4dd7916e767；SHA-256：46ef23335d8174df0e309810a62c83e3735f82a1c68f7bdfd7fc677534e93dd3
- model-response-4d3d173c-4a77-4c4c-a1ec-987bde448175.json；ID：b5a8e702-8de1-4923-8063-e856ab5ec214；SHA-256：c3f5d311527300b819e5a9b0cd3d2fae33cfaa5a903cd9e63606667892662d2c
- model-response-4d91a564-4751-43aa-8055-7d75eee3d856.json；ID：76bdb96a-2652-4430-b4c8-c70bcd2c3a83；SHA-256：8ae432a9d9b637328069a4a6f6f4628865df85169b87ee08e12fc6e28b2fbfe5
- model-response-574e77a9-bf14-4b33-b391-b208a43d99f4.json；ID：9a644356-ce04-40a5-b845-3d6c1dd236ee；SHA-256：2ca9565bdf0b0c6ff98dc250d09ecb9d4ccacd46a5445bae23e360af56924aa6
- model-response-589722bb-0916-4686-8960-55a315ac85c9.json；ID：1e805fb5-af60-456b-a5cf-bceb176140ef；SHA-256：f3a39e6df3a68f72688e36ec7cdc693d761d0e419c9d05f32ce8db3ce819aaee
- model-response-59e9aefa-6e67-41dc-8cb8-27f06f17c3f7.json；ID：e139bd00-3888-4787-a0fc-37c761298fe0；SHA-256：7aeed2c83836a30e50f8a2b3b45d4a5099e2065986a4d1e5428dff3c82438056
- model-response-5b554326-a72f-48db-91fa-882c13c03fa8.json；ID：76743e6c-9344-4f8a-ab98-468c844325bc；SHA-256：cd92dea5ebd2014b9ea241207d6d12fb4b016bada52fd4d971bec38e68fd9de8
- model-response-5bfdb86e-f025-4583-8c09-a8c80c901c8f.json；ID：980316f9-5606-4223-a33c-06c12b408a6d；SHA-256：5c4821ab2ddc0831b9c7a7dd2695b908feb0adcb75a4b7c528d53a994d5e454d
- model-response-5f28fdbf-b1fb-4e0d-8995-d939a674a249.json；ID：695df93c-9462-4562-8e17-2394474a6be4；SHA-256：67c9010b5b39f58290e2f5b674188d001411ef2123e856c7d73b1c8a58f9c977
- model-response-5f60411e-a4c8-4d0c-a5eb-f23c2c5d5f58.json；ID：ff7650f6-6456-45ff-bcc2-335cbfcee5c4；SHA-256：547166c8bfa6a4642adef717634dc4f58dca31f95dfc5c8886028c19e302cbec
- model-response-6038ebc2-bac8-449f-b9e6-850ba1156b23.json；ID：71f50d9b-da24-43ae-999a-ff39db99e823；SHA-256：083bd5156e997505e1c6f3fcf22658618d75d8e29460875ea3af300769b1a236
- model-response-606427b1-8cde-40f0-9c71-3a3dd58f9e81.json；ID：83c6c73f-03d5-4297-bd2e-0d460a947ed0；SHA-256：d9a05d73503494f72b6591916f5f60aa20243a6d19f2cc8f4bf825f2907b4748
- model-response-6775c4ee-3364-4924-972f-f3a7d0c1c228.json；ID：711aa5b3-9e38-4212-a6f6-8da16d8885b2；SHA-256：1ebe4d45041a6abc040f57f4a1dbf3163b3bf27250bac63e13599fbcf7553b3e
- model-response-6915030d-96ce-42b8-81f8-9eb950ca3954.json；ID：ffff43ef-65c4-4aa3-a3b2-40e35567dc36；SHA-256：533a8ad7c84461dc3e5a7fd4a678378bf841ac8baad65970857405695c0c731c
- model-response-69e3fe77-4ca3-4def-b1bb-52ba73226d9b.json；ID：eb53bc25-412a-4191-862d-305cdeb60f00；SHA-256：200b24c78f5f83c2480b3178c6f35756563094cf7d00bf4a5fd4e170dddb091a
- model-response-6b3fbfe2-15c6-40d4-a19b-d22f0b084a0a.json；ID：cc1eb9c2-5366-41b3-b395-621d0b5740b8；SHA-256：fd2ea68746117c276cf73075a4f74864e84d354908506e5d90a4ae894551c845
- model-response-6c333ec0-5a9c-48ca-ae51-5310d2df4ea0.json；ID：8e47c9de-276d-44ff-9ff7-d1511d30b05e；SHA-256：1a188d8c28664757c8c2d8f4cad55690a726f1e4fe537a0ea7d4f8c83aa4f18a
- model-response-6d3eeee7-7665-4004-a6b4-6b0f9daf1f02.json；ID：33b08c0a-d984-495f-8c39-e5a2a1167813；SHA-256：d2c85acc89f2b4acd191aabdf2aaee6c156aa6026a9b48e16456519e8a79a040
- model-response-7176cf05-0517-436b-a7ad-9f04a0b34398.json；ID：0d3ec91d-0973-4dcc-8b82-dca046f3d0ee；SHA-256：788ca158d4f1adb033626de3eba9423a5777a633e037dff55a34f1153b539225
- model-response-76413f87-9721-4070-b874-3bc7687de34a.json；ID：5b6d949d-08e2-48a5-b797-1afe5379f77b；SHA-256：33a49bc59c26a99c02ba0d6aa63f1ed07da9dec24b4c457b302ef47bff507151
- model-response-76f3e660-e283-4930-a1e9-725e9f9542cc.json；ID：1b96b3af-773d-4404-9b64-5d0f7a285fe7；SHA-256：4a6327227831038bbf18afffc7ca1b5a4a19aa3c04e09a20ac49d6a0e0b0a580
- model-response-7ae0f843-eb92-4c9c-930d-34180109b034.json；ID：79865db4-383c-4a52-b9ff-495acc229eda；SHA-256：e41f9fa4b16ffc1cf1357f3d2d8ff477d13162a0bc57e0a4716ed9aebc09cf8c
- model-response-7af3c42d-b8a5-45cf-8a60-fba569da1fcc.json；ID：4ff4201b-4540-46cf-bb0c-c8fe7adf43c1；SHA-256：0336ad4a22c3783403511effef14ba413089d7d0491c7b27451051d35ae52e26
- model-response-7c71dbe6-c621-453c-a0a8-1c51fd605e51.json；ID：bd335a2f-a7c2-4335-81bd-d1f95b11a015；SHA-256：f8a482cffe8cda600f7a0581350a3a4f7b2cb1ba3b4ef959b9e606944a693bc4
- model-response-7f5e3ae0-8450-4c70-b9b0-c88316adf1a4.json；ID：c526040c-ab76-4593-b28f-86b359d38c06；SHA-256：748e7b3ebe03554c69a7cdd3094a17d5f876e5dbc2f86df28734dc12571e5aab
- model-response-7fd4a677-ead0-4683-bfd5-89f404fd5f57.json；ID：68f6ae88-6d4c-4e0b-bc82-e56206f7c7ab；SHA-256：60984194812fed6411946173a93741c4d099d56a4b698132f5f1c06a8f01ea41
- model-response-8338b25c-7b61-4932-82c1-478036031b5b.json；ID：78bc9345-cb08-46f8-875c-dbc4045b568b；SHA-256：21a9f7e6790c0d3f36f56b04732f233bb40ef5f77ebaf10fe941ef506185d0dc
- model-response-850b7661-8ee2-4f31-b63e-60e7503ef1e4.json；ID：faf354a1-8ce5-4f8c-bf0e-c170a4295e86；SHA-256：f2b606fb242a56e89a146578e79f11f1608ca0a33ccffd4fd96b574a011eee3c
- model-response-8836bf5c-25a5-45ad-90f6-6bb06763f0a8.json；ID：65682065-3040-484a-bb57-cbb4732aace1；SHA-256：64b22738564619f6d68d21db531797bb9e209fc672da4924ceef45ab0bdd69c8
- model-response-88fd0897-535c-41da-96af-4908c827e789.json；ID：cd3fcec8-3b70-40bf-a135-92ff6ccc6eff；SHA-256：ad4904caeadf55eb356fda1f16a600c72cf67fefb6ccd2b111939a8961087303
- model-response-8adb8f07-c5ed-4d16-a3b6-5a337c5ea1fa.json；ID：dab5d51e-56bd-4a28-b810-68043ad426fe；SHA-256：f47e2785677e3c7a2a147c89dd19f3779f84a72fc40d0f1ac6026af0ae53f525
- model-response-8ca943e8-a2b9-4743-92e5-bd264c16cb07.json；ID：42d98d22-80db-4408-b7e0-5235bd57e8da；SHA-256：fa3b9098faeaecc1a77550b21c4bd1a82ce88018266a404b3ea3e6b052a025bb
- model-response-8e52c8c1-bc62-4e53-9d18-feda36f510b5.json；ID：ddb0a686-a946-4a6f-9a63-8ac228fd9393；SHA-256：e7409325fb050558bf7f0d152bb22859d234f70b0a82656b113f22d2e99e42d5
- model-response-8e8978d8-b73f-455a-878a-0af7476802aa.json；ID：cb781dc3-5486-4f45-9973-96bcc6c2d012；SHA-256：650d04d7897526cfb3e6999bbf45971e70ecb2c5b78176fc7ac1c86d4e2ff70c
- model-response-938cc296-b8c8-42e8-8fa1-0f7813290665.json；ID：bc24c29c-6714-4563-8138-6c71b8f04aea；SHA-256：f220525e343ce0c4a0eb2bf37c07583b0cbbf048dcbcf9f0c07965b052f080e9
- model-response-97fbdbda-15b6-474e-895c-075e15f5f2b8.json；ID：eac0c00a-f44f-492c-b6ab-39c52461ffc7；SHA-256：a67f8d6ea75cec6c2e8be3ed81d6c31c776d6a6f785314fd6aa6f03b5fdf212c
- model-response-9869f3a0-a4d4-4a12-9fce-f4ffa6b865ff.json；ID：25dd3d2b-4742-40ce-8a0e-6cec0137d3b0；SHA-256：3f34e468875dba88f309277a502672f2957d186ee04faef090dc91f794124190
- model-response-9a472615-33c0-49ae-aca6-7625f7537709.json；ID：89dff4df-a469-4bc8-80d1-df7dd112bc3c；SHA-256：3bb87ceebb527fa029a776159656fbd949e90b080049b66ba6cb6a71abda52df
- model-response-9b170ff6-889e-40c6-8f4f-25928ac66513.json；ID：1d0c9343-46a4-4d64-a332-09dd8c80b1e2；SHA-256：5b3df22589b31214669c76dc7ce751fd5937e6bc5bc1cd2c8d47e7134cb0d7af
- model-response-9bfdbcc7-730d-4492-9867-e61caa91bd90.json；ID：129346ac-1625-4887-9631-ef5bb8d5d8c7；SHA-256：4c1147949dad382ddd59748560c5d2baa8241bc249f45425aa185a60ffa14ae7
- model-response-9c741cac-a41f-4f09-a906-664655baa2ed.json；ID：0f767d5a-cf16-470c-8cb9-6b6fca3a85e6；SHA-256：b666688ebf8843afcc901de6305f2411e36744eb036d313b717ffb323ee69049
- model-response-a09a0c1c-1196-4b6d-9c72-0fa81784db4a.json；ID：1e112f05-797e-4732-906a-4d87039f91ce；SHA-256：e4755324db368ec1749c365529cb0300560646d1f0d74d9633c04f8f0794a0c9
- model-response-a68f5a0c-1ad7-4504-b243-a251c47080ec.json；ID：4d7442a7-0300-4460-a293-0e685a45f349；SHA-256：4d0bfaf773bca28511c9602f3db57702e2b375384dc6b682c92ac0a8f4c54f98
- model-response-a70da7da-e9eb-4ae0-8190-b07d66587f0e.json；ID：66b40858-eaf1-4d36-9963-0e9a19009e76；SHA-256：daa378107cb95f8f822208a0278cd7e12484497a0200951acf7a475b5ec75800
- model-response-a86e976f-8b47-40af-b605-5f5e56f8b25b.json；ID：176c6783-b91e-4826-966d-17fd05bbe44f；SHA-256：a0ead3d49b3c5080f01c0176c7df6cc4045d1a80dc6e21c7233319551a07d6fe
- model-response-a952f079-f37a-4ffc-adda-2e64d9b05ae7.json；ID：5d61e0ab-9e75-42a3-a9e3-351c79a4e454；SHA-256：b498c727421da295f5151a95ebd7048390e0ebfdc9957f79cbe7c62703694f5c
- model-response-a953c6b7-5c09-484b-8ebe-cc4ff761d932.json；ID：26c97267-7d32-489c-a91a-2ea014f4face；SHA-256：a47ceec257268723b33698414cafac2be1d216c485decca35d27e7d66b1f9768
- model-response-aaf72441-271c-4bee-afab-acc39186163f.json；ID：f2e53ca1-551d-4011-8324-63ab119e98aa；SHA-256：a2e1fb0f44b4e35907b8eca80bfc6b6caa36a7fe4a9e11ce0d88bc4eb9431fd9
- model-response-ab01b5a2-0eb6-4848-a716-ab68266a3902.json；ID：d70f53da-6b0d-4729-8c39-d889225e7f9b；SHA-256：688e97999906fa0a19bf9dd5102cd3078835dfa4049293e06a52c538b72f65b1
- model-response-ab1c5974-b3e0-4eac-93a7-581abf862ba4.json；ID：58ca50c1-30af-4632-9366-7efe70564488；SHA-256：9939151b4c7c7c3790000a2f0ed0d0d40c010e6ae81352e0f54e8f9b6342f6f5
- model-response-adc8732b-93a8-4c7a-b604-eef96b4c7980.json；ID：e4a2e5de-2d68-4cf3-a58a-9b8ddd084a0b；SHA-256：58d47e47c8a20f496bffa64292090028bd9ffcd46ce1059aaafacb499396ba4e
- model-response-b341851a-701c-4b0e-9641-67ad75eb2f0c.json；ID：54e1a3d1-413c-468b-a776-6a8be56c1dbd；SHA-256：174c5b6f06caa937394c8450c99c45236a75ab71ed541f7be0e4e54c113a2025
- model-response-b348bf69-e8b6-47f4-a48b-eac20e192fd5.json；ID：9ac27b3c-6b12-4815-8635-478c95d92375；SHA-256：b042a5cca02511d0003847aaaf0140cf7d9798d16dfb842153e7c14bd62ebe72
- model-response-b7cf2228-4812-46d5-b8ee-3057d8133afb.json；ID：18f5f860-7c9c-414e-83c2-b2cc4fc972d9；SHA-256：60d031a68437accb0513dab0739d1f338b73bbc83558ca952cac892f73d24b6d
- model-response-bcd76cef-a7b1-45c1-b080-9d1b417a208d.json；ID：eef5044a-7f93-4902-b31a-b7d1e2feebc3；SHA-256：040bdda106fd0c425e6674772f6d957e9179d1dca5706ffa30547be6197cb9f6
- model-response-cab7377c-e929-43e2-8e78-ac4e8327c260.json；ID：a9ca3aba-838a-4f02-b197-bbffb541753e；SHA-256：b5f9440f60e9fae97b4afb9d81b8f21eb3c0d21a0898bfc58d8cdaffd108965b
- model-response-cd479408-8264-4a1e-8479-b81d04770624.json；ID：49fac461-c427-446b-8dd7-5d81b72ddfb5；SHA-256：0d02cbc7f918af91c0365fe835e1ab3d0bf7ab45d59034b5ee2f08de956ffe9b
- model-response-ce44c711-cada-4b1b-9a63-8699df1edc02.json；ID：ba8fd68a-ea08-4354-b92e-d42b2aeb0bc4；SHA-256：10d31a0cb18fb008125d11161ed5f6e5c6f6cb94d0f67f389cc7db545a61871f
- model-response-d15b7998-03c5-4e6f-8604-d29ab1feaeaa.json；ID：afa0fa8c-a85f-4696-a6f4-bcec2578d9b2；SHA-256：cb56a5a7165e8d12e4e99034172c4854e3c184818189fac9d64587b30785b450
- model-response-d3cc9bf5-1f75-4242-8bac-b3ac7336b035.json；ID：1eddf7c5-01e9-4190-9c52-281f5c5ef815；SHA-256：90ae7759704279b9eff26c05d1607707bd5f8ff0a1c3333d77dce6b62246b974
- model-response-d437f58e-814c-422d-861d-23b3d2d5e990.json；ID：9101cbf3-7ab5-4fac-bae9-436ea2819568；SHA-256：61aa312feff257f6e75b583e8968bd027e49c67bbdf7294980ec795fccfddb33
- model-response-d7cb2ae3-fa10-4006-a66c-e7d05b56770a.json；ID：51b67402-d563-4176-9a26-eaae29387795；SHA-256：c657520db04cfd22d9e695daae53ed3d9a93cba5d030e72d028c7cdc0f392cf5
- model-response-d9a5d449-79d0-4a2d-a125-46411169dec6.json；ID：f90d6c45-ce12-47d4-8f77-42739deeefdf；SHA-256：3bbf00753c6908f425f5d790588f23175c42399f25517907b9b0a2c83ee0cdd0
- model-response-d9c290aa-0d18-4a43-95f3-9766f4a83994.json；ID：00d0288f-4055-420f-89e9-bc22bbfaecfd；SHA-256：a3d3ca00211ae654e268a66fbc273a2c0bf95a6dd37ea07a18bc3ebcd6a64853
- model-response-e04373ad-03fa-4fd6-b185-ab968bade0dc.json；ID：f906bf88-bb9a-44bf-9957-0fb2c7685ae3；SHA-256：411d50c7878055f1d980d1d23a26c857f875ccf03db7eab810341c19bf40d594
- model-response-e2044ca7-2f1f-4a9d-aa6a-bf19ae0de29e.json；ID：53e13217-d149-46cf-97f4-bd0df6a020c6；SHA-256：ab8bdd3acd55ecaf21b7c7f64cb701b942514ee0700accfea5eabc2101c29fb6
- model-response-e3702cbf-e93c-4565-a5fb-bd9179a51fc4.json；ID：518524ff-b613-49e7-a798-399407ca43be；SHA-256：50e8c100e8e394d355f83d3d0d954682cdc9cae3e3d59e10707b65934e35e3c7
- model-response-e5a8d542-f69d-4933-b7ac-d751d2c1e81c.json；ID：de751315-a50b-4d90-b262-5a5f1ac312d5；SHA-256：455c49f9bc6649ab50d16b041ff26ce9ef97cfe0a39a5f75c85f9eec09dc8144
- model-response-e8ee1d0b-61df-4a6c-bc22-d6e454887abb.json；ID：7d324f21-84ed-4518-93c8-4154fbcd9d61；SHA-256：4ff21e74d950d7dd2a180cd4009f3cda1acd7067af7bef259c3b5ccf8dcdcdf1
- model-response-e9953cd2-34f0-48db-b4fa-ece0edb55993.json；ID：77407460-ffed-4106-80aa-3fd71b89adf5；SHA-256：4f205db506b17e78a4995a9e9da5a2efa28bed2a4faadd394f040a1f9782820b
- model-response-e9cb3fae-d27c-45b3-8d11-3fee1fbf15a9.json；ID：cb42734d-0ae1-4773-9678-ff19da413c81；SHA-256：dc1cec6c37fec636c8af66f1f6c48f65ce782301615c98154f697752925bb646
- model-response-ee407063-9a76-4bbc-9df5-637d018b993f.json；ID：ef888269-7cc8-4481-9767-58f6cbab6160；SHA-256：9ca16fa3ca3c05ce8b21091956a8d1e2568540cb00a50b01aa380a5663e7c4fe
- model-response-ef668a7d-5ffb-4bd7-8693-65f61d6ad820.json；ID：f14a946b-d1d9-47c5-87af-2cbe497f8b9c；SHA-256：3bfe17c33227e7c75ddab82d97eae7becdabc36bf149e247f8fff62f188fb8c7
- model-response-f16825cc-b3e7-4a8e-87b5-3c94e8f05e84.json；ID：58bda5c7-220e-4bf1-8afb-3f82b64ed43a；SHA-256：d5e61ec38d68660b280323f71b1ac7686a8e45441f615f11e29c8bc3f46f3ac4
- model-response-f2ee9d05-7b09-4dd0-8cf5-31a89fe1689b.json；ID：b76eddac-58b6-4373-b3c6-7cf948f68a41；SHA-256：3c271094363b7b4fdbef648b276753d9ce76782749af37cf9491a5fa3ebc6a2e
- model-response-fa0eae8b-7c28-4e97-8843-1e94e3e1c4b7.json；ID：45540960-8073-4014-8f4c-15bd91d48c09；SHA-256：b3d1aed1da00b737868de712bcaef5b5aabcffb90c7aa8f7a596af8b533b467b
- model-response-fac07c8f-d0cf-466f-b43d-52b65f82bb41.json；ID：5c0d6781-0a8c-4fb6-a754-ab1ff9a3cea7；SHA-256：1c60bee5f6d943db839653059eebfedb91b42e45d425fce688cf673491d357fc
- model-response-fad60d47-d89b-4a15-825b-30090839f81c.json；ID：4a4063ac-5f18-4cb9-85c0-3c65a15c1249；SHA-256：967ddf8af915c3e584cb262ade0233557ce43e9fe64d93dea59faaa0f780a1dd
- model-response-fb6238fd-8c9b-4bdd-af9d-dccb3b343f68.json；ID：f2e5e2d1-7819-4cdd-bbbc-b6f0487345be；SHA-256：74a0c710c3a4c0b6cb2a2732e076b317abddbf971441ef90ad13e60d1cd324e3
- model-response-fcb4634f-ec6c-485d-ba0d-b569449d331b.json；ID：f648a3d0-b709-4433-832b-e9a58b9adadb；SHA-256：94a280cda7720661f42b24c8c38e220d9f39cabc4cffcb1254496366bb84f5c9
- model-response-fe215e38-62b2-4a61-b53f-39d29ca94ce1.json；ID：1c92dbaa-e69e-4079-99b9-2e56317304ee；SHA-256：766781c57a717c2f83e573ee03500d59bb0d084fa3ae7c0fde463bdd0c3cec02
- p02-llama-buffer-vuln.zip；ID：8466a3a7-0466-4073-86a8-1a6bcfeb2896；SHA-256：e25dc26f35fc08d6f17179473f17a29d5576c159660b3c9b1bf5dc7b6b1288f0
- snapshot-manifest.json；ID：68f2bd2b-1914-4851-93f0-1685b88c8b3a；SHA-256：92f96cc7adcaf5d5fc059491c958aa927a8d30cb32efc3f64dc71898061ff830
- source-snapshot.zip；ID：470b81e5-cb13-4fab-976a-7296aafbf026；SHA-256：6d94318d39fe5fbfaee8187b6c97589021d40a6de0974b218e19debdb1dea839
