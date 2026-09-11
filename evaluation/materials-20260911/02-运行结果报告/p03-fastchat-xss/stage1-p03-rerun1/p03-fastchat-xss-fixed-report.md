# AegisAudit 分析报告

项目：对照池评测 20260911-074407

任务：d1341ab4-1c50-455f-9250-c5aa217d6ca1

状态：Completed

目标 SHA-256：6733abe3a11878f8a02097e47b8427a6762d420064d442d65920a493ab600fa2

结果快照 · 数据截至 2026-09-11T08:01:38.327Z · 导出时任务状态 COMPLETED。漏洞审计：COMPLETED；独立复核：COMPLETED；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| \_\_init\_\_ | fastchat/serve/gradio\_patch.py | L27–L73 | PARSED |
| \_process\_chat\_messages | fastchat/serve/gradio\_patch.py | L98–L120 | PARSED |
| fastchat/serve/gradio\_patch.py | fastchat/serve/gradio\_patch.py | L1–L168 | PARSED |
| get\_config | fastchat/serve/gradio\_patch.py | L75–L80 | PARSED |
| postprocess | fastchat/serve/gradio\_patch.py | L122–L153 | PARSED |
| style | fastchat/serve/gradio\_patch.py | L155–L168 | PARSED |
| update | fastchat/serve/gradio\_patch.py | L83–L96 | PARSED |

## 审计策略与优先级

目标为单个 Python 模块 fastchat/serve/gradio\_patch.py（Gradio Chatbot 组件补丁，共 7 个单元）。审计优先级按“外部/模型输入 → 渲染与净化信任边界 → 配置回传 → 辅助方法”排序：重点验证 chat 消息的 HTML/Markdown 处理路径（用户消息走 nh3.clean，助手消息走 markdown2 convert 且未见净化），以及非字符串类型消息在断言/清洗处的类型与异常边界。仅做静态语义规划，不执行目标、不做 CVE/版本比对。

1. u\_9b335403084aa5168178a902bb5b72b5：postprocess 是聊天消息进入前端的渲染信任边界：第 144-152 行对 message\_pair\[0\] 直接拼接 nh3.clean 结果到 &lt;pre&gt;，对 message\_pair\[1\] 走 \_process\_chat\_messages。需核对两侧净化策略是否一致（用户侧净化、助手/模型侧是否仅 Markdown 转换而无 HTML 净化），以及 message\_pair\[0\] 非字符串时 nh3.clean 的类型/异常行为，和断言依赖是否可被非本地数据触发。
2. u\_3f8590da588515c9f5965161ff842ea6：\_process\_chat\_messages 处理元组/列表消息：第 103-111 行取 chat\_message\[0\] 传给 processing\_utils.get\_mimetype 并把 filepath/URL 原样写入返回结构；第 116-118 行对字符串仅做 markdown2 convert 后 str 化，无 HTML 净化。需判断媒体路径/URL 与 Markdown 内容是否可能构成注入或本地资源引用边界，并确认渲染端是否复用该输出。
3. u\_42aedb996cb719c3a2e810dab3b29268：\_\_init\_\_ 第 55 行配置 Markdown 解析器 extras（fenced-code-blocks、tables、break-on-newline），决定后续 convert 的输出能力面；color\_map 弃用告警与 \*\*kwargs 透传也影响组件受控面。需确认 Markdown 扩展是否会放行原始 HTML，从而与 U0005/U0006 的净化缺口叠加。
4. u\_8c0f91a2da1240fa3efcf637c07df3eb：get\_config 第 75-80 行把 self.value 与 selectable 回传前端，value 可为 Callable（见 U0002 文档），需判断配置序列化是否可能暴露服务端对象/路径等非预期信息，属于对外信任边界的次要检查点。
5. u\_a480678d629c3a0e337100fac52a0ef6：update 为静态方法，第 83-96 行直接装配含 value 的 updated\_config 返回，未见校验；需核对 value 的 \_Keywords.NO\_VALUE 哨兵处理与后续使用者，判断是否存在配置注入/类型混淆路径。
6. u\_e163d76d667f7432ac065ef4d4d0bdcd：style 第 155-160 行仅写入 self.\_style\[&quot;height&quot;\] 并透传 kwargs，受影响面小，作为低优先级完整性检查（确认 kwargs 不被用于敏感属性写入）。
7. u\_c375b5c882099c5c9451affcdde7120f：模块级上下文：第 1-9 行显示代码自 Gradio 组件复制并以通配符 from gradio.components import \* 引入依赖，且依赖 markdown2/nh3；需据此确认符号来源、依赖可用性与整体派生关系，避免把库行为误判为本模块缺陷。

规划限制：仅提供 1 个代码文件、7 个单元，调用图不完整（call\_graph\_complete=false），前端渲染代码与 Gradio 库内部实现均不在目标内，无法确认 nh3/markdown2 输出的最终消费点。

规划限制：Semgrep 未支持、verification/vulnerability\_audit 均为 NOT\_RUN，无规则命中或执行证据；本计划只给出静态优先级，不构成漏洞结论。

规划限制：目标未构建、未运行，无入口、输入接口与依赖清单（run\_config 缺失项），因此外部输入的实际到达路径属未知，需在审计中显式标注为缺口。

规划限制：记录中无 recovery 数据与任何解包/反混淆变换，无法评估二进制恢复质量或加壳保护。

规划限制：工具请求预算已用尽，本计划基于已读取的模块正文（含 U0001 截断至第 160 行）制定；第 161-169 行未直接读取，需后续单元级阅读补充。

规划限制：人工注释为空，无可参考的标注证据或需验证的声称。

## 发现与复核

静态结论范围：COMPONENT

### 助手/模型消息经 markdown2 渲染且未净化，可注入原始 HTML（前端渲染时形成 XSS）

CWE-79 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：postprocess\(U0006\) 第 150 行把 message\_pair\[1\]（助手/模型生成的回复文本）传给 \_process\_chat\_messages；该文本可能包含来自用户提示或模型输出的原始 HTML 片段。

危险操作：self.md.convert\(chat\_message\)（U0005 第 118 行，Markdown 解析器在 U0001 第 55 行以 extras=\[...\] 构造，未启用转义/safe 模式，也未在返回前后调用 nh3.clean）。

防护缺口：缺少与用户消息一致的 HTML 净化（nh3.clean/转义）；postprocess 第 148 行对 message\_pair\[0\] 使用了 nh3.clean，但第 150 行对 message\_pair\[1\] 未做同等处理。

前提：1\) 攻击者能影响模型回复内容（直接通过对话诱导，或回复中包含来自检索/工具/用户内容的原始 HTML）；2\) 部署中该返回值被前端当作 HTML 渲染，而不是纯文本转义显示；3\) 未在外层再做全量净化。

影响：若前端以 HTML 渲染返回字符串，攻击者可在聊天回复中注入 &lt;img onerror=...&gt;、&lt;script&gt; 等，导致在查看该会话的浏览器上下文中执行脚本（会话令牌/操作冒用、界面篡改）。若前端仅作纯文本渲染，则该问题降级为潜在风险。

修复：对 assistant 侧文本采用与 user 侧相同的净化策略：在 \_process\_chat\_messages 返回前调用 nh3.clean（或对 markdown2 输出再做一次 HTML 白名单过滤），或在 Markdown 解析器中启用转义原始 HTML 的选项；并统一两侧处理流程，避免安全不对称。

- 证据：fastchat/serve/gradio\_patch.py L116–118 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：        elif isinstance\(chat\_message, str\):             # return self.md.render\(chat\_message\)             return str\(self.md.convert\(chat\_message\)\)
- 证据：fastchat/serve/gradio\_patch.py L148–150 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：                    + nh3.clean\(message\_pair\[0\]\)                     + &quot;&lt;/pre&gt;&quot;,                     self.\_process\_chat\_messages\(message\_pair\[1\]\),
- 证据：fastchat/serve/gradio\_patch.py L55–55 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：        self.md = Markdown\(extras=\[&quot;fenced-code-blocks&quot;, &quot;tables&quot;, &quot;break-on-newline&quot;\]\)

复核 v2（MODEL，VALIDATED）：在组件边界内，U0005 的 \_process\_chat\_messages 对 str 类型参数（第 116-118 行）直接返回 str\(self.md.convert\(chat\_message\)\)，没有任何输出净化。self.md 在 U0001 第 55 行以 Markdown\(extras=\[&quot;fenced-code-blocks&quot;,&quot;tables&quot;,&quot;break-on-newline&quot;\]\) 构造，未启用 safe\_mode/escape 类选项，markdown2 在默认（非 safe\_mode）配置下会原样保留输入中的原始 HTML 标签，因此形如 &lt;img onerror=...&gt; 的字符串会被保留在返回的 HTML 中。对照 U0006 第 144-151 行：用户侧 message\_pair\[0\] 经过 nh3.clean 后才放入 &lt;pre&gt;，而助手侧 message\_pair\[1\] 直接调用 \_process\_chat\_messages，安全处理明显不对称。该 Chatbot 组件的声明用途就是显示用户消息与助手回复的 Markdown 渲染结果（U0001 第 20-22 行），即在浏览器中作为 HTML 呈现，因此返回的 HTML 字符串进入渲染上下文属于组件自身契约，不需要额外的攻击者能力。符号化调用方传入的字符串（含原始 HTML）即足以在本组件内部形成一个未经净化的 HTML 输出路径。

反证：代码中确实存在一处净化：U0006 第 148 行对用户消息调用 nh3.clean，说明项目具备净化能力却未应用到助手侧；此外没有任何 safe\_mode、escape、html.escape 或对 md.convert 结果的白名单过滤。未发现其他守卫会拦截原始 HTML。

待补信息：1\) markdown2 在该 extras 组合下的具体默认行为需以实际库版本确认（本次静态审计未运行，不声称已执行），但缺省非 safe\_mode 时保留原始 HTML 是其常规默认；2\) 实际部署中前端 Gradio 是否把该字符串按 HTML 注入 DOM（组件契约指向是，但本目标内无前端代码，无法在运行时确认）；3\) 助手回复文本在具体业务中是否可被攻击者影响（属于调用方的数据来源问题，非本组件可判定）。以上均不改变组件内部“无净化输出”这一静态事实。
静态结论范围：COMPONENT

### 非字符串消息（dict）原样透传，缺少字段白名单与类型约束

UNKNOWN · MEDIUM · 复核 REJECTED · 验证 NOT\_RUN

输入：调用方（可经 postprocess 第150行或直接调用）传入的 dict 型消息，字段内容可能来自模型输出或上游服务

危险操作：第112-115行：直接 return chat\_message，未做字段白名单过滤与取值校验

防护缺口：缺少键名白名单、取值类型/协议校验（例如仅允许 http\(s\)/本地路径）以及前端可见字段的净化

前提：dict 消息的 name/mime\_type 等字段被不可信来源控制；前端把这些字段写入 DOM 属性或资源 URL 而未再次校验

影响：若前端未做二次校验，可能造成媒体 URL 伪协议注入或界面内容欺骗；在缺少前端证据前影响范围不确定

修复：在返回前对白名单字段进行类型与协议校验，拒绝 javascript:/data: 等危险 scheme，并保持与字符串分支一致的净化策略；前端渲染处应避免把不可信字段直接拼入 HTML/URL

- 证据：fastchat/serve/gradio\_patch.py L112–115 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：        elif isinstance\(             chat\_message, dict         \):  # This happens for previously processed messages             return chat\_message

复核 v2（MODEL，REJECTED）：候选把 U0005 第112-115行的 \`return chat\_message\` 当作注入 sink，但该行只是把调用方传入的对象原样返回，组件内部没有任何 URL 拼接、HTML/DOM 写入、属性构造或模板插值操作；\`javascript:\`/\`data:\` 伪协议或属性注入必须发生在另一个未经审计的渲染组件中，本组件不产生也不执行任何标记。第103-111行的 tuple/list 分支主动构造完全相同的字段结构（name/mime\_type/alt\_text/data/is\_file），说明该结构在组件契约中被当作数据载体而非标记；第116-118行的字符串分支才调用 \`self.md.convert\` 做渲染，候选并未针对该路径提出具体证据，因此不能把“dict 透传”本身当作注入缺陷。缺少键名白名单/类型校验在本边界内不构成可利用漏洞，属于下游渲染方的防御性措施；候选人自己也承认结论是“待验证假设”，缺少前端渲染证据，无法支撑 VALIDATED。

反证：第112-115行无插值、无 URL/DOM 构造、无执行语义，仅返回入参；第103-111行显示同一字段结构由本组件以同样的无净化方式主动构造，属于既定数据格式；第101-102、119-120行显示该函数是类型规范化器（None→None，未知类型→ValueError），其职责不是净化下游未知渲染格式；函数与 \`self.md.convert\` 的渲染路径仅在字符串分支（第116-118行）出现，与本次声称的 dict 透传 sink 无关。

待补信息：未提供消费这些 dict 字段的前端/渲染代码，因此无法判断是否存在把 name/mime\_type/alt\_text 直接写入 URL、HTML 属性或资源请求的不安全使用；也未提供上游是否可把攻击者可控文本写入这些字段（本组件内 dict 被注释说明为“previously processed messages”，更像内部已处理状态）。这些缺失条件使得该注入假设无法在本组件边界内被证实，但也无法在不审计下游渲染方的情况下断言其为漏洞。
静态结论范围：COMPONENT

### get\_config 直接回传 self.value 原始消息，绕过 postprocess 的净化/类型归一化

CWE-79 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：构造参数 value（可由应用代码或调用方提供，可能含不可信消息）

危险操作：get\_config 返回 {&quot;value&quot;: self.value} 并序列化给前端

防护缺口：未调用 \_process\_chat\_messages/postprocess（含 nh3.clean）后再回传

前提：应用以不可信或未净化内容初始化 Chatbot.value，且前端直接按 HTML 渲染该 value

影响：初始化渲染阶段可能出现未净化 HTML，形成 XSS 或布局注入；同时暴露服务端原始数据内容

修复：在 get\_config 中先经 postprocess/\_process\_chat\_messages 归一化与净化后再返回 value，或明确文档要求调用方只传已净化文本

- 证据：fastchat/serve/gradio\_patch.py L75–80 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：def get\_config\(self\):         return {             &quot;value&quot;: self.value,             &quot;selectable&quot;: self.selectable,             \*\*IOComponent.get\_config\(self\),         }
- 证据：fastchat/serve/gradio\_patch.py L144–152 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：            processed\_messages.append\(                 \(                     # self.\_process\_chat\_messages\(message\_pair\[0\]\),                     &#39;&lt;pre style=&quot;font-family: var\(--font\)&quot;&gt;&#39;                     + nh3.clean\(message\_pair\[0\]\)                     + &quot;&lt;/pre&gt;&quot;,                     self.\_process\_chat\_messages\(message\_pair\[1\]\),                 \)             \)

复核 v2（MODEL，INCONCLUSIVE）：代码路径差异属实：U0003 的 get\_config 直接返回 {&quot;value&quot;: self.value}，未调用任何净化；而同组件 U0006 的 postprocess 对用户消息使用 nh3.clean 并用 &lt;pre&gt; 包裹。因此在组件自身接口上，构造参数 value 确实未经 postprocess/\_process\_chat\_messages 处理即被序列化。但候选所主张的 XSS 需要“该初始配置 value 被前端按原始 HTML 渲染”这一组件外条件，且需要 value 携带不可信内容；本目标仅含 gradio\_patch.py 单文件，既无前端渲染代码也无 Chatbot 实例化点，无法证实任一条件。该 get\_config 返回初始值是 gradio 组件配置契约的常规形态，postprocess 是运行时输出处理路径，组件范围内无法证明 get\_config 必须复用同一净化。综合而言输入控制与可达性在该组件边界成立，而决定性防御缺口与额外前置条件未知，故不能定论为已验证或已排除。

反证：U0006 中 postprocess 存在 nh3.clean\(message\_pair\[0\]\) 净化，说明组件具备净化能力且作者有意图；但该净化只作用于运行时输出的用户消息子项，属性为初始配置序列化而非运行时事件输出。get\_config 返回 self.value 是 gradio 组件标准配置字段，U0001 的构造参数与 U0003 的返回共同说明这是设计上的默认值暴露渠道，不能仅凭“未调用 postprocess”推断为必需防御缺失。

待补信息：1\) gradio 前端对 Chatbot 初始配置 value 的渲染语义（是否 {@html} 原始渲染、还是转义/安全 markdown 渲染）；2\) 初始 value 是否可由不可信来源（而非开发者常量）填充；3\) 目标中无 Chatbot 实例化/路由调用点，无法确认部署形态与输入来源。
静态结论范围：COMPONENT

### postprocess 对非字符串用户消息无条件调用 nh3.clean，缺少类型校验

UNKNOWN · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：postprocess 的 y 元素 message\_pair\[0\]（声明类型可为 str\|Tuple\|List\|Dict\|None）

危险操作：nh3.clean\(message\_pair\[0\]\)

防护缺口：未先按 isinstance 分派或转换为字符串（对比 \_process\_chat\_messages 的类型分派）

前提：调用方传入非字符串的用户侧消息（如 None、文件元组或 dict）

影响：渲染阶段抛出异常导致请求失败；若某些实现接受 \_\_str\_\_ 不可信对象，则净化语义不确定

修复：在调用 nh3.clean 前按类型分派（None 跳过、tuple/dict 走 \_process\_chat\_messages），或显式限定参数类型

- 证据：fastchat/serve/gradio\_patch.py L141–149 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：            assert \(                 len\(message\_pair\) == 2             \), f&quot;Expected a list of lists of length 2 or list of tuples of length 2. Received: {message\_pair}&quot;             processed\_messages.append\(                 \(                     # self.\_process\_chat\_messages\(message\_pair\[0\]\),                     &#39;&lt;pre style=&quot;font-family: var\(--font\)&quot;&gt;&#39;                     + nh3.clean\(message\_pair\[0\]\)                     + &quot;&lt;/pre&gt;&quot;,
- 证据：fastchat/serve/gradio\_patch.py L101–111 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：        if chat\_message is None:             return None         elif isinstance\(chat\_message, \(tuple, list\)\):             mime\_type = processing\_utils.get\_mimetype\(chat\_message\[0\]\)             return {                 &quot;name&quot;: chat\_message\[0\],                 &quot;mime\_type&quot;: mime\_type,                 &quot;alt\_text&quot;: chat\_message\[1\] if len\(chat\_message\) &gt; 1 else None,                 &quot;data&quot;: None,  # These last two fields are filled in by the frontend                 &quot;is\_file&quot;: True,             }

复核 v2（MODEL，REJECTED）：就 INJECTION 类别而言，候选声称的“危险操作”是 nh3.clean，而该调用（U0006 第148行）本身就是对 message\_pair\[0\] 的 HTML 净化，目标值在写出前即被净化器覆盖，未见任何绕过或未净化直出证据；第141-143行的断言只约束 message\_pair 的结构而非元素类型（U0005 第101-118行展示了本应使用的类型分派，但此处被注释掉），因此非字符串元素（None/tuple/dict）会使 nh3.clean 抛异常——这属于健壮性/可用性缺陷，候选自身也承认“非直接安全缺陷”。缺少不可信调用者跨信任边界提供非字符串值并造成实际影响的证据，故不构成 INJECTION 安全漏洞。

反证：nh3.clean 对 message\_pair\[0\] 实施净化，直接覆盖注入写出路径；第141-143行断言约束元组结构；另一处理函数 \_process\_chat\_messages 显示仓库存在按类型分派的既有做法，说明类型问题可控。

待补信息：非字符串元素（None/tuple/dict）是否可由不可信用户经真实调用方跨边界提供、以及是否会产生超出单次请求失败的影响，均未证实；也未证明存在绕过 nh3.clean 未净化直出的路径。
静态结论范围：COMPONENT

### 用户消息直接传入 nh3.clean，非字符串（tuple/list/dict）输入会抛出未处理异常

CWE-20 · LOW · 复核 VALIDATED · 验证 NOT\_RUN

输入：postprocess 的 y 中 message\_pair\[0\]，按类文档可为 str / tuple / list / dict / None

危险操作：nh3.clean\(message\_pair\[0\]\) 要求字符串参数，收到 tuple/list/dict/None 时抛 TypeError（None 亦不会得到 &#39;&lt;pre&gt;&#39; 空串语义）

防护缺口：未先用 isinstance\(str\) 分支或 \_process\_chat\_messages 统一类型处理，也未捕获类型异常

前提：调用方按文档传入 tuple（如 \(filepath, alt\)）或 dict/None 作为用户侧消息

影响：异常向上传播导致该次响应失败/端点不可用（局部 DoS），并使多媒体消息功能不可用

修复：对 message\_pair\[0\] 先做类型判定：字符串走 nh3.clean，其余类型走 \_process\_chat\_messages 或显式拒绝；不要依赖 assert 做入参校验（-O 下会被移除）。

- 证据：fastchat/serve/gradio\_patch.py L147–148 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：                    &#39;&lt;pre style=&quot;font-family: var\(--font\)&quot;&gt;&#39;                     + nh3.clean\(message\_pair\[0\]\)
- 证据：fastchat/serve/gradio\_patch.py L137–143 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：        for message\_pair in y:             assert isinstance\(                 message\_pair, \(tuple, list\)             \), f&quot;Expected a list of lists or list of tuples. Received: {message\_pair}&quot;             assert \(                 len\(message\_pair\) == 2             \), f&quot;Expected a list of lists of length 2 or list of tuples of length 2. Received: {message\_pair}&quot;
- 证据：fastchat/serve/gradio\_patch.py L89–96 ；产物 02488ee2-38f9-4334-81d1-1fe36730ffcf；引用：        updated\_config = {             &quot;label&quot;: label,             &quot;show\_label&quot;: show\_label,             &quot;visible&quot;: visible,             &quot;value&quot;: value,             &quot;\_\_type\_\_&quot;: &quot;update&quot;,         }         return updated\_config

复核 v2（MODEL，VALIDATED）：postprocess\(y\) 的类型注解与类文档都允许用户侧消息 message\_pair\[0\] 为 str \| Tuple \| List \| Dict \| None，但实现对 message\_pair\[0\] 直接调用 nh3.clean（Rust 绑定，仅接受 str），仅用 assert 校验 message\_pair 本身是 tuple/list 且长度为 2，完全没有对 message\_pair\[0\] 的类型分支；原本能处理元组/字典/None 的 \_process\_chat\_messages 在该位置被注释掉（第146行注释，第150行只用于响应侧）。因此在本地组件边界上，把按契约合法的非字符串（tuple/list/dict/None）作为用户消息传入，会在拼接处抛出未捕获的 TypeError，导致该次 postprocess/响应处理失败。这是可静态判定的输入校验/健壮性缺陷（局部 DoS），唯一前置条件是调用方按声明类型在 y 元素\[0\]传入非字符串，属组件声明输入本身，不需要任何额外攻击者能力。

反证：对正常的 str 用户消息无影响；第138-143行的两个 assert 已保证 message\_pair 是 tuple/list 且长度为 2；第134-135行对 y 为 None 提前返回空列表（但这是 y 本身为 None，而非元素为 None）。未发现任何对 message\_pair\[0\] 的 isinstance 字符串判定或异常捕获。nh3.clean 对字符串仍做 HTML 清洗，异常仅源于类型不符而非清洗绕过。

待补信息：缺少实际调用方证据，无法确认生产部署中是否真的会在用户侧位置传入元组/字典/None（多模态用户消息）；也未提供上层异常处理中间件，故仅能确认本地组件会抛异常，不能断定部署级 500。

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
      "未执行任何动态分析或利用验证（dynamic_execution=NOT_RUN），所有条目的 verification_status 均为 NOT_RUN，VALIDATED 仅表示静态复核通过，不代表可利用性成立。",
      "本次审计仅覆盖 7 个单元，未覆盖目标全部代码、前端渲染实现、部署配置与调用方代码，可能遗漏其他入口或真实触发路径。",
      "XSS 结论依赖“前端直接渲染返回内容”这一未在本快照中验证的前提；若前端另有转义或 CSP 等缓解措施，实际风险需重新评估。",
      "get_config 绕过净化的主张缺少调用方证据与运行时数据，只能保持为 INCONCLUSIVE，无法判定是否可达。",
      "两条 REJECTED 候选的否定基于当前快照代码；代码或依赖变更后需重新复核。",
      "无人工标注证据可用（human_annotations.items 为空），无外部参考数据交叉印证。",
      "报告中不含 CVE、版本匹配或项目特定结论，结论不随环境版本差异自动适用。"
    ],
    "recommendations": [
      "针对已 VALIDATED 的助手侧 markdown2 未净化问题，统一两侧净化流程（在返回前调用 nh3.clean 或对渲染结果做 HTML 白名单过滤，或启用 Markdown 解析器的原始 HTML 转义），并复查前端渲染点是否将返回内容直接拼入 HTML/URL。",
      "针对已 VALIDATED 的用户消息直传 nh3.clean 问题，按类型分派处理（字符串走 nh3.clean，tuple/dict 走 _process_chat_messages 或显式拒绝），并避免用 assert 作为入参校验（-O 下会被移除）。",
      "对 INCONCLUSIVE 的 get_config 直传 self.value 路径，补充调用方与运行时数据，确认是否存在实际绕过 postprocess 的入口后再决定处置。",
      "将两条 REJECTED 候选记录在案但不再作为漏洞跟进；若后续出现新证据，应重新独立复核而非直接沿用原判断。",
      "补做运行时验证（dynamic_execution=NOT_RUN）：在可控环境中确认净化绕过是否可实际触发渲染型注入，以及非字符串输入异常的触发条件与影响面。",
      "对同一处理模块内其余函数做一次对称性排查，避免同类净化/类型分派不一致在其他入口重复出现。"
    ],
    "summary": "本次审计为纯静态审计（dynamic_execution=NOT_RUN，static_review_only=true），共覆盖 7 个单元，产出 5 条注入类（INJECTION）候选。经复核后状态分布为：2 条 VALIDATED、2 条 REJECTED、1 条 INCONCLUSIVE；所有条目的 verification_status 均为 NOT_RUN，即未获得任何运行时验证或可利用性证明，结论仅建立在源码阅读与调用链推断之上。\n\n已验证（VALIDATED）的两条均指向消息处理链路中的 HTML/类型处理缺陷：(1) 助手/模型侧消息经 markdown2 渲染后未做净化，而用户侧使用 nh3.clean，形成安全处理不对称，若前端直接渲染返回内容可形成 XSS；(2) 用户消息被直接传入 nh3.clean，缺失类型判定，非字符串（tuple/list/dict）输入会抛出未处理异常。两者属于同一模块的表层健壮性与净化一致性问题，静态证据充分，但仍需运行时确认实际渲染路径与可达性。\n\n被拒绝（REJECTED）的两条为：非字符串 dict 消息原样透传的“字段白名单缺失”主张，以及对非字符串用户消息调用 nh3.clean 的“缺少类型校验”主张；这些候选已被独立复核否定，不应作为漏洞计入。标记为 INCONCLUSIVE 的一条是 get_config 直接回传 self.value、绕过 postprocess 净化与类型归一化的主张：该路径是否真正绕过净化、调用方是否另有约束尚未确认，缺少运行时或调用方证据，需保留为待查项而非结论。\n\n总体判断：当前证据最值得跟进的是两处净化不对称与类型分派缺失，其次是 get_config 的绕过路径；三者都需要在真实部署与前端渲染链路上进一步验证，本报告不提升任何条目的验证状态。"
  },
  "audited_unit_count": 7,
  "edge_count": 20,
  "eligible_unit_count": 7,
  "exclusions": [],
  "files": [
    {
      "language": "python",
      "path": "fastchat/serve/gradio_patch.py",
      "reason": "",
      "status": "PARSED",
      "unit_count": 7
    }
  ],
  "finding_count": 5,
  "function_count": 6,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 0,
  "independent_review": "COMPLETED",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 6,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "6733abe3a11878f8a02097e47b8427a6762d420064d442d65920a493ab600fa2",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 69,
    "cost_cny": null,
    "measured_tokens": 326854,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "02488ee2-38f9-4334-81d1-1fe36730ffcf",
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
      "finished_at": "2026-09-11T07:53:46.814Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:53:46.812Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 7,
  "unresolved_calls": 20,
  "verification": "NOT_RUN",
  "vulnerability_audit": "COMPLETED",
  "warnings": []
}
```

任务错误：

## 证据产物

- aegis-report-d1341ab4-1c50-455f-9250-c5aa217d6ca1.html；ID：029d581b-1151-47b6-94cf-c0fe67c9c99d；SHA-256：51b65b38d534daf50d46c241d4c9c748ce03ca124527789f50fc5de7dcfdbcdf
- aegis-report-d1341ab4-1c50-455f-9250-c5aa217d6ca1.json；ID：b72f0250-b59d-45e3-952e-8fdcda6adb23；SHA-256：011b44d69d27ceeb7701fe3d1270fc22ec85fe82f85a283b57bc41d37816496e
- agent-AUDITOR-14586f1b-9ccd-4a50-8267-3bb83afe1cec.json；ID：4d08778a-2512-4cea-a66c-2cedb90f8208；SHA-256：af8b92ac8a47a647fdd46d9f5fecce0145e35bc8b6b4e22095117e1754a51287
- agent-AUDITOR-3f42c4a9-835e-4eef-bc5d-fd574476282d.json；ID：35fcade6-78f4-4541-985b-c6a0099e4622；SHA-256：8ecda614ae140fd17a6938c95cd85703c73f6bfe7e30267fb70ebe462fec00ea
- agent-AUDITOR-43486617-fe26-4db7-8dc4-cf0305815111.json；ID：20165bb0-9848-413d-ae77-c854cc77710f；SHA-256：27008a7ffef15b59ed0e546afe720d54d748b3a388894987bef1503c0f6893bd
- agent-AUDITOR-5af6d8ec-eff3-4850-ac4f-fb309a70c9a3.json；ID：2a538c53-71ae-432d-9bd7-a2710dba7b03；SHA-256：3a8ccde9f35000383ea00c39c40046f4269d8465108083a85323b978f7365fc2
- agent-AUDITOR-5bf169ae-ba6f-41d9-ae63-fa016cb4e9d8.json；ID：3212fe51-8da9-4848-8996-d1a5a5ec617a；SHA-256：b55fb5c0d67fa5cf2dcd18ac07b0c39c75dc37e09cd0ae908d3a646470797a71
- agent-AUDITOR-667cf58c-4f0e-4b96-9f2f-205f48eadac6.json；ID：7caf2edd-470e-4931-82f5-ccda7ba10a95；SHA-256：d3fec1f8d72b8bbcc22b82e5831865467d6bb744b69e6d9af4d3425d96476d60
- agent-AUDITOR-aa3293b2-0bba-4582-ae34-abff7bc1078c.json；ID：4c1802aa-e161-417b-9730-60da54e13115；SHA-256：9f25b003de8193af442d8f2af6f49b87e8652fa301938b90731bc4db6178c06f
- agent-PLANNER-1ca9b39c-55b7-42f8-995d-596b60b37cac.json；ID：7d1defd9-998c-4b2d-9eee-014597b0a67d；SHA-256：b0bd1a68268fd4c7af0327a7e6928762d3aad1b4415256ecfa6811a1c696af14
- agent-REPORTER-e3ba193c-7276-4363-bc76-d411bdf95a67.json；ID：49c1eacc-5846-4d3d-b8be-abea10929e6c；SHA-256：2855299d7ef6d7d4bed86ad546fc056500df7e7a9bbfb53a436ba0248460c95e
- agent-REVIEWER-2d49097b-7c05-4e73-a74d-ec13f9e96d62.json；ID：232b6436-b336-4c39-af37-cc8f696b2319；SHA-256：046dc45d7b2dc5685cfac38854128acd08bc3e2a9d043d971113c6c8d016f595
- agent-REVIEWER-5e645322-af18-45c6-8d31-69d29cb73d99.json；ID：acaaa5ad-de9a-4ca7-9918-5157948725d4；SHA-256：d68834407e7653ff8c520d1c81d70e3d6736b97387612b503413868e235fb73d
- agent-REVIEWER-62385b2f-9845-4a51-bc86-c81eb199dcc9.json；ID：3dc2c05e-5ef0-4f8e-86db-504cd3a0f229；SHA-256：63acec24dcd1d78671ece4a299fcb980463b7f00bed1c9b880f638173de04313
- agent-REVIEWER-9ca31750-2002-40a8-9e94-935dadecc261.json；ID：199d0c3f-f956-484b-bec9-4c9385039ed3；SHA-256：75267e52acc8928381aa6b8de1567057d1d3f6b21c18c23aca3fdd34880e448d
- agent-REVIEWER-cd15f077-1406-417e-863f-51c402b19691.json；ID：d1124d99-4d14-42f3-b83e-cd2afcdb9f7a；SHA-256：240a42f16a8c0ded83b73959b6f0027000b59e98d686346a817aa4fdb0b8f9a6
- agent-VERIFIER-c71e136a-1aca-4b32-b295-07f1fd63eec6.json；ID：2d09533a-9afd-470c-93a8-49a84c138c6e；SHA-256：f829292ac3edfaaf8b8ed003a7f7e4ecded4eaa02759e2f97b84e3f0ff6c53b6
- agent-VERIFIER-f1dcf6ae-a2fd-4bed-90a0-901d3218e9de.json；ID：570e634b-3945-4e8a-8e9a-5d4987a0df46；SHA-256：52b50034ce9579255d3bec820627dcf59f6d82fe871819cd14d338ae9591e2b0
- analysis-result.json；ID：02488ee2-38f9-4334-81d1-1fe36730ffcf；SHA-256：8e1ea9c012d0e6c019e9206e081097ea23e182c6cfd85dc7841ca2aab4d1fdd4
- model-request-03a6444b-6064-46df-8344-077244dc1358.json；ID：5549eb23-7f99-4374-90e9-9066168fd497；SHA-256：7ac0fa408892fa524c2ae713778bec83c5966fb3ac1557bcbaa32c963f5ef946
- model-request-046c92ea-e03a-4d4b-ae57-b9db20de9243.json；ID：093154e6-168f-4943-825e-67073e0e35a7；SHA-256：c47ca311c5db75080d4953866cf62ed5be61ba6719e6d587f111e4dce8e10329
- model-request-049942ab-fa4b-4b5d-bd43-283db1d6a3cf.json；ID：9e1e60af-f730-4470-ae4a-070caf71f7ff；SHA-256：21b30765fa426f6ca127d281ebdb1362fc542aa94dfbb5756ab4d30dbc78fe4a
- model-request-14f1c32b-6411-4ae9-9313-29793f34ba8f.json；ID：ee3bece5-cc35-4f8c-a83a-3c5465f77a75；SHA-256：906ba14e20138bcc741bbdf589f6c46f453b392a1e9f02afb733defef15bae43
- model-request-15b57c7c-b4a0-4efe-bee3-05e994ef88cc.json；ID：557eae0d-9346-47e0-9c08-18a09933ccf4；SHA-256：aa4041c36983b0a1f8946058efece683ecda88f713bdd816df1798c7006808e2
- model-request-283d6fac-8ca4-493f-bffb-2525d7979ba0.json；ID：0ad68139-c924-406f-afa9-457bbeaa135e；SHA-256：8b7c3c27c9f7d06c74dea073a0ec673709d3269b377588fba8e16853b464a4ab
- model-request-2869c7a1-0d99-445c-a64c-2dfaae42b8a8.json；ID：3ed914bd-cb97-4e88-a4a7-88e146b1ec4b；SHA-256：97a4ed139a0fe5f5c80c2f550b4a8d6acbf4356bcc5f73b135edeaea894496a7
- model-request-2afc509d-9fa5-4ec0-8fb8-c9ace39fa215.json；ID：03a527d1-3e9e-4bd6-bd50-8419ae4dbc4b；SHA-256：b77df4a5dda18017f859ac6761681e3d6670c3f68ddbc08f34057fb6af88618e
- model-request-2c969f6b-ab6b-4bf5-885c-b07abb138aa8.json；ID：e0fc99a8-70b7-44bf-9667-1c71723257ba；SHA-256：4730c3a6624ff6f38f55351328f0d263be90067035a37e31fe5d08bb59b42ddd
- model-request-3a6c4ddf-ce78-478d-9a7d-f1a8d322b959.json；ID：131d0ab2-bdfb-4e12-92a1-29c8af3c4eff；SHA-256：53c829fecf222fa44284829ef4720924729aef0fc05830999267734f32c071ae
- model-request-3b10b5db-5afd-4863-9577-f91b82ac2d36.json；ID：c376660c-feb1-46b8-84fd-515ec0026fda；SHA-256：0372ee364e15f20e151d9eee5da43b660c0e90834f4673623b259f9b2ed6bf26
- model-request-3ccff19d-7a3f-4c46-9a16-4eefb2a27be5.json；ID：420bea19-1c3b-4ea2-b0c0-8778d2984a88；SHA-256：4bb5c91880fa5725a54a03a76e84565156c19b44bfadf5c20643ac2f4486f53f
- model-request-418076f3-d959-4d0f-85cc-48d77632e37c.json；ID：d707d02c-fbb0-4a5b-a633-33638f1e3708；SHA-256：f5040637b235e93755d8e3483d15b567ab8d4b8d7e94acac729eb6f74b0d139c
- model-request-43eeef0a-ff6a-4f34-99ad-d8b551c2ce26.json；ID：48527b50-eef9-47a1-9de0-9bdd62dfbbf5；SHA-256：7d79441f6985776b50507cb82df58532f3d7a67bb1ff3e6fc32e1699e79128e0
- model-request-446130b7-fc34-46b2-b804-983d07889cf1.json；ID：47f804f6-2b95-4dad-9239-0071cf9a5d7b；SHA-256：874446a2d5bebde9ee838a365cc99811ffcc4f4a10597f7e50e6a53064f7010f
- model-request-45f6bcdc-c939-485f-916a-bb694e860dd1.json；ID：0a187ca0-c9ba-4886-9af3-01b619f8aaf0；SHA-256：bbe59ab0f046a1aaa2c5b1f7749debe5cd22a0abdb345728a16853163296d7db
- model-request-47316b58-6652-41d0-b208-cd1cd3297ea1.json；ID：4481dd20-2e84-40c6-a6db-5fd42904d756；SHA-256：8ea035278323849954342ccf194ba52664801cfa2df60fd558928993fd94c436
- model-request-48941bd7-0cc2-4128-9dff-1f0fad2b771f.json；ID：92fdf3b1-d374-40ec-b2f1-bf41cebbbacf；SHA-256：b17c89482b79482eb073484c738b11e166735d0ec4d5f514393d43ace9c82ce9
- model-request-4dd0193f-dd19-46f3-844e-12daa2126faa.json；ID：0a784660-9cc8-41d0-9790-d60d402110b8；SHA-256：26bca125ff6bab8b873cd65ae67d43af943f4de7d3c2f637e60c18e1e9ab7804
- model-request-4fdc2407-b3d1-4c97-9089-b8e9be42d9a9.json；ID：19fbb54f-94b3-433f-ae73-3c9b7415a6e0；SHA-256：a4c9333885efbcdef724a41c3419065dea1e3ef04fd5fdadfada344f424017ea
- model-request-53ca4d81-a15e-4451-8d91-bd9199bef4de.json；ID：f27d4f33-7e07-459a-a153-4c1792c97557；SHA-256：b5f00a7842032f3f819b6d6cab72fc0eae841bd5089a717758901c69fc38519d
- model-request-574c55b0-6101-47df-885f-d43ed0563061.json；ID：bcf2b225-23a1-4ba8-9d02-34631d0398e3；SHA-256：6b0d46aa305fc5160a515a6b3fcff8ac442806496369152514cca01d23328b94
- model-request-57e32baf-00fd-4985-a67a-e730e85caa41.json；ID：8d1ed5a8-6bc4-4baa-84e3-a52ce89346d3；SHA-256：98d0bbfd56f0e01340091fbadc608ac286cb8f8d9b0464f42719074616228077
- model-request-5a9973ef-935b-43b7-804a-195d9b5f0305.json；ID：e9119da3-5955-4c08-862e-f34284523cb8；SHA-256：e6974f654598b807cd5ba521ce693a7b1af38e70da433f171d40d3a34a197e40
- model-request-5e24fb27-f471-41d7-9d29-d4060a0f9721.json；ID：34978c04-adcd-4f5f-8d1e-aed60ff586e7；SHA-256：1cb4253648a1fb7a381775fe6d6eb9f16d6a28409bfd288f5b9df4e9ed0dc34f
- model-request-68097214-0eb3-4d54-b889-dcfe4eee3f86.json；ID：9e87007c-3a7c-4411-a294-dd4b23a78606；SHA-256：da25f527d64d0bf323ba473242ad0b9871fb9142423de77214b941b3ffec6a99
- model-request-68f28c3c-4f43-48c9-a017-89bc0716d77a.json；ID：ca416c05-ba00-482a-b679-cb053d469765；SHA-256：5a9f7c33b6afe1ede64e34b775e87d26a5e9703be786c4bb7974eeb4f363f9bf
- model-request-69de9d7b-cc5d-4f21-808d-01c953dc5d34.json；ID：85d007c9-d777-4768-baf1-8b74f39dab80；SHA-256：bdd3df82ea9e5dd50a708734783f1b1605883b1bb16dec7ea0a29b55a3f6064b
- model-request-6ee88790-692a-437e-9b36-570dc910f958.json；ID：4070689c-f688-4b44-8162-22d147043369；SHA-256：0e65587d6a7b3773e5462cf6aee6a50aebe6b678486b40c5785d1c6971a69d2d
- model-request-70b5cb90-fb7d-4cb4-84b2-cf000ae49823.json；ID：78e4dc41-2a49-4181-9af1-5da6a9b87ece；SHA-256：096e9ed9f5363fbbcdcd20af1cb8c5af0955b47917a010b5c84072dcadebbe93
- model-request-73c7b29f-e8a8-44f6-9774-fb68a83bba96.json；ID：c1dafab2-34eb-4d04-a8de-c051339e7726；SHA-256：0938d427fe3ffc9d52d8394f0db1c098d85c7fb4c983d83bad5b272a4adddd3e
- model-request-76fbfcd9-82e0-4765-a05d-d28d69988a55.json；ID：b7dc9c30-96f7-495d-8a9a-db0fa3045c88；SHA-256：618f7ecb78adcc2eb35f9e3532ab9fb55cc7e27914689f7016722afb2a2ab3d7
- model-request-7f085740-d070-4ba7-84b8-7f15a67d0d87.json；ID：3a874bee-4147-403d-bfa8-92697387a9cb；SHA-256：edd5d4fab65155b3724381785c0bb9bd000e263499193941943049b288c7935a
- model-request-82107ccd-4f96-4703-8361-338b8f6d6edc.json；ID：f203a640-674f-41c6-8804-9aa5f1b452d7；SHA-256：62c14bc71a6697e3d8e9e03d8268fbef4dcd519b4c4de60ca2fe48c05c446034
- model-request-8445cacd-2a2b-4282-9be5-45a32c8e8f2f.json；ID：f0b9b68b-9a3d-43da-a258-54a1118cd6c6；SHA-256：532153f3144a0b7c3e5ec4b74ba02a58b47f3f6af450121d0eac3bfd86bb4676
- model-request-8695bf48-d5a8-4b86-84df-9f7a2173eaa0.json；ID：01515687-7e10-4ba5-9a75-184b84254502；SHA-256：30aa0985d8e561763b9c4b908e29855d2c47d38bf1fdf46bebcb00ad680b18f5
- model-request-8d50f999-6a5c-4269-be18-f62d20f429c4.json；ID：3f97c129-e45e-4fe4-8dd4-1ff5df824f21；SHA-256：bf47fa25fba604c160195cb9215482ed8d0f463f9b3f163b811b6fb494a12eda
- model-request-8fa182b2-51de-49a6-85cf-c933e527f23d.json；ID：4c9270ca-e30c-431e-b1a9-3810563dfa53；SHA-256：59b2002e3a91f438d6f36d7cec33b6746b9f61e69e1180d23c97a4987adbbb91
- model-request-913026bb-9db5-4be1-83c5-7243f7518ed7.json；ID：e254888f-3e17-41a4-96cc-3fe0813b9053；SHA-256：bd79041b215a955c129d4c1778b6f8712b3011d3793a025d65dc7dc462e2268f
- model-request-95532776-1f4b-40c7-a1dc-748c5b0ce23c.json；ID：4a5413bd-e318-403d-94a3-226b5e0dbdf4；SHA-256：3452ed94a85f50ba48d45c58139406b1648ec6d0bf101e9f748113ffc40438d7
- model-request-97058146-b542-4f13-96b7-b85cd3d25121.json；ID：5ba735aa-160b-40c7-88a8-9bc473bb05dd；SHA-256：1d5931782e2ae0cbda48eaeda3318ff724bbfcdbf351bca8ca687c8b69b80e1c
- model-request-97e5612c-316c-4368-9fe8-f094bcb51c51.json；ID：4329ca7e-430a-47ff-b73d-d8da29979cc3；SHA-256：093e136b6092f5f2303ea51c16106d2cfef82ff454fb67a7fcd72b2c5773c007
- model-request-a4bf518a-5ba2-4b89-924b-06b46ba5739a.json；ID：5eb29292-e575-4ab1-a2f5-e2822e39ffa3；SHA-256：3ddfa96c9a30347514fd0bb8ddc0649170d2c13c2b9c276575dfc5f5ae05a493
- model-request-a57a0717-3f71-44ff-825b-f9b2cc6efdbe.json；ID：5628084e-f73d-486b-b661-35f86576fd66；SHA-256：1da9ae72fa202d293505ed40b1240b12c640b96704a37671ece86e0b61fd44e5
- model-request-aae60d72-03cf-4287-abda-33171cdecd59.json；ID：a9935b53-010b-417d-a51e-167f3cababbe；SHA-256：8cdb534f66815171a1c83cd9f943da62574b6de5299b7e142e61a4f2332fef47
- model-request-b5428ee3-f4f9-42e5-aeff-832f8d5a62aa.json；ID：b8a1aa7c-4c5d-4e8e-991e-35d62f0b3b1a；SHA-256：3f86bad98e08523814d1680e2e22256cd2ad5cc7e385fcc7000f4fa93e91c707
- model-request-b7086eb1-9bdf-498c-a7a3-16efc6369d9b.json；ID：834c52f4-fd2d-4f80-9a45-70c1e8d60a80；SHA-256：e3d3f4719f92a753ffcb89983ec09f6ba3b34a1eddc1634e4e64c93916de0d4a
- model-request-b805c1a8-ef50-4d02-b8b5-be3ad7a871b3.json；ID：e95c324a-cce6-4ad0-b762-17624b89706b；SHA-256：2fadabf77c06a31dcbf3a265d5cab2475a6fdd2d71f06a75240708803c538ebf
- model-request-b9793efc-4a5e-433e-adf8-998c30e4ef61.json；ID：f387f8b0-f3dd-4d2d-8423-fbbfcf3f5943；SHA-256：c7b656cab3c1dcd49c04b6e8b0beeece60a4f89b34581edfdffd66dbbafbf902
- model-request-ba796219-06f5-498b-b632-c86ee0face1a.json；ID：a6ad1845-30e3-4f27-8a38-8711578610b4；SHA-256：b75efa6e72197e38b95078a9bea5425a75f508a2acd14171d316b2c3163d05c0
- model-request-bdb563e0-7ed4-41ec-a197-9e20d0546a9b.json；ID：afc32b86-59a5-49ba-8585-1a30442b69a5；SHA-256：7b148fd7dc7005194755f29e82dd2063ba3b03c8e53f291da1bd24ddea10b9c1
- model-request-c1357668-26be-41a1-add6-cd874ac3e82c.json；ID：7d336c46-ff76-4aa5-b694-07d7d4376856；SHA-256：df2b08a46aefcec8f210fdee65ef693bb4afce40feaea67c3d322d76dcb1824d
- model-request-c7e75281-4126-4aca-9554-44e2cdfb3713.json；ID：85c74c7d-c1d3-4890-927e-eafaa575b6d8；SHA-256：0b1c435880687fba82128740a3d6bc5ec51fc1dc40490a0967cbf9bc9f379521
- model-request-ca28f62b-b310-4912-9e3a-4286cf272c4f.json；ID：be1161de-c484-4a62-af0a-c285882f1970；SHA-256：63521e772f9f725fe5702cdcdd98ba520956ba7386e7718c3bddb850b3fb6924
- model-request-cc6c0cae-4462-458f-8c61-2d58a034267d.json；ID：a6102011-29e3-4d54-b262-6f3c4cb508b2；SHA-256：edb7e4c240eaf531b0649b0ac7dc416dc3df896038e50d2bcbd185dcf6b9455e
- model-request-ce596b9b-afa4-4440-99ac-a60c0170cdbd.json；ID：a9bcdeb1-e393-4dbb-aaa4-94db52db3c3c；SHA-256：ebb9e26b1ffdb6a0c605ebad19026e3e96581b3db7baa7235cd0523d2aa9583d
- model-request-d12013ed-8436-4831-99e1-942878c650f6.json；ID：6c0eb88e-530a-4da3-9790-eeb0ed932484；SHA-256：09e1d44c195b2e9b6a905b4766df59f8b56e9390031d2416b798d257dc454398
- model-request-d8e6a2c4-f7a3-4c4d-9a8b-42bcd956163d.json；ID：d088f8fc-6342-4268-b9a2-6fbc5becbcff；SHA-256：71dbb4a35e081a2523b71e35d5e3032a4b035a7a0a0527086d241bd6f1c20862
- model-request-ded5bf55-2ef7-46b3-8514-6d0aee6a975a.json；ID：2997a1d9-5320-4faa-9c0e-07f124426d65；SHA-256：38773d24d8022a5ca1923951f9176345be93440e275e1567ddea45948f5a9131
- model-request-e2ddd6f4-032d-4d48-9fd3-942c1c404e9a.json；ID：cd062cda-0749-4db1-86ba-71f80e769ac1；SHA-256：4353740578a06080b1c0ad29bacf4521b28f1861b7da9f5cf6e1930e61028c3a
- model-request-e7b47a87-dab0-4bcd-a19b-2e497d8bc28c.json；ID：d66d51fe-9f51-4146-9a4f-b4c057c5ea40；SHA-256：d47de6a93786cdada82080619e26fef259280bbe8f0e033a48a5653b4edb5a63
- model-request-ea774636-3402-4de9-8ed3-dc236017d78a.json；ID：518daf09-9398-46d4-98cf-81b8e159c7aa；SHA-256：bc153bf3f94c36221b9f214f48d211fd91aa67e156072bf22841e7f715ebc2dd
- model-request-ebcd5bff-b7e0-47b4-a1f9-90274735209c.json；ID：b13ab363-c068-4155-82b2-e4f2788c4d97；SHA-256：8fe048f91f06dd6a399614aaa51b6f5a1c34ad46301205b43422d74ffa7b03b9
- model-request-ec4b826c-94e2-4fbd-b220-618b1f4328a6.json；ID：92002154-60ac-4c05-9e54-d8cbc180ac3b；SHA-256：ed6ff83b2eab3565100d7daf9b1abb8517d599945b41ff934448dee93d676c08
- model-request-ee8b8164-beb6-48f8-ab70-a2b6affaaafb.json；ID：643cc7bd-66ef-4057-befb-4f5f1e1e46a4；SHA-256：f74c33f003e64a622bbf4ad3238c4f7d440560352469deb622bd7b844fff29f8
- model-request-f84e5457-4458-4ffd-adee-9265f17a6bf0.json；ID：9547bf27-d2d6-4a3a-b2fd-9c944f1d3db6；SHA-256：eb719a730466914d94975ba83cced4bfd2232e104e67b78064e73f2fd2620e66
- model-request-f89aca8b-3d09-419e-bd86-600f0bc55c93.json；ID：9d3b912f-045c-4098-9634-44927ccdda65；SHA-256：edd9d0777ad118e043172076c09efea6de40b752184b1d2d78b9aaad7d99e01d
- model-request-f8b57b09-2b98-48e3-8085-901ea44edd2e.json；ID：08acd69e-bf8c-4f7b-8905-f902cb32d637；SHA-256：7265039a8efdcd99bb255ce22f4c3ce1460d3ad3749098f7ad4f7839fe172fc0
- model-request-fabf8cf0-4e8b-41f8-9edd-62ff2ba005b3.json；ID：7de2d5e8-91ad-465c-b31a-98617a0afbf5；SHA-256：582e064a8b287856915c84b0afc2b2c3d610630bb353e90663b9a5d29d53b411
- model-response-0522c834-fa6b-42f4-9e6f-cb346f309ff0.json；ID：80afe90e-67a3-4633-b2d0-777749834d33；SHA-256：0cd47b3de20f4996bc4839c5ca52294e878e02cede6f416e9660942193e77e8a
- model-response-07649aca-8141-4709-8399-7c3e07b1f733.json；ID：15508219-7a4c-4c6c-b9b9-2f1906d91ca5；SHA-256：ce5bb81760e539205ba9b6225c05bf45cd01795f11cbf345d0ca578e411537b3
- model-response-0ebaf028-b9d7-4630-b6b6-aa78fa8f5fee.json；ID：1da58b76-7f71-4230-9542-ab1efd6edcc8；SHA-256：4099d157427abca8c6ce598fad72f90bbc0060d37dee2e14886ff9b83046ecae
- model-response-0ffcc7d8-6e5b-4fd4-90bf-05f25e249f3f.json；ID：5151685b-b11a-42c4-ad21-d20fb392e5fa；SHA-256：f82b83d19cbea93489efc6037fdf65ca58574d49ed7c524abd31782dd1995ad3
- model-response-1044fbfd-8c5d-4c69-9e6a-cf2ca73a69b7.json；ID：6b88588e-2fa5-4643-b01b-d60f5c46183d；SHA-256：f93edf27a1ab2699095ecfc38a3a9fdb8f50ef61928e471e4dd253d4737181cc
- model-response-1e11236e-b3be-415f-a35d-bb0c393e6389.json；ID：71d65c9d-4b8a-423b-a424-84f4bafd8d22；SHA-256：7994330a847dd068b24cc73703f45f12f3679f615271f08744fe6b4d85ec942c
- model-response-20cfd060-e5a3-45b1-992f-b2b359ba5cfb.json；ID：82d28af0-1433-4ce0-bc32-73d00672a8e4；SHA-256：bb773212c83b374b375b5fbfc8a10ffad7c98dbca23969f6e520286b9581c70f
- model-response-22eb4401-69b5-48fe-afec-325dfdb464e8.json；ID：092407ef-b9e6-4f19-8615-eb6b42f8fb73；SHA-256：60e1c11f98d0077be24a03f26f77e9f2dbe5f05137bc7a0ced96c7ed7e2fdd76
- model-response-266c2b2a-f911-470e-a16f-43c21fc33f5d.json；ID：79387c73-94eb-4110-a715-7e7e18a5113f；SHA-256：9b17715db3e5d9968c8c63cf7dc9905b7378be90f07919b187bfc974cece762e
- model-response-2a516864-4b7f-41a9-ba14-d3d957d7459a.json；ID：1ebe0f09-9db7-4c78-8eca-23b8143d1ebb；SHA-256：334083464b698799ab9e865834c6dc25c3fa61dd76a939601313f1bd9ffda33c
- model-response-2bc25763-04ec-4d2a-b60e-a4716d14c0a1.json；ID：7de34465-bb04-4a1d-b7c6-74e6a8433c8e；SHA-256：a556c2f43e2a972b108c602239ae69e14a2fa031b17885f12018bc9698f403e6
- model-response-301274c5-e2be-49f2-9e0e-32607d6e3682.json；ID：abeba7f0-cfd5-46cc-aa71-06e981cd25c2；SHA-256：5976ad319f69702cf27476618cab1dab592d98191b0c5a85499e2d4ddf57f553
- model-response-310a82ee-5e49-45da-ae02-265483d4fc33.json；ID：df6a4d47-9b71-43a9-b2df-e02a2bccfe58；SHA-256：bb17327c7eb1c473eeafa1f6c692f9514d35be2319e4fb3950f6e0399e2e5ef9
- model-response-31cc8035-beaf-4232-abcf-561edd5d556f.json；ID：7f5a4516-2a43-4dae-8bcf-66639ae982c2；SHA-256：26694f12fd4b944f7f45f6bbe12ccfbad6959cb5b816a743877d6c437961d928
- model-response-32abe9be-fbca-4efb-83f3-15b1c8c6c71a.json；ID：3f251f26-6f36-42b5-80a4-23edeed91b79；SHA-256：b54663e6e5a02c840e5736c5b1a3a37dfa66755e953f9e5f6004f7a34be313db
- model-response-3379ee55-a159-4344-82ec-b77dea92274b.json；ID：24927321-6ab5-468b-bad0-e7612c8c356b；SHA-256：46ec757106517bc4e6b83d157b7e63dc41a9d868659df5283ee0ce7c3908f449
- model-response-33f27571-721f-44c0-a761-77fda1bad043.json；ID：3466e580-b9f1-4089-87d0-99e8a0e858fc；SHA-256：f4ad63ead381323cb9dd199b9f99c32f17c1583cac9bcfec25e636704375aaf4
- model-response-3542ef60-aad4-4c4d-91d5-8ca242d0e423.json；ID：84369f1e-6808-4a3b-bf1d-1451e6cf092f；SHA-256：175d7355a5190938021571445e9b201f246b2441ed4ef5af4c85c24eb5f2009c
- model-response-3901933e-3008-4c45-ac29-18edc7e3ca77.json；ID：09da3a2b-88b9-4106-8cfe-8c6635a221b4；SHA-256：62b4f407c02e173048102966a38bda82ff0ac7801122eae01c2d3074842d9433
- model-response-3f823d9e-217e-4af1-b902-7150f523fcd2.json；ID：42e94e25-9517-431e-947a-34d850b9304c；SHA-256：fd88a9f0a4badd7a425aeb24160961286f857ce0fb966fd069352a42e1ec378f
- model-response-458cc53f-6587-482a-a52c-4834ef8a9cf2.json；ID：21e38901-9065-45d7-b51c-b28ecd7f2932；SHA-256：55f7e46827721cb13b4c8a15f211caf1f82c976498e65881d884ebe80c6f9185
- model-response-46935b96-a497-41aa-b2e8-cca2353b10ad.json；ID：0e3a2fa1-f1b3-4cc9-8cc0-57a56b82ec86；SHA-256：32ef32804beb2d838ae767e97083e6543aeabca81f15c3c78caa80e8942ee736
- model-response-56238b9b-f17b-4b70-aa71-42cd6235fbe3.json；ID：871df75a-3732-4847-aa4b-6b3587f9a6f0；SHA-256：14d6810032b48508f055a7c6eaf417a19f991aeb9f3d2274da4d9744a072e07a
- model-response-597271ad-b671-4b2e-832f-46a3fb817584.json；ID：3ed77b3b-63e1-448a-a0e7-f79026ff7e76；SHA-256：db5ae8ae3f68080a4dca6d3f5db391e6fbf80228c73b50d159f4da80372ca2be
- model-response-5bd2c2ee-a73c-4e95-84d8-ae8618bb8684.json；ID：0fa5bf6c-cd91-4248-9d79-2bfed2914796；SHA-256：911268c784eede0314fd01d3624c352b2a17c544678da8065d0f7ecc5aab9625
- model-response-5e08d8b5-803b-49c1-8f85-59838370a048.json；ID：249bedab-7c9b-4ff7-87ee-29e9cf2d3d77；SHA-256：cb79f71da541868a353ae6912941bac66398c4b73e9842b918995b8e4513e48e
- model-response-5e224de7-ca9d-41f2-9f50-3a31cc7bd63b.json；ID：19ba1923-253a-4f29-8d87-0c44fac65ba7；SHA-256：43d06fce7cbd4beef3492e27a8b904daba6be4bb3bb080bbdcec2535feae4c85
- model-response-604bb738-8046-4510-a29a-c685ef9124fa.json；ID：79cc2759-1724-453e-b649-ee2caa121d6d；SHA-256：b2db1162c5a9d778df7d57f5a333eb424ee2a757644b4996d0ebe3096dcd8345
- model-response-605d9a43-2378-43ef-a7a8-d1a2ca22f25f.json；ID：4aa2e32d-ad9d-4a07-9027-8c0171a66a43；SHA-256：37e0414a4e5915a61d2bb45ac4c0f4a95206c4a78ad3824cdd8ccec38bc7dd9f
- model-response-63b06f75-b318-45c4-a149-fc3c46dc77e1.json；ID：3b73979c-9cc3-4932-9b2d-0add3d45c2be；SHA-256：fa519703caddf912b98dc0a4710f29148c2a4cbaccd33b1153b61ea0ecd460cb
- model-response-68599896-7251-4bc2-b9c1-c71e47708269.json；ID：a185f333-3496-4f60-9be1-9a89c2548913；SHA-256：fe8b765c5394e1c467497fc401b28c2ab4bc65ee3b92b53f13c200a0eb329f0f
- model-response-691760e6-3776-4f6f-956b-2970f2f9055d.json；ID：607a6017-820e-4c7d-bcc3-882d6962c461；SHA-256：95bb1da1a3269b3c7bcabd9ef5f86cc0f968efbda450a48a7288da6aee511bc9
- model-response-716d3c10-38d4-4e3e-ab25-6d7bbf36d5eb.json；ID：89c58b05-dd06-4028-9b34-5b76f680ce7c；SHA-256：2385e5548b5229dd90e86310e088f01406fb91474f8da08be43af38cabbc9c93
- model-response-717c8be2-b77e-408d-ab2b-35cae113a4be.json；ID：050d9fca-f27f-43a8-b2ac-5bf2698d7a3b；SHA-256：fa21485a5261d0231d4f50892abb92b673b5920f945037b97de95702ec0ef221
- model-response-739093e4-0087-464f-b9bf-f8b0a3d020b8.json；ID：15d6f1d0-bd3e-41ad-85d6-d7eb3fcb3d10；SHA-256：221caac1909636cc8e3e00f190cde8c57ea2a6ef2a8086ffb73b0390dc97c3b0
- model-response-7c2f577e-5a74-4e67-b254-ccccff258139.json；ID：ef65676e-ecac-4260-b6eb-fc4ec2902bec；SHA-256：c3cf3a2018ba864562c5f7a74f010af46a11d13b8f94c75e3f3c4e2e638d466a
- model-response-7d4e0a7d-87f7-4e9d-8d37-c8799fb88a46.json；ID：45fd5a42-bb51-4b73-b247-de9fdfc7263c；SHA-256：624c0d36e7f449ff73e213f842768a63cf2fafb5710f6f552bac94abfbe2b538
- model-response-7e39e507-9af4-4ea2-960a-0a703ef286ac.json；ID：a6436d6d-6352-4b3f-bae6-7c5496f0e768；SHA-256：a695278923b660c3399ea56413513f7a0bbd4413ad6e9f5dce8184013923f482
- model-response-7f40c8ba-6bfd-489e-8996-e45cc8bea3df.json；ID：1c7e2776-e7d0-45d3-8eb2-a0e4e2fdb892；SHA-256：3bc516375f6779e9c9ca1d042dfaade2c9d955eaa0f3fa378edae0ea3c10e2b0
- model-response-8021eb00-56eb-4e95-8bc9-b108b538a163.json；ID：7a6713d9-06b8-487e-8cd1-7d2ba504780e；SHA-256：de7b0a78b5a5d1281b5d054875c3088607d4a20a6d5dd5e749361557f6f62f95
- model-response-820aacf1-8230-4ef7-862a-30c675095cf6.json；ID：7e3155c1-7dfc-45a7-940c-8bf3c66850df；SHA-256：3c2ff937c9b8ef038ca8e2813d287ac64376c444606e70911bce016e3258dd39
- model-response-85d65684-ee8b-4909-acbb-c8db2db66a6a.json；ID：e1f8baa3-4c70-484f-bfaf-1abc7d3c3592；SHA-256：6fbf4a01346cb925070ce16df84598a32c18aa8c72f53c5f12423a4d1dee11bc
- model-response-8692809d-fcc4-4e25-afbb-a1eb6d276fe1.json；ID：bbf0f309-fb10-4b94-acee-f8ca4a2db189；SHA-256：f31f8a95ac92deac5308cf9b47210d779ea57332a7fc4511c0e3e24d15e2a4d7
- model-response-86bc47d2-28d7-4261-9c01-df1c83723ef0.json；ID：795c25ae-1265-4c40-bf38-fa7bec9d31ed；SHA-256：fc7f6536641a9ee7d16ea28b1ea04f5f631abec98b8c430a7958a35e5556437a
- model-response-8723bb87-9717-4783-aa17-da8304986ea8.json；ID：1bf364de-9fff-4058-8139-441fa8c2136b；SHA-256：25fd48255034dfa9ff392c3ac7fd06703d996429df097d1bd33ddfd042a0ceaf
- model-response-8c2fcafb-39d6-4654-8435-19dd75be3f60.json；ID：565575c2-a365-41a8-a6b1-c0bfda45a524；SHA-256：47e5b0ca3cff9d6042be508d1d4c5645e01dbfb0bfa0e55a874c6837c16c6b5b
- model-response-93803018-7433-4aaa-b978-cde8c41c911a.json；ID：f9371cba-2183-4924-8042-163ef9e2f9c9；SHA-256：eb61a23b5da904c32c9d2fac19e60999420d8495085270638b2959998cc4047c
- model-response-981ef2c2-139d-4c85-b116-e0c5e9c6d7ac.json；ID：3a3fd4a0-5319-4994-b793-57d57b088115；SHA-256：56474eff60ecccbf861d793bb08def3d68659d2b51813f9abe53f029d12f327b
- model-response-99d72512-e6e0-4825-9c07-2fa02b92a20b.json；ID：9042c9e5-e52a-494a-8f00-fc8b128c0531；SHA-256：b4ab4b7e7d6d68a63b59e15e9e00df657fa7b313ad7baa5d61b60de3db301bb5
- model-response-9a266dce-bd1e-4a42-96d8-80a108e2e932.json；ID：51922303-657a-4724-b61d-edf99f73b58d；SHA-256：734332141effd3cef8420aa75cf9a21e1884bc3a62fa783318b400ecdfdd8812
- model-response-9d25f1a4-285b-4a10-ab6e-32ccbd9efe79.json；ID：c123510b-e1d2-41b8-84b9-74cb63f03de2；SHA-256：fdc0dbe9bbfa8b6d50082f3fcd46e8a45bdd9cc0d04d82d352e86f42333c74ba
- model-response-9ec81259-c744-4ce9-b870-6c603b0f789c.json；ID：563cdf33-cac9-4a74-a4e4-7d2de286dffb；SHA-256：99f44f1e3933ef4a15502e62055049438ad3c1d58ecb84d0dd60b113de832726
- model-response-ac1475e3-c0d7-48db-bfa7-996d2328b15b.json；ID：5e985041-82b7-47ed-b345-db64fc1f9823；SHA-256：9cd7a3f2653bf98d0bd0a235474a8d491d436397ea34cecb0aea351bb29a795a
- model-response-bb0829c7-bcef-48bb-9245-146a5db9927c.json；ID：f638b95e-046f-4f11-ab4f-614b9add49cb；SHA-256：7fb33e416c530c20d115d4f453e56141b886c8ff9189c16f08cacfb6891102e7
- model-response-c2abf2fb-66d4-42f9-bec0-5a619ac42823.json；ID：572148d4-fd4a-4cc6-b4ec-f163a5eb8cbb；SHA-256：c99c3f56f4121d7e727a7a3a589a2d996039e6a6a89887506370bcfd4ef32e71
- model-response-cf31c7ac-7e13-46f1-8c97-d707be2c6597.json；ID：1e72e8b8-1094-42cf-8a6d-9337e95ae471；SHA-256：921ec6df4205ed113437ae10c1c3add6f027b4d706fcb56f349c64ab0370f33e
- model-response-d5d40623-891b-46a9-a5cd-f168830ec20d.json；ID：e1828e46-a5ae-40c2-b0ca-8f2c0913f34a；SHA-256：b04245d9e9209e7bee41340d4bb8e65230820e710ae6558cec15279c9cf12839
- model-response-d9705a75-b0e2-4a9b-a9aa-1a41eb6d02a2.json；ID：5c74aeb5-09b1-488e-ba52-58c5fe94d128；SHA-256：c00b3efb64ffcfb1235283b5e863c910aca0dbae73cf13b274b27d16f2b13fcc
- model-response-e4d38724-d051-4e86-aaed-709e859110d9.json；ID：5c97e599-3897-4464-bebd-efe12f90d09b；SHA-256：3e692c78c050aedc484071fb71fb37c88e7f1edefec6d3d2c6675f7791e195c6
- model-response-e6a0b907-5506-45b3-99fd-61d47b445750.json；ID：a6b7bd8b-5635-4c76-9bac-0abcb53462a7；SHA-256：39290ef78f80c9eee38f16ad07b3b3e78da80d45c21de5d84d671a685754f4fb
- model-response-ece3b359-a114-4e0b-a9bf-52d82fa79761.json；ID：38099d4f-f7dd-4f0f-baca-a364ab571d1d；SHA-256：5db05ebc3d26250f5532e4f7040edea151c168e1772afbbd5c559adc5ac90c23
- model-response-ef2dc7c8-e725-4c47-b3c5-a09ea50e32da.json；ID：6b023dcd-b2a0-4553-8d5e-a9407c31795c；SHA-256：bd36458faa0f21b7dfef200aa0907b4eeb4367151c44fbd7f2709e6324ce8568
- model-response-f0e92984-8091-4bd7-a039-66836e74450c.json；ID：023d2ead-5053-4189-803d-2216c85a5d5c；SHA-256：9b645a308817dbf5db90ebeb5698e9f5ae23a6b6e7e9d5551de5010cff4746ce
- model-response-f1164fd2-b2d2-48ef-883b-9cb6c570ce5a.json；ID：5e7e6176-9ed5-46dd-a357-0687f54006e0；SHA-256：3af0aa1c3c4b04d017ba227a5fd05fbc71663230d4c381757581bf5d67a372b0
- model-response-f2dc67ac-b749-48fe-8ffc-ee95104ec335.json；ID：42d4e1c7-120a-4310-ba66-26efea159a3f；SHA-256：a8da269ca271f030b1f484b90cae334f030155f756df18de3f66c34f89a4ca0f
- model-response-f8f6c7d0-6c78-4bd6-b8ee-7a6817556ae6.json；ID：7d8057f2-6ebb-419b-a3fa-16fa0b1b51b0；SHA-256：5dfe6f3ab1cfba2811c0bccb446d972925affa03a0d9994ee73e36a1f362bc93
- model-response-fbd58941-b1d7-4d0a-addb-7b50d88994ca.json；ID：a0caa6ba-bbde-45d9-86ab-f761f663b86b；SHA-256：56a53cbbd5c188a0b1a406a37c3ad28ccf21de364b2507f12906513e21b30f6d
- model-response-fc3254ed-0924-48ff-8aa1-e0ede83a9675.json；ID：6ecf4099-4f48-4e1e-8a1c-3c65495b767c；SHA-256：408b52ccf95b6d650c3905d17e95d5b7b5befa142d67b857bc49cf37a3acb933
- model-response-fce76691-65db-4b06-bbb1-a6554254753c.json；ID：1dd82b82-46af-4174-891e-796e99bba35d；SHA-256：a6b57a9554909a2a7b3bf30bab734bb54b35e7b440153edb53832992583adea6
- p03-fastchat-xss-fixed.zip；ID：30baa452-3757-434e-a007-82321edebab5；SHA-256：03b41a7afdbefbb45c921424d0fed63c23dc6bcf11394b8e66bdd3af7b8732ec
- snapshot-manifest.json；ID：a1533fa6-4af4-4303-b8aa-7a1f19d2871d；SHA-256：3516c542ffaa575bfb5c7baeb5766edb65f1010a8cf8b7b4341e9b8bf9840db5
- source-snapshot.zip；ID：93baa88e-cb36-4c88-8d75-11e14ff02019；SHA-256：6733abe3a11878f8a02097e47b8427a6762d420064d442d65920a493ab600fa2
