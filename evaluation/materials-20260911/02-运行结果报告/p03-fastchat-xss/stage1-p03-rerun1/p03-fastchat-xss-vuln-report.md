# AegisAudit 分析报告

项目：对照池评测 20260911-074407

任务：97fb7551-533f-40be-94ca-17b09fd17076

状态：Completed

目标 SHA-256：f0e549546608e38a56149170307630323e16d26e48989301b0b4c75383222421

结果快照 · 数据截至 2026-09-11T07:53:44.880Z · 导出时任务状态 COMPLETED。漏洞审计：COMPLETED；独立复核：COMPLETED；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| \_\_init\_\_ | fastchat/serve/gradio\_patch.py | L26–L72 | PARSED |
| \_process\_chat\_messages | fastchat/serve/gradio\_patch.py | L97–L119 | PARSED |
| fastchat/serve/gradio\_patch.py | fastchat/serve/gradio\_patch.py | L1–L167 | PARSED |
| get\_config | fastchat/serve/gradio\_patch.py | L74–L79 | PARSED |
| postprocess | fastchat/serve/gradio\_patch.py | L121–L152 | PARSED |
| style | fastchat/serve/gradio\_patch.py | L154–L167 | PARSED |
| update | fastchat/serve/gradio\_patch.py | L82–L95 | PARSED |

## 审计策略与优先级

目标是单个 Python 文件 fastchat/serve/gradio\_patch.py（仅 7 个单元，全部已通过一次 read\_span 读取原文）。这是对 gradio Chatbot 组件打补丁的文件，因重写 markdown 渲染，风险集中在外发消息的 HTML 拼接与 markdown 渲染路径。规划按“外部输入/渲染信任边界 → 数据组装 → 组件配置/样式回传”排序：优先 U0005（markdown 渲染与多类型分支）、U0006（把 message\_pair\[0\] 原样拼进 &lt;pre&gt; 并调用 \_process\_chat\_messages），其次 U0003/U0002（配置与解析器构造）、U0004/U0007（配置字典与 kwargs 透传）。调用图不完整、无入口与依赖清单，因此下游调用（gradio 的 sanitization、前端渲染、process 调用方）只能作为未验证缺口标注。

1. u\_ff82c819c39a548e1dd05c9490756faf：核心信任边界：\_process\_chat\_messages 对 str 调用 self.md.convert（markdown2 渲染），对 tuple/list 调 processing\_utils.get\_mimetype 并把 chat\_message\[0\] 作为 name 放入返回字典，对 dict 原样返回。需独立核实渲染是否带净化、媒体路径/名称是否可用于注入或路径泄露，以及 else 分支抛错行为。
2. u\_4c44b8beee6be6500cae2d33fb6f2281：postprocess 直接把 message\_pair\[0\] 与 &#39;&lt;pre ...&gt;&#39; 字符串拼接（原第 146-148 行）产生 HTML，且用 assert 而非校验判断结构；断言在 -O 下会被移除。需核实该 HTML 是否插入前端 DOM、是否构成注入面，并确认未处理分支的后果。
3. u\_28910435557ffa922101acaa97a60097：get\_config 将 self.value 原样并入对外配置字典，属于配置外发信任边界；需核实 value 是否可能包含已渲染 HTML、文件路径或敏感字段。
4. u\_d26da6851cfb7dd83f00bc4711a0f2d1：\_\_init\_\_ 由外部调用者可控制 value（可为 Callable，随 every 周期调用/载入时调用）并构造带 extras 的 Markdown 解析器；需核实回调与解析器配置对渲染安全性/自动执行的影响。
5. u\_760a411d632f31e83bf9cb34c5f7353f：update 静态方法组装含 &#39;value&#39; 的更新字典并返回，是外部可触发的配置更新路径；需核实 value 是否被后续直接用于渲染或执行。
6. u\_e922451480b37e916f5c3db0642b15c5：style 把 \*\*kwargs 透传给 Component.style 并写 self.\_style；kwargs 为外部/调用方提供，需核实是否存在参数注入或未过滤键名导致的配置污染。
7. u\_3ab7a88e4174ab7d10d8718944421044：模块级导入 from gradio.components import \* 与 markdown2：是判断渲染器来源、默认净化行为与环境依赖是否缺失的唯一依据；call\_graph\_complete=false，需以模块级证据标注依赖不确定性。

规划限制：分析范围仅为 STRUCTURE\_ANALYSIS：vulnerability\_audit 与 verification 均为 NOT\_RUN，未执行任何构建或运行（build\_executed=false，target\_executed=false）。

规划限制：code\_file\_count=1、function\_count=6、call\_graph\_complete=false：下游调用方（谁调用 postprocess/get\_config、前端如何渲染返回 HTML）与全局调用图不可见，无法确认数据流终点。

规划限制：Semgrep 状态 UNSUPPORTED（执行器未准备 Windows 原生 Semgrep 1.176.1），无规则扫描结果；所有线索判断均为静态语义推断。

规划限制：未识别构建系统、入口、输入接口与依赖清单（metadata.missing 全部缺失）；gradio 与 markdown2 的实际版本及其净化/转义行为未知，不能仅凭函数名或字符串判定漏洞。

规划限制：recovery=null：无可用的二进制恢复/保护信息，不存在任何已记录的脱壳或反混淆转换，不得声称进行过此类处理。

## 发现与复核

静态结论范围：COMPONENT

### \_process\_chat\_messages 使用未开启 safe\_mode 的 markdown2 将消息字符串直接转成 HTML

CWE-79 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：postprocess 传入的 message\_pair\[1\]（聊天回复字符串），最终可追溯到服务端返回内容/用户可见会话数据

危险操作：str\(self.md.convert\(chat\_message\)\)（第117行），配合第54行构造的 Markdown 解析器

防护缺口：缺少 HTML 净化或 safe\_mode：第54行构造 Markdown 时未启用 safe\_mode/bleach/DOMPurify 类过滤，第117行转换前也未做转义或白名单过滤

前提：聊天回复字符串可由非完全可信来源影响（模型输出、外部工具/插件结果、多用户共享会话），且前端将返回值作为 HTML 插入 DOM

影响：HTML/脚本注入（潜在存储型或反射型 XSS），可窃取同源会话凭证、伪造 UI 内容或触发客户端请求

修复：在服务端对 markdown 渲染结果做白名单净化（如启用 markdown2 safe\_mode 或使用 bleach/DOMPurify 等价过滤），或在组件契约中明确要求前端对 Chatbot value 做净化；不要把未净化的渲染结果视作安全 HTML

- 证据：fastchat/serve/gradio\_patch.py L117–117 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：            return str\(self.md.convert\(chat\_message\)\)
- 证据：fastchat/serve/gradio\_patch.py L54–54 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：        self.md = Markdown\(extras=\[&quot;fenced-code-blocks&quot;, &quot;tables&quot;, &quot;break-on-newline&quot;\]\)
- 证据：fastchat/serve/gradio\_patch.py L149–149 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：                    self.\_process\_chat\_messages\(message\_pair\[1\]\),

复核 v2（MODEL，VALIDATED）：在组件边界内可静态证实:\_process\_chat\_messages\(U0005\) 的字符串参数在第115-117行被 self.md.convert\(\) 转为 HTML 字符串;该解析器在第54行以 extras=\[&quot;fenced-code-blocks&quot;,&quot;tables&quot;,&quot;break-on-newline&quot;\] 构造,未启用 markdown2 的 safe\_mode,且原版 utils.get\_markdown\_parser\(\) 与 self.md.render\(...\) 已被注释\(第53、116行\),因此原始内联/块级 HTML 会被原样透传到返回的 HTML 串,未做转义。postprocess\(U0006\) 第149行把 message\_pair\[1\] 直接送入该函数,组件自身契约\(第130-131行 Returns\)明确声明返回值是 &#39;a string of HTML&#39;,即该未净化 HTML 被设计为交付前端渲染。故“函数参数字符串 -&gt; 未净化 HTML 输出”是组件接口层面的真实缺陷,不是仅凭危险函数名的推测。CWE-79 成立范围限组件层;是否在浏览器触发取决于下游前端是否二次净化,属部署层条件,不影响本组件级判断。

反证：考虑过的防御:\(1\) 原版 gradio 路径 get\_markdown\_parser\(\) 与 render\(\) 均被注释\(第53、116行\),当前实现未保留任何过滤;\(2\) search\_code 对 safe\_mode 无任何命中,本文件不存在 bleach/DOMPurify/白名单净化;\(3\) 第117行仅做 str\(...\) 包装,无 HTML 转义。均不构成有效防御。

待补信息：下游前端\(Gradio Chatbot 客户端\)是否对 value 再做 HTML 净化,本快照无前端代码,无法验证;消息内容在部署中的实际来源\(模型输出/外部工具结果/多用户共享会话\)属调用方侧条件。以上为部署层条件,不推翻组件级静态结论。
静态结论范围：COMPONENT

### 元组消息被转换为前端媒体引用字典，文件路径未做校验

UNKNOWN · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：chat\_message\[0\]（消息元组中的文件路径或 URL）

危险操作：返回 {&#39;name&#39;: chat\_message\[0\], &#39;mime\_type&#39;: processing\_utils.get\_mimetype\(chat\_message\[0\]\), &#39;is\_file&#39;: True}（第104-110行）

防护缺口：缺少路径合法性/目录白名单校验与协议限制（未检查绝对路径、.. 段或远程 scheme）

前提：消息元组内容可由攻击者或上游模型/插件影响，且前端或框架按 name 读取并回传该路径的文件

影响：在满足前置条件时可能读取服务端可访问的任意文件并以媒体形式回传给客户端（信息泄露），具体影响未验证

修复：对 is\_file 的 name 做规范化并限制在受控媒体根目录内，拒绝 .. 路径与不受信任的 scheme，或在服务端仅接受预注册的媒体句柄

- 证据：fastchat/serve/gradio\_patch.py L104–110 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：            return {                 &quot;name&quot;: chat\_message\[0\],                 &quot;mime\_type&quot;: mime\_type,                 &quot;alt\_text&quot;: chat\_message\[1\] if len\(chat\_message\) &gt; 1 else None,                 &quot;data&quot;: None,  # These last two fields are filled in by the frontend                 &quot;is\_file&quot;: True,             }
- 证据：fastchat/serve/gradio\_patch.py L103–103 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：            mime\_type = processing\_utils.get\_mimetype\(chat\_message\[0\]\)

复核 v2（MODEL，INCONCLUSIVE）：U0005 仅对参数做类型分派与格式化：当 chat\_message 为 tuple/list 时，把 chat\_message\[0\] 放入返回字典的 &quot;name&quot; 字段并置 is\_file=True（103-110行），函数内部没有任何 open\(\)/路径拼接/文件读取或媒体服务逻辑，get\_mimetype 也只做类型推断。因此组件边界内不存在“读取文件”的受控操作；被指控的任意文件读取只能发生在未提供的下游（gradio 前端/媒体服务）中，且该下游是否会解析、拒绝 ..、限制目录或协议完全未知。组件确实缺少路径规范化/白名单，但这只是数据流上的缺口，尚不足以在本组件静态证明任一文件被读取，故不能判定 VALIDATED；同时存在下游校验的可能，也不能据现有源码判定 REJECTED。

反证：未发现本组件内的文件访问或路径解析（无 open、无 os.path 拼接）；输入来源 chat\_message 的具体可控性、下游是否有 is\_allowed\_file/path 规范化等防御均未提供，无法据此反驳或证实。

待补信息：1\) 消费该字典并真正按 name 读取/回传文件的组件（gradio 前端媒体服务）是否存在及其实现；2\) 该下游对绝对路径、.. 段、scheme 与目录白名单的校验；3\) chat\_message\[0\] 在真实部署中是否由非可信方可控。
静态结论范围：COMPONENT

### postprocess 将消息对第一项原样拼进 &lt;pre&gt; HTML，未做转义

CWE-79 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：postprocess 参数 y 中每个元组的第一个元素 message\_pair\[0\]（用户/调用方提供的消息文本）

危险操作：&#39;&lt;pre style=&quot;font-family: var\(--font\)&quot;&gt;&#39; + message\_pair\[0\] + &quot;&lt;/pre&gt;&quot; 字符串拼接（第146-148行）

防护缺口：缺少对 message\_pair\[0\] 的 HTML 转义（escape/quote）或结构化 DOM 构造；第145行注释掉的 self.\_process\_chat\_messages\(message\_pair\[0\]\) 表明该路径没有任何替代净化

前提：调用方或用户可影响 message\_pair\[0\]（客户端自报消息、上游服务转发内容），且前端以 HTML 形式插入返回值

影响：注入 &lt;img onerror&gt;/&lt;script&gt; 等标签后可造成会话内 HTML/脚本注入；若消息被持久化或转发给其他用户，则可升级为存储型 XSS

修复：对拼接进 HTML 的文本统一做 html.escape\(\)（并设置白名单），使用 &lt;pre&gt; 文本节点或结构化对象代替裸字符串拼接

- 证据：fastchat/serve/gradio\_patch.py L146–148 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：                    &#39;&lt;pre style=&quot;font-family: var\(--font\)&quot;&gt;&#39;                     + message\_pair\[0\]                     + &quot;&lt;/pre&gt;&quot;,
- 证据：fastchat/serve/gradio\_patch.py L145–145 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：                    # self.\_process\_chat\_messages\(message\_pair\[0\]\),
- 证据：fastchat/serve/gradio\_patch.py L149–149 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：                    self.\_process\_chat\_messages\(message\_pair\[1\]\),

复核 v2（MODEL，VALIDATED）：在组件边界 U0006 postprocess 内，符号化参数 y 的每个 message\_pair 的第 0 项被字符串直接拼进 &#39;&lt;pre style=&quot;font-family: var\(--font\)&quot;&gt;&#39; 与 &#39;&lt;/pre&gt;&#39; 之间（146-148），该分支不存在 html.escape / 引号转义 / 白名单 / 结构化 DOM 构造；与之对照，同元组第 1 项仍经 self.\_process\_chat\_messages 处理（149），而第 0 项原本的处理调用被注释掉（145），说明此路径被刻意绕过统一处理。输入来自函数形参（139，def postprocess\(self, y\)），循环 append 后该值直达拼接点（143-150），因此本组件内“参数可控 + 可达 + 无净化”三者均可由原始源码支持。需要强调：本结论仅为组件级静态判定，不等价于已部署 HTTP 服务被利用，也不改变候选中级严重度。

反证：第 1 项经 \_process\_chat\_messages（149）表明项目有集中处理习惯，但不能证明第 0 项受到同样处理：该分支是完全独立的裸字符串拼接，且 145 行的注释明确移除了这一处理。&#39;&lt;pre&gt;&#39; 只是显示容器，HTML 规范下不会对被插入内容做实体转义，因此不能作为防护。断言 140-142 只校验消息对长度，不涉及内容净化。未发现任何 escape/sanitize 调用覆盖该拼接点。

待补信息：1\) 下游消费方（gradio Chatbot 前端）实际把返回 HTML 字符串写入 DOM 的具体位置与是否二次净化，本组件不可见；若下游再做净化则利用链在本组件之外断开。2\) message\_pair\[0\] 在真实部署中是否跨越信任边界（仅同一会话用户自报的自我 XSS，还是可持久化/被转发给其他用户而升级为存储型 XSS）无法在本组件内确认。3\) 本环境对 \_process\_chat\_messages 的读取输出不稳定，未能确认其是否做 HTML 转义，故仅以其作为“分支被绕过”的对照，不作为净化存在的证据。以上属残余条件，不改变组件内数据流已成立的事实。
静态结论范围：COMPONENT

### postprocess 使用 assert 做输入校验，且假设 message\_pair\[0\] 为字符串

UNKNOWN · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：调用方传入的 y 列表元素 message\_pair

危险操作：assert 校验及随后的字符串拼接（缺少显式类型/内容校验分支）

防护缺口：缺少非 assert 的显式校验与安全类型转换

前提：应用以 -O 运行，或调用方返回不符合约定的结构。

影响：校验被跳过导致下游拼接/转换异常或行为不可预期；异常消息可能回显调用方数据，造成信息泄露或报错路径差异。

修复：用显式 if/raise 替代 assert，并在拼接前规范化类型与转义。

- 证据：fastchat/serve/gradio\_patch.py L137–142 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：            assert isinstance\(                 message\_pair, \(tuple, list\)             \), f&quot;Expected a list of lists or list of tuples. Received: {message\_pair}&quot;             assert \(                 len\(message\_pair\) == 2             \), f&quot;Expected a list of lists of length 2 or list of tuples of length 2. Received: {message\_pair}&quot;
- 证据：fastchat/serve/gradio\_patch.py L147–147 ；产物 dd4cad93-896d-4336-80fc-c6ebd5d24a7a；引用：                    + message\_pair\[0\]

复核 v2（MODEL，REJECTED）：候选类别为 INJECTION，但其自述的“注入”落点是 U0006 第147行的字符串拼接 \`+ message\_pair\[0\] +\`。该操作不是注入汇聚点：当 message\_pair\[0\] 为 str 时拼接正常完成，当其为 Tuple/List/Dict/None 时会因 str 与序列/对象相加而立即抛出 TypeError，不会静默地把数据拼成可执行/可解释的代码或 HTML 属性（HTML 包裹仅发生在 str 情形）。因此“结构校验被跳过导致下游拼接注入”不成立。至于 assert 在 \`python -O\` 下被剥离，这只是部署期解释器开关导致的健壮性/调试差异，属于纵深防御建议，不构成本组件接口层面的安全缺陷；候选本身也承认“本身不构成可利用漏洞”。错误消息回显输入仅在 assert 生效（非 -O）时发生，且未证明该文本可被外部观察，属信息暴露而非注入。

反证：第137-142行确实存在显式结构校验（isinstance tuple/list、len==2）；第147行拼接在类型不符时抛 TypeError 而非执行注入；不存在 eval/exec/模板/SQL/命令等注入汇聚点；候选所谓“缺少校验”与源码不符（校验存在，只是用 assert 实现）。

待补信息：部署是否以 -O 运行；assert 失败信息是否对调用方/用户可见（是否构成信息泄露路径）。

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
      "本次仅有静态审查，dynamic_execution=NOT_RUN，全部 finding 的 verification_status=NOT_RUN，无法证实或否定实际可利用性。",
      "审计范围限于 7 个审计单元，未被这些单元覆盖的调用方、配置与部署环境属于未知缺口，可能影响结论（例如 safe_mode 是否在别处开启、媒体路径是否在上游已受控）。",
      "INCONCLUSIVE 条目反映的是证据不足（动态分派、跨组件契约、未知部署），不应被视为风险不存在，也不应被视为已确认漏洞。",
      "REJECTED 仅为评审阶段驳回，属于健壮性/风格范畴，不构成安全结论；如后续发现该断言可被外部触发导致崩溃或逻辑绕过，应重新评估。",
      "人类标注为空，没有可交叉核对的人工参考；本摘要仅复述已保存的 finding、评审状态与覆盖范围，不新增 finding，也不提升任何验证状态。",
      "缺失的运行时证据、动态分派目标与部署细节均保持为显式缺口，未做推测性结论。"
    ],
    "recommendations": [
      "对静态态标记为 VALIDATED 的两条注入类 finding，在合并前补做验证：确认消息内容是否确实来自不受信任输入、服务端与前端之间的净化契约由谁负责，并以最小复现用例记录结果。",
      "针对 INCONCLUSIVE 的媒体路径转换问题，补齐调用方与数据流证据（消息元组的产生位置、is_file/name 的来源、媒体根目录约束与 scheme 校验），再决定是否升级为确定 finding；在结论明确前按未校验路径处理。",
      "为 REJECTED 的 assert 校验项保留为代码质量改进项（以显式 if/raise 替代 assert，并规范化类型），但不要计入安全漏洞清单。",
      "在服务端对 markdown 渲染链路统一执行白名单净化，或在组件契约中明确声明由前端负责净化，避免出现双方都未净化的空档；同时避免将消息文本裸拼接进 HTML。",
      "所有 finding 均缺少运行时证据，建议安排动态验证（dynamic_execution 由 NOT_RUN 推进）以确认可达性与实际影响面，并同步更新 verification_status。"
    ],
    "summary": "本次审计为纯静态审查（dynamic_execution=NOT_RUN），共覆盖 7 个审计单元，未产出任何动态执行或运行时验证结论。数据库已保存 4 条finding：其中 2 条经独立复核标记为 VALIDATED（markdown2 未开启 safe_mode 直接渲染消息字符串导致的注入面；postprocess 将消息对第一项原样拼入 <pre> HTML 未转义导致的注入面），1 条标记为 INCONCLUSIVE（元组消息被转换为前端媒体引用字典时对文件路径缺乏规范化和根目录约束，静态阶段无法确认实际可达性与信任边界），1 条标记为 REJECTED（以 assert 做输入校验并假设类型，属于代码健壮性/风格问题，未被认定为安全漏洞）。所有 finding 的 verification_status 均为 NOT_RUN，即尚未进行独立验证复现；review_status 仅表示评审阶段的结论分层，不等同于可利用性证明。本次人类标注列表为空，无参考标注需要比对。结论应理解为静态代码层面的可疑/成立风险与缺口记录，而非已证实的漏洞或已被利用的证据链。"
  },
  "audited_unit_count": 7,
  "edge_count": 19,
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
  "finding_count": 4,
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
    "target_sha256": "f0e549546608e38a56149170307630323e16d26e48989301b0b4c75383222421",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 74,
    "cost_cny": null,
    "measured_tokens": 383616,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "dd4cad93-896d-4336-80fc-c6ebd5d24a7a",
  "reviewed_finding_count": 4,
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
      "finished_at": "2026-09-11T07:44:10.114Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:44:10.112Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 7,
  "unresolved_calls": 19,
  "verification": "NOT_RUN",
  "vulnerability_audit": "COMPLETED",
  "warnings": []
}
```

任务错误：

## 证据产物

- aegis-report-97fb7551-533f-40be-94ca-17b09fd17076.html；ID：9bf0cc76-e485-4511-9a8a-53e9547537a5；SHA-256：58c6578568dde8fcee0657dfed4cc8bdb261a50904fed7abacb37ef3cb6adb9e
- aegis-report-97fb7551-533f-40be-94ca-17b09fd17076.json；ID：b7ce72a7-84f8-4c27-9384-20b10cec9c43；SHA-256：733d016595e87367da2b31ef52a874177524b5bcd845fc62633d31fd5f7510a8
- agent-AUDITOR-36bbb6be-1d7b-4db8-accf-08ddb47833c5.json；ID：9e234d71-81b0-4c27-ba79-0fa36e2031ab；SHA-256：48595009e5f0d09e9d1ba5339aa70e28b031fc903fb954bfc9c126e0672fae34
- agent-AUDITOR-439effd7-ea3f-4de2-9079-3c2e192c6bbb.json；ID：47cfb889-8290-4b70-bec3-cf15debbe23b；SHA-256：8b5fe1cc78215559445bcd9b35f1aa610741258ac858abc22625cf21e75d4c43
- agent-AUDITOR-9ea0e606-f8ab-4c18-9a56-0cce47a8d679.json；ID：0b1d2659-f391-47ea-80b2-66a75f855ad3；SHA-256：eb05f4f0a92e3e9a2e47b5f05366586a24569c6a522274707ce1871d1a00b309
- agent-AUDITOR-b568ac22-ba61-4215-aa34-be9c41fb85a0.json；ID：f0ddcc89-7c60-4f22-8fcb-483eb42cf010；SHA-256：e6ff56c20f6fc4b7cd12a6507a79d7c54a0a10a4cdb83edce6ab47eb73461f73
- agent-AUDITOR-c2789086-3822-43dd-b498-7b06ad81578d.json；ID：f3b1c5f1-005a-4745-ac9d-a52d7e86d88e；SHA-256：2ceed69f9f706c583c58faf78ff0b1f18db29a35fa1de997211e335e3e960156
- agent-AUDITOR-c6d11593-6684-48fe-abba-9fb8829e2cc2.json；ID：236cdf9e-3e79-4de8-a948-8e8596b31440；SHA-256：fc896504d02315083d9d0f4def5af6d3d9d270d46a76ceaf0327062241fee947
- agent-AUDITOR-e6334c07-0779-4c6a-8464-f97b4444e91a.json；ID：5c2e92f5-3cd4-4517-a061-359ccbcce94a；SHA-256：0e17118ba832de5497c347a46f3e4bbf9440447ed9268cb0b4b459c58fd03a23
- agent-PLANNER-b02b8a31-fffa-48c4-a2b7-d5df6845f206.json；ID：d048f0a8-6bbd-45c0-8f5a-d87909d88ffc；SHA-256：c315298e756e4fd6cadd565beef2d05c1d379886a60ff2ad101796315542af07
- agent-REPORTER-cd34b7a8-a80c-4ab0-a6d5-20b0651bb5e0.json；ID：a87954a9-cbd8-4017-a7a9-f0c8aa9f4a0c；SHA-256：c0edc79af0463e2e3e1cb3593cb4b2d06b311e4b3eba0380149a9f44dc8a4a95
- agent-REVIEWER-3352de47-8580-4cc2-a998-54650cd421f2.json；ID：796ae26a-41f5-4d74-a841-8698baf3f7c7；SHA-256：2cfa547af325bc3cfa93a5132b8815dd0e8462d68a91c31444b0b6bf4a1893ad
- agent-REVIEWER-48f85cef-7271-4cfc-ba4e-f7ed4ba97ec6.json；ID：0c5a1b23-5f14-41f3-8251-ced30246c553；SHA-256：c6fc4e815bba6b8a4f3a8348944fca65011ba50c52ebff246b861cee5182a060
- agent-REVIEWER-59fcffcb-4aec-4876-aa51-20eb91f7796e.json；ID：81ae883b-9522-4b2d-9198-35034752bb4d；SHA-256：d3d4b9f4ad16039e50e5f37c5ef9cbc012e30c9c3cdfe296cd05c54f0e8128e5
- agent-REVIEWER-bdb628e0-b076-44ee-95f2-3d91d862f25c.json；ID：99654c66-aa08-45bd-8be8-39fd477a380a；SHA-256：2128cfb6f5bd83b8bae64befe38be129e86e598208e3ef0e2fdd4af30eb9596d
- agent-VERIFIER-206f605b-c250-4926-9886-1d7ea41f2118.json；ID：5620de5d-a443-4a66-a1a9-c92ca4dcb145；SHA-256：30f1d044ea10ae97de796269c96aa2d896b478fe16b076fdb951594e03093eba
- agent-VERIFIER-65c7821d-3a74-4d33-9680-6cab6dc1f037.json；ID：783f08d6-9965-468a-b7fc-bc8956581d74；SHA-256：8eacc713437f7f42d1fafcf0d61ec1983a9b119eca296b7a4eb3f8558b374d2a
- analysis-result.json；ID：dd4cad93-896d-4336-80fc-c6ebd5d24a7a；SHA-256：4ab8b0da775892ba5a8fd69ac59553a7609140c07e0799eb789e3a67d069fc69
- model-request-0449b43a-f329-4b3e-9808-936ad0676cba.json；ID：3909ef94-7bc3-44f0-8d01-1e669fd0f9da；SHA-256：1c732a87f1f42c51b5102e4732744cc6b6b878e2eaeb62a435e65d7c12a49caf
- model-request-04b36cd8-3ebc-4e23-a2eb-cb25d53b4722.json；ID：eb6767f5-21e2-448c-8a55-5281f789e6eb；SHA-256：2773313b16c264893bd522f62c784e136e902c3bc55be41daeae2cefc967aeae
- model-request-09790554-a7e5-4d23-aa47-db2fbf2b8092.json；ID：ba037433-1364-4e57-b4f1-9923a3d76b1a；SHA-256：cee9c3ea9e53f921fb81b285572f8c8eba564af106cfdb49284028a7a0390e2b
- model-request-09e2cd9b-8754-4ff9-8ed5-f7b1ac2bc601.json；ID：e9da9001-c8cb-4f53-b8e0-81f26fdcee98；SHA-256：edb224c26f3e249744d8bb5d13efc47d0938bda47b8e14208902eb2b513784d7
- model-request-0aa7751f-a953-490e-b210-6deca53088b4.json；ID：8ec62923-5642-4d1a-82ba-abec649f4435；SHA-256：df2695454156625bcd01862bb30e3b8874bdf76258410fd5d3c6e7ac2cc73202
- model-request-0cda218b-4896-4d78-9634-a693531d58e8.json；ID：3a270e46-6683-4981-a9a5-2f351e77f3b9；SHA-256：f16656ed0a8e64378c92cb5e4d7e7ae149bddb3869c6bb0c74086f592102ec4d
- model-request-122f2119-60da-4351-afda-7625928604da.json；ID：46e02295-27f6-496e-b99f-afd97a4c8308；SHA-256：5c2746fbd8fff8e1dfce4dd3caaccb5fc1b3b199cdc42c4180ebce9895c61117
- model-request-13a8deff-c38f-406a-80f8-ab2b926f9e69.json；ID：a632b998-6350-4d91-aa5e-49b087d29f55；SHA-256：24ca5b52e2b13ea4a62dc0ef970be95caa28d28a870c7cb77dbb7472d07c7dad
- model-request-1681aff2-f8b0-462d-a854-344cb9cdd9d9.json；ID：00e726c9-b086-4928-b0f9-46ee0ad26c49；SHA-256：8dd3071c9ee7220287acfb692c243ba326ac181d0714e1d4890e95d012db2c62
- model-request-18d2aaed-d735-4f38-b388-1cc7afba1b4c.json；ID：282262ea-a120-480d-a3db-35c88fb6eab4；SHA-256：ccdaeea49ef429d60b47229f0db9cb53cda6f085793665fbfb0f05d4a52aae88
- model-request-1b935bbc-8a38-4372-baf9-1056f8c9f0a3.json；ID：3fdcbba2-9d15-4e70-968f-121082e28f04；SHA-256：654951a7958508f3b844766e7515972f5ee4e2180e06fa2c364a12e949720544
- model-request-2c8a56a4-8a7a-4915-a4c6-e7e0ce77e94e.json；ID：49dd5116-d4c5-4772-8efc-0bd5621bfc3e；SHA-256：d41c5abf938db3222239747ea9a18ee51fea6970baa881e07c6f9a20057b573a
- model-request-2d1ce69d-02b0-4a2a-bc29-5ac623818746.json；ID：8b9f13d8-61d2-4956-8cb1-53c550c26013；SHA-256：50610e756fda98567d325e2b78eee3dc7f0fb273925bb8c042a39d38efaef966
- model-request-3a16d4cf-5698-4e45-8584-e4ecfca217a5.json；ID：2d29730a-2891-4264-b4b8-b05e7404af6e；SHA-256：31888463bcc25a396180b9c907cb9b94c9db785034f0e91a7cc43bff2e8fa824
- model-request-3fd3c0ff-ee5c-44b1-b6a6-276977f97c17.json；ID：243af278-bfff-47b9-8cbf-cd95b97e8268；SHA-256：32cdb14a60bf1814d38f8f15c29f484be86fcefae0a2c5c665003608d379afca
- model-request-4039ea07-b9d9-4a8f-9fbc-552e7d603e57.json；ID：327b47ee-dc32-4d22-91a5-01e292bd5315；SHA-256：7aeae18c351d17357d22761794e73fb5b5a102a637dabb96b261f3e0f383d9cd
- model-request-46f6f680-3600-4c7d-ac22-d873b0fc3fad.json；ID：a4a66211-123b-4f36-8673-d7f0d975559c；SHA-256：f319ed20ae56e76bcf90c4b5e751d8c356bf5df5d8c4e44ab4af73c988c7dd2b
- model-request-49bed462-37f9-4cea-9208-19cc0aee2f11.json；ID：af9c66c9-9368-489d-af76-303bea028652；SHA-256：85edb51617a6e65bb16ec84dc936d1e724bbfd8e60f01badc2365daf2a46befa
- model-request-4d946125-6c4a-49ab-ab67-43601d341e8c.json；ID：c59bea21-86ad-4ee2-9933-848fe8547fe4；SHA-256：120443d0536045dfbfc96a1a3527c56537eef7fdbcbcdb7addbfffc774ad2a03
- model-request-520aadbb-f76f-429d-bfd6-04fbd4054ce9.json；ID：add1bfcf-8ad1-4e28-8021-f909677f5c3e；SHA-256：21ea0cf2e9ac3bb9848ab8ca252ad6e4517045aee18bcc0d3e245b578ce89496
- model-request-5244d71a-ce28-495b-8b52-0c4b73e90750.json；ID：fac108b8-5cc6-48dd-b4e8-45d7c932e956；SHA-256：237162a7f2e0f6d34e46aee28e7dbff6c01e380dcf7353106b2f19072f81e87a
- model-request-5629b720-4e0a-4df5-9d8c-3b150a2a63ee.json；ID：9411d920-8ebc-4119-a348-77328162f15f；SHA-256：ad0cd86077a527fa6a743dbff9bd1dbc1ab260d6e63732f4514322e9c515e412
- model-request-5db3277c-4bf9-48f9-8d99-6eac021b1fb0.json；ID：9d2c382b-2b4b-490c-9be0-5197ff98b757；SHA-256：bcf8e1cf74640f12ebec5bd5ad136835a7e0ecf5fb40da32680fdac137be7d99
- model-request-606046e4-210c-498f-bfb0-c1d15936d593.json；ID：e3b9fd51-be2b-4db1-a7f6-484925b6cffc；SHA-256：55d7c552091322fa28a6cef6d46a17c9431227a2c00ebcf5c59464bc8083ec96
- model-request-63b3659d-9e56-4f13-85d7-6ca1ef458c49.json；ID：845792f1-8f36-41a8-ad99-60c24263304d；SHA-256：e43711b5c61261fa0d0faf1236948a0aadd88d5cfbc48a19ace01abeb3cb81a6
- model-request-65773707-fcd6-47dc-9a70-643ca4b7d026.json；ID：c9602950-5833-404c-a415-66b010efd1fd；SHA-256：7d177ae40a356338ad183be0fa8907cb3d471c2ce6f6988fd91ab28444eb34b0
- model-request-66fc5375-7f05-4d6d-888b-894a343e1eaf.json；ID：9b86a2c4-44c2-414e-9fe3-a1c70565053b；SHA-256：6375c67a4422e29208e9c7df2e1c20cf9d552cf3ed70b7f72f60a54629e5dde9
- model-request-67cb07dc-17b9-4d38-9d13-5d1dc85074ae.json；ID：cdd290c6-1029-422d-b634-8f1ec4653566；SHA-256：47aee5157b3532c20123407578b0aa2de4b1dd05da0de4157a8e73f00d06799e
- model-request-74fd36ca-d1ab-41b1-b7a1-4f446fcc6acd.json；ID：2b9e853f-9b1b-468f-b236-877ca86e3051；SHA-256：2348e9548e243a113957217f15bf9e5c9e4dae70d523a8bae5092237f864d295
- model-request-75ef3326-d459-419b-b970-76e78ef6cf5e.json；ID：8d70df0b-ed23-4c30-8b4e-b3441d08e037；SHA-256：b2c4750d894ba2b0480047c4a807a8d86480bd352110e240d859c33794d15b5e
- model-request-7638e408-7617-4b53-8891-393d14e0c17f.json；ID：a9550e07-3283-4e04-bd63-7052fd441c2b；SHA-256：914e9b3e33e323b1b431a0f2cf16f0bd350b1e415156a1c6e4b3dc9236e9222e
- model-request-776bc1cf-9d75-4200-9bc0-696cc3440393.json；ID：0d812320-8232-4e5a-bc0a-ece860c05867；SHA-256：316938ccb7f5dffc945e9281885ec2f1e04b8fa222689ee243531321506d187e
- model-request-797a4538-1b76-4393-b3e7-0ed82c973e13.json；ID：ca9167c7-04a9-4dcf-81df-cdeecccc1c30；SHA-256：5400f420748ce9e6ac58eaf4211a89b62ba34175b052b834e865306a37a56783
- model-request-79e2606e-8126-4f9f-98bf-7f73bd1b3aff.json；ID：7ceaf546-daf1-46a1-bee3-a80fc542e9b4；SHA-256：abecdb87680f5254242e44871094e6f3abe93ed4bceac96af74291e6e163c6a1
- model-request-7e4434c7-212c-455b-812b-9587461dd33e.json；ID：55196c5d-0903-49e1-b661-84552e746ce2；SHA-256：8cff6bec1d7a7fcd4df5c657887cccc7642905a8b2dd9c293cde5b463fe1a022
- model-request-80c7b39c-5606-4a34-8ced-174286ea67e1.json；ID：933ff848-5504-4181-b7a5-83c08e13a55c；SHA-256：d0a85dcfd385fb07fb8787e3724263180a59194f64337f7218df689800d61d05
- model-request-81037766-c801-4210-9f6e-372d8bdd5bd4.json；ID：ad1cdb77-6b7d-4d69-bad0-7da7b45a7e47；SHA-256：e1c9caa4b8c75522657235e82cf036ee82737f0c3e48ef83036c4e3a3101f250
- model-request-879ff0b8-b136-4882-a600-e3785e47ceab.json；ID：e9425831-056b-45b4-8648-f837b87477d7；SHA-256：71bdab724c714394eb2e6a0fdb57f9e9d9654c49711a9df2315ed43030d1016d
- model-request-88267271-81c7-4e07-9a33-f836201c584b.json；ID：b0273f88-b7cc-4126-a5cb-69e0d9fdf6c8；SHA-256：4c00485fb3975ba435dc40bbfcc1c9ea1b77d386cf609f12c7cbdaf1bbab8e84
- model-request-8ddc0469-074a-4de0-84b3-ab5421cf592a.json；ID：cb1f41b8-a2ef-4c8e-8d63-186ed20a40ed；SHA-256：3e0558913ed2cd540d0030a08a66eea9cd4712625e08e8d690bed6c202a21917
- model-request-8e97764a-f5de-4eb1-be7d-6e972ff41885.json；ID：d1bf6c40-aed5-4cfc-9c34-d59b3bc7f9cb；SHA-256：eb3ce19334e18b3d465d3b16462cfaed7e6beab27557872106be1838e510e72a
- model-request-9370572a-07c9-4ab7-9ed4-618117fc9169.json；ID：22eadd10-a549-4309-8792-1efc633405cf；SHA-256：ee271f800237542be5a89eef8ecf7ad149a1be9d9013cb336e1f9fb5d59001da
- model-request-9378b438-d741-4d93-bb44-57a40f974e86.json；ID：9a56ceaf-3b50-459a-bd6d-2454ba03d4d0；SHA-256：1bf7cbed14f7e5b0a739731640104fe6ae5c231b526eee3fc510c8daa1e57705
- model-request-93f42be2-19d3-44aa-9e38-03f6582fa597.json；ID：1b94a81c-799e-436a-bb30-f5ca898fd6c0；SHA-256：bc45bfe45539741e6f5317c3ca96dc0e92ceefb04e8cf32d942753cf06b11b63
- model-request-9823a3f0-0125-4616-8889-e0cf9a01b111.json；ID：7d435b88-78c6-4fce-af98-c7216d45a49c；SHA-256：0d09153f385759ec0557e3cb8a08353762dd417c541c5c2e4e2578386a4b4617
- model-request-9d464efd-2e43-43c8-9036-67c62ed73b2d.json；ID：12b3f00d-018d-4c8d-bbf7-dc2af321cfcc；SHA-256：9c74c134522e0ba961353eb7ff9892bc44cc2d1114c9c1f963ff445121168653
- model-request-9dceb07f-3941-4658-8a73-84b18c25f702.json；ID：6a5c3c08-d9ca-4b5f-90ec-845f37069714；SHA-256：e72d9ed827b1c5b13b2cd31fcabc5abe29aab2be90ad34319782df3f6dc32195
- model-request-9fc084ab-6321-4041-8619-99360220a8e8.json；ID：bbea1543-6a76-488d-9ca1-b8e8acb8eeb4；SHA-256：1e5a5a79b3d99c11100761e187a4e54baec3a610b8c1cc3cf1b69054386b12af
- model-request-a34905ee-cef4-48bd-8be8-66a618f23bd2.json；ID：8738d658-9ea6-4644-b917-ba8da9b59534；SHA-256：d0d3a09757df83b198c6514c0563f3811f49b39129f84bd8fd9da61a70400c2f
- model-request-a42397fe-7817-49a1-91d2-c4ccd4badfe4.json；ID：0a320234-4ba4-4b8d-b25f-ef78c45e727f；SHA-256：70692cd0b6b1bfb4004f54602110d2404b51cbc6a0e26c228ab8554e7fdc243c
- model-request-a8ae9ad3-e2a4-4e40-b778-9b27da39352b.json；ID：f3d9300c-8591-4489-a667-e27be98f2498；SHA-256：209d3a5c3576ef887187c64fcd730c95512fd8701891bdaab9fd9c4f7d18519f
- model-request-aced610c-2a6b-4271-b95f-27ae71b1fcbc.json；ID：36a5d724-67dd-4883-801f-e3cfe87d4aa0；SHA-256：8b06f6265d54ae8058b0353ab86d41a82cd9846f42db8cf584daa2770ce5a8a3
- model-request-ad6daf7d-896f-45a2-b3b7-3ffab019236c.json；ID：c5303775-2da5-464c-b814-45730cf9469c；SHA-256：ef49e361efc2afc8e0c6517e5b99f6eda2f9e6c4d073157ea41926c79c11831f
- model-request-ae84035e-0e6c-4167-a83a-db8e6f963b14.json；ID：e86ea2c1-193f-4060-8736-fbfbc6fb5478；SHA-256：97698cdeefdf750fe54f27e7db6a155fcd7d722c2df9e4baf30858b93d9abf45
- model-request-b63834ea-a396-4ea2-aa76-e1e963371e14.json；ID：0a069735-da7c-4ef3-aa35-4a0f4d2a0688；SHA-256：40e03622ac63507a1834f96fb41f66ae5fec3bb58b107f3bf52992d4f83cbe14
- model-request-b9e98f1a-675d-43f0-ab45-8c1f3f7106b6.json；ID：bc80a08d-a378-4748-a8a5-46a1e00e2363；SHA-256：13de7561b6d0da2fd2a9519b167eabbfcc53ed57bc296aa156e48bce5b4171c5
- model-request-ba3d71a5-c121-4d2d-814e-c342d197396f.json；ID：feb0d747-f4e7-434b-8289-a5622eb8a5ef；SHA-256：fe629bae3aa0279e8036e526f3aca56103f30288e4271cd275c97579374d70fe
- model-request-bbdf0f59-ce9a-4777-a026-970a298c25c7.json；ID：3031041a-ac7b-411d-bdc6-86909fda05ba；SHA-256：cbb1a00d809c3d6fbf5da3cde6f0e1e7d0a487f8aae5a8cbb4cb08425b1fe1a5
- model-request-bcb421a8-b734-44b6-840b-85bebb06e8ed.json；ID：e25ba333-ea6e-48f6-b8a0-8b076104469f；SHA-256：436a9bf993597d90f17b57fbfa50c9574841f36c7d5d4759497b7e165a133916
- model-request-bea338a3-2375-41a6-8a1f-62a56280dbc5.json；ID：5ec4f0b1-7966-4b68-a27d-6e985b242d1d；SHA-256：c1b4c399fd31f2ab72d4fac0c15e2997a2830288b9a10c93ed291b7c1a943ece
- model-request-c353a82d-3dc8-45e1-ae9c-9e92fb4424d0.json；ID：6298f4d3-fe25-4bfb-903c-b45dbff6df08；SHA-256：8be4eef0244b4fdd81ff9a725de937bfda57d42f3b27c8fc1f4ed0f61389dfa4
- model-request-cedd27ed-94e6-4b4d-be51-665d410d43a5.json；ID：3f332bb0-747b-4e03-a7b1-a9d53c26df51；SHA-256：b6d83d4d2d43607fe21acb3e0a35280550924de8c947f93d3b92e811b98e3ca1
- model-request-cfa2fdb8-9d13-4cba-8c9c-b905e28a8365.json；ID：acf1292b-4c8a-4970-bbe0-ea67a26cefcb；SHA-256：ae164abdd43f55d5053860fa9fd17aee32219375de2095f8f47c6d3058392f5f
- model-request-d098c013-fc04-4e0e-9bd5-f5d5c77e4b79.json；ID：ad6b38d2-4ce8-4a33-826a-3d453234df36；SHA-256：4a78ac321e44ed26ee2df56e471b6c348b51e2d050c3e1a8a0a422c11e441f0c
- model-request-ddf1d87f-c83b-4360-9695-70d92a4e3f8f.json；ID：c052575c-b40c-4d1f-a199-cfbc6d4edaee；SHA-256：a1230e68d40e13b188a65573dc6c19a3225b8e37a44da0d38ff97ee315266910
- model-request-e953089f-702f-46bd-a0cb-2e34a354312b.json；ID：94232272-abda-4848-9490-9a21d18978f6；SHA-256：6bdd614e8a07e7bd5b3f9e85b10e0117e5549ea34ab126ffc599d626e0d54d75
- model-request-ea0c9d19-078c-41d5-872d-a3858a2c7814.json；ID：b0e73967-e444-43a6-824d-1b33f052acf1；SHA-256：9e83e36f019527663eb653e191ff43bd9122f855330853b7bb799bf17ea31c62
- model-request-ea47b624-c0bd-436c-9a62-ff18b8e89a37.json；ID：a0915791-145a-4102-9443-4550031e503b；SHA-256：ebeba0a90f7cb3d2fa467e0f9f90df69a5b37a9fd7a474583b2e16231f9cd12d
- model-request-eb8c0b47-18c8-473f-be12-b13162649b8e.json；ID：3a0b8db4-133a-4fb7-be9b-e20e30523cba；SHA-256：ef0a121e803aa412ec55e33322cf664467ff8f590d7eb5e90543966ea6829402
- model-request-f123435e-a8c6-4ff4-8bd3-e552884ad4a8.json；ID：eb231e67-ee4c-47f8-9364-2095fb527c45；SHA-256：916866d6d08bae0295cb2a3a7940540edb828367ec92fc72f37354ef1aa32ffa
- model-request-f150061b-9459-48eb-a2de-b0f7e5edde10.json；ID：0bf10d74-a3df-49db-b009-1d3f32b30cb7；SHA-256：85d60abb386a10bee611a5f95de9444038df0d1af5ebb98f01aa02a3f2501008
- model-request-f8bee0e6-5db5-4de0-88f2-58a77059d4e7.json；ID：79bdadff-8c84-4910-9b9a-13b4a45abc06；SHA-256：b384635244223c959ec862ed911430f8ee4ab7b50b788951983340b043ca3ba9
- model-request-fa105baa-bdb6-4c91-b217-0051b5f6c32a.json；ID：6bbf03d5-3421-4332-af3d-e11bd33d1423；SHA-256：c151f9016dbde7f7dfc25231335809b90504fd10e7b8662c7be729f8c336b7cc
- model-request-fc561e9b-1be3-47fe-b2fa-5fcc7c67836e.json；ID：6c9492ef-77eb-41a2-b6d1-f4ce6a45d5e6；SHA-256：8c62ecfccc327a580790fbef6d53d840dec19c428491ff725d134c1842c45f4e
- model-response-008e3322-24be-436c-8030-ff075c13d102.json；ID：7352d389-c820-49e5-ab81-2e93cd9dddf1；SHA-256：8516021b6f0e0958691ddfbb4bb301f60b6598497b61e7160fad61deec1eb6d2
- model-response-00a764f5-91e8-43ac-93c2-143d6de8dff2.json；ID：b49a843a-bb9d-4d85-b13c-d1455838d1cf；SHA-256：606ffe91acb40b61dcd2008430302cd947546acabbae34472b98d06d57323534
- model-response-072c9d67-7d79-4a0d-8f83-a728c0448f8c.json；ID：4eaf32ea-1ab4-46d3-9851-ebc83fe81b80；SHA-256：10763d93baa176ec97f7fe1ce232090b0d945c7cdc3872f4c62fd75369dea5cc
- model-response-0a7e9c6a-edfd-42a6-a5b0-16ae75a954b8.json；ID：2d52a363-241b-49da-bf55-5a051892f092；SHA-256：0d14191a98e90e9987d1ace7d10b4cfe547f49311e28d3f4b572c6a26fe62dbb
- model-response-1f2a11ce-e779-4a25-8e2d-f5da7918cee7.json；ID：82ea2da7-8d17-4343-912a-b95b2f51b381；SHA-256：025086d85e70fb64573b110f384e8565bae2415da61ec0e87a8f8bccd240fc6a
- model-response-24389c53-e162-4df5-923a-3ea9f946ee11.json；ID：1d77359b-7e49-4d9f-953e-6ad4a76add34；SHA-256：18ba4059d6fa1bafaf00e47fc5906709e1edca13f07ae4fb99618a0494fb42cc
- model-response-271f7794-8b8f-4c28-80fb-94d7fe077587.json；ID：4a936877-cb0a-42eb-90b3-1ccb27c181b7；SHA-256：ab31f1143d6afc6f3602110c3992e9d0120a6e58281d2f87ef0f22a921612e3a
- model-response-28cab655-c413-488c-a7e9-366be4418d3e.json；ID：d88a7379-325b-459c-9857-04ac4c68c837；SHA-256：2de7bc6fa52db8819634d9bf416b682e6c980fa90a95bdd7de1d8fe27713afea
- model-response-2b5dcef9-8023-489b-9a3b-d3a4513cd85d.json；ID：ce004506-c4cd-439f-8697-e7bdb63bf79e；SHA-256：eb306f3a4e3b19d4df1b58f0f936261ade11b1059668d35f00e1fa466767cc5c
- model-response-31de4ac8-0448-4351-aba1-158f5e57c003.json；ID：e31d91bd-ce8d-486a-be2d-f7c70f66f384；SHA-256：7bc36ada8b17a5d36b15b2c8de618467df9e8d4b277314ab3e2dfe9b4ca4790b
- model-response-342051f5-70dc-47c3-a7bd-85ee46348d59.json；ID：ef50db85-ff1c-456c-a986-711215dc7596；SHA-256：5c52dcab803754636a818e3d0022558c982f8eb119803505c74f08b4b8f3632a
- model-response-37076c89-1e77-4fb2-940b-2bdf92b926c2.json；ID：147367da-e6dd-430b-ba51-eb96297ef4e9；SHA-256：a77ac5deb8e7319641b0378be41dee507b83ace40da45f71af087200b3e252c6
- model-response-39387360-48c7-44e2-930b-57eede07848e.json；ID：1e48c2f3-cfce-4b32-9492-89a829458966；SHA-256：1ceb8cd97d7fefd191fdd5495e0e3043992c1e35eb54365d68ae3088f1ae1c93
- model-response-3b238763-0228-4ffe-8a7e-85060834132f.json；ID：d8be1744-5be4-47a7-a381-738d866ce139；SHA-256：568de72d57b727d5c0a8678686412b11faf17eb1fc47312d3da290edb265bcb0
- model-response-3d69ce87-ed26-48b0-a4ef-0d3042b7a514.json；ID：d41dc7c7-c239-40e1-8197-46af8456c501；SHA-256：17375b40f3a053e69307912f6a2c2a22fd7162648cc0459fe3a786d88f39ed7a
- model-response-4485e5b9-4697-4aec-a4f2-fd09076255eb.json；ID：98c1c2f1-c006-44e7-9ab6-074ee0bc99fe；SHA-256：d18e33109ffad73e16a05bcbb427dd7e773183b129a8b54a592303ce362f7165
- model-response-44d82de5-380e-45fa-b46d-30c4e7adfb7c.json；ID：272c3cd5-ea70-48c4-ad2f-8ca445fd9776；SHA-256：6ef84896a3bfa15d3a4f7c8e6da7131dd839e8add65d59826044b0b4151eb14f
- model-response-45c4e4a5-2c26-4e04-9a75-47fc6e460878.json；ID：5c6e59d9-5da8-440c-9fc5-d7609ab10769；SHA-256：8c45911d8a683b9075d02ae6124a33822ce6410f55bc5eb2e7eec49dcde5e48c
- model-response-4bd44c55-2cc6-402c-92eb-58c2940a719e.json；ID：8c518cff-e9d7-42d6-9369-28ee708f960b；SHA-256：b5dc8a4b38c6220addfbdaed6b4400efad78eface1055262458c820d6004b1c3
- model-response-520d18aa-51e9-404e-a7f9-b417c8056018.json；ID：6aeca3bd-12c2-4df5-a8a0-285126c9fd47；SHA-256：1be08a9d1015fb1ed026a0b33e25d7248612f0ac8fa3c5c6c22c79fedb7ab908
- model-response-5349e5b2-1631-409c-82c5-64e90f362cce.json；ID：3b8ed404-5a1e-467f-9858-3da962cab5de；SHA-256：d1952084b73dc6ec57181fe614e4e1210237f9a45f30e53f62a15adbcb116651
- model-response-5630528f-68c3-4339-9b70-706521f7894d.json；ID：2cb080b4-a110-4b2d-8675-db55dfd6600e；SHA-256：fad9ad87a8f234f0ce26a440c7a6c5ffc317ca0f96e7298301171fb246551202
- model-response-573d3e92-620e-46a4-b92c-09a5ccfed707.json；ID：774bb160-c7f6-435a-b640-fde70f311aef；SHA-256：50fec11dba702ab0d90722bd56d04474499349145a3ba49c238d566501f557db
- model-response-62a00d35-be22-4e54-886a-75f406975d70.json；ID：6d437b39-294f-4b58-932d-9044b67b7f6e；SHA-256：f4bf34b74ee3aebd21774272df031eb7204a1c6904f3d629e469921a1dfd552f
- model-response-66132757-956c-4dd5-b459-0d17644746f8.json；ID：3ed97811-a945-43cb-b2a1-602ac45c9bf9；SHA-256：079f5ee639314fe10ff420556b607448752d656de8f850c6f5b4e9c9ff5b1d21
- model-response-6dfed550-c683-4a90-b017-fb00f9ba132c.json；ID：8cd1e232-7c4a-4271-b34a-5946baa5ac64；SHA-256：79cbc7633b228f1fe624cd0977448a6c00c05a864439d6c4afc2050d90670a49
- model-response-739f3dd5-f56e-4dd3-95f8-f2a22f98faaa.json；ID：dfc9fc6a-11c3-4bc6-9c50-8488c38af252；SHA-256：fc8f63aee02f365ce1611748072af8917cc9cbbe8ee6d0d33019944c1b237d42
- model-response-748e8f76-d100-429f-a83f-4a2a4c5be238.json；ID：4617b139-c0b8-42b9-a79f-f0e2fd29407c；SHA-256：8438c33d7ca59e68ab8e746c1fa2c76ff1420c51e1a088b2c2658ff1509333ef
- model-response-7b3b8c6c-44ff-461c-95a0-a1677ceabb05.json；ID：35f0d001-9328-4bba-a38a-352dc034fed6；SHA-256：6255d3033ae0d19b0c453ef247e0fdfc4167bcfd7b9fa34b507d379599b4099e
- model-response-7fe560c5-3bb0-4649-a742-3d59c59a73ef.json；ID：ca5b78bc-0443-489f-813e-29618ad3e409；SHA-256：35311ad5257f900f9092f04aaaf0220db1490040bef96933189562a25ea6cc43
- model-response-840ce3e3-27db-422a-923b-bb9fbbb68a5a.json；ID：b95a60b6-4376-47bd-9366-994c6c6534e8；SHA-256：7d5203e1eb3a0d9775e50d56989e16da479d04075124c76b7067e5e8e5221ec6
- model-response-87c28ff6-a9e3-4093-b621-88ecd28e7cc0.json；ID：4e1b29b8-6b49-4dc4-84c6-a43ef825fbda；SHA-256：90f4845b35944550d31a1acaa892a77279ea2563b459c547465e5a359c28e128
- model-response-8ae4bd0e-3f33-4286-81c5-602296213f2f.json；ID：505bc5e9-5f27-4dc1-8bb8-e7d1c4bcb872；SHA-256：0289c41eea79088f5da9dcda2e5fb0cc7eebe481c9d432f8930a53982bec1289
- model-response-8cc41e7f-8f4b-43b9-9b2b-9ab035bb14fb.json；ID：c39a3025-a81e-4be2-9a04-05487b1fa6d3；SHA-256：490859f4f46f83111b8873924e0136bf89d9ab96272ded9086acc883ac1c82e3
- model-response-8de7469f-c397-4360-87d2-c13d89976e0e.json；ID：0d167a33-2846-4ecb-ba30-cda99374073e；SHA-256：11e1646ecc18c132ab18fa67f99bd03ecfe67d3c877fa6c99e1a72e05a4f3d17
- model-response-8ded04dd-1f5e-48d9-aedc-685f6475c017.json；ID：319793d7-3cee-4f4c-b71e-fc5024be4f9e；SHA-256：2fa571fc8dd5b757e88b9d8eabdf3d3985b299d966711fdd1b3872b62a7f032f
- model-response-932d4c63-aa36-4218-a9c6-f6434eb3aedf.json；ID：976809e5-2c68-4b9a-ba04-40b0bbf01f8a；SHA-256：e44dead04e615a51edb084c06be820f9f624c81c8776106dfac911a043648395
- model-response-93a84694-75ae-43b4-b02d-b44c319aa10d.json；ID：b8bb951b-bdab-4d8a-bcc3-cdedc1e66c42；SHA-256：c4d8d1631581d91ac4369fc9ae323d06181d2b33d1416e2fb923ef88b1cffb9a
- model-response-9457cb53-4abb-43cb-9fb8-7db1de8493a2.json；ID：21010f58-24c9-44a8-9fd5-f0237dafcc67；SHA-256：886368c5ba0795e6224a678c2d7cac84680aba33e3504a97050c43cbfb83439e
- model-response-951ee5ab-c746-465e-b033-98a139d4048a.json；ID：a67f97fd-da32-4caa-9949-8bfff285eab5；SHA-256：1e0e376fb1b5e40878e53013bb0501d20f1dba1b2abeb13a00c35d01adae472d
- model-response-9a55a607-70ee-43ec-a4b3-0ba2e53121fb.json；ID：1c1e9712-b00e-410a-b443-5e9fbfff60b6；SHA-256：04800e2ca8a813da55214be71a66491aba96df209087f34e8dce5a37248c5cd9
- model-response-9aa37bb5-e61d-4590-8645-bc35fb20dfb9.json；ID：f8b2d2e8-e096-4278-ae75-2a97e67e6007；SHA-256：19ea4c6a6e21a0f916e990fc0b4965bcfe03ab271515ad197f8f2fe98fba9f94
- model-response-a083ff37-a54b-4cc3-a337-32dfe226e098.json；ID：c7b55774-aecc-415d-bbbb-548dce50d608；SHA-256：1cdea5842a41f95aeeac58d95df0220c6a367910acca939f6a8485f815efe344
- model-response-a19f5bb2-eb88-4141-8134-57d2f5f5fdfb.json；ID：e158447a-d93c-4d7b-a48b-c4e8d2edea1e；SHA-256：549394c39d4ea129ae28570416d10cca80a3719826ceb7bd753038e2828d3a31
- model-response-a33265a7-e432-4669-adba-595d84a301d1.json；ID：12a625c8-0764-4b59-8ab5-9373ff6d9e2b；SHA-256：066a9bb21d30a38af8cd7a7252964806ed58f204070a0979ab9cef1edaf7fe6a
- model-response-a52cb445-ddd7-40c1-ab56-d291ae8438ed.json；ID：3d55a2dc-975c-4a61-9e48-3732979e8feb；SHA-256：e9def3a27200598d786a8799a340e1c0d448de663aa78b4b945b0c5c17fc2d80
- model-response-a72b17cd-8436-43d4-8a62-f233418af169.json；ID：d0322481-f501-4720-8be0-2b18d103dd40；SHA-256：c213d355982cb610f14f5d1581cf44c9edb4ab47482254afe98fa408a2950801
- model-response-a7e20100-fba3-45fc-acc4-a98e8d69fd11.json；ID：430b1f8e-cd88-4aab-ac25-82e0d5e972f0；SHA-256：6f6c531405b96979a7a5646d83c90544b5f58379b6aa3e0291be9a6de4dc7f67
- model-response-ad9f5e64-f65e-4fd5-87aa-4e640d29083c.json；ID：2b95137a-c301-49f8-999b-9fb4d3fd45ef；SHA-256：abc875a22cbf7e97026f13b912a9eb52fc2961314ead0797d94e861bc9caf298
- model-response-b02afc5e-9839-4a2e-9e00-36a4110ddf4d.json；ID：2be0d75b-a164-4fd3-b5d4-817b9031886f；SHA-256：fa9fdec39ae71718106f57c709bd43c756d76b798063ef8e5b7b4f42039c5bc1
- model-response-bcd7382b-64c4-4666-9934-0f79935af3c1.json；ID：53b47ecb-dbd4-4b63-a3c7-10a0f6210f72；SHA-256：f92b2ec6efc8eda1aecfadcead9fc4493877a2c3951572e97c4a34fad6fb2cf0
- model-response-bd9490f7-90aa-433b-9352-9c253f0f40bd.json；ID：77627edf-13c1-4206-bc55-471d836c8e7f；SHA-256：051e346e28b5b4c432f020f0e3f706fa558c27736ffe71adee211aa752dd2e14
- model-response-c08329ca-1a5d-4a88-82cc-23fb49ebed57.json；ID：c8636f33-036f-4f8b-8b25-fd30aa1a7a8e；SHA-256：35199efe654d4dd0e021faac58c04309f8ba71916dd93b30c72f0a0dc6ccabb5
- model-response-c23b6d91-f611-4ad4-9754-57cd741829f9.json；ID：895e8f8b-742d-48d2-83cf-083a14be3bce；SHA-256：fae1ad8a64db516423ea5d6f7f698f90187dccbc7c32ade26b193e148e9a56e5
- model-response-c8967eed-117d-4c9d-bcff-1f6d91dcc1b7.json；ID：738a67e1-698d-46c4-9591-4d5dfe6616ad；SHA-256：3ec413260e9fe68d5f457dd14bba125819c2417cf52d989f7d5fc38e86a917d9
- model-response-ca02ae2c-d589-4404-905e-25421ccf6324.json；ID：515d8f51-74e7-473b-8120-36686029bdd3；SHA-256：6b9a1b5c4847cd51fd4eb00895e72ee05118429829668fb537b92cde675d57cb
- model-response-cd1b4ea5-8ad2-47f7-aa7b-993ba7463790.json；ID：867a9bf4-1815-4f34-853a-25858ade7445；SHA-256：ee685df5c45335ea336a85d9a68a90ecd0f9e3726e46d9dbb2d882bb48ecd8d5
- model-response-cefbc34e-7fa2-427b-b808-6a41ee0a3d79.json；ID：44f5e08f-5557-41f4-9b52-4bd32b36262f；SHA-256：55c00bdfb6d59beddd2bb758a32a580df4b86fdef31053d81240b5715ea6c6cf
- model-response-d0ba727d-6bb9-4929-8707-54288567cdff.json；ID：e62e084f-b76a-47c5-99fe-add4e2c241fc；SHA-256：caafb638d0acbd904ff2626d9418c3eddb6b6819fbd035e9c333e7016910dacc
- model-response-d11c91a4-3102-4a70-aa24-8027c77438a7.json；ID：116ebf7f-78f0-4ec4-87d3-0cae26c8efca；SHA-256：5510937b2626d1cbe00f8f8ea757ccb5a2787ddce59c4e8c5aaacf58530f8b28
- model-response-d29ba49f-0f8d-4013-91ab-8f49a8ed3a1b.json；ID：ab3b0538-43e6-4b39-97be-50be9c7aa405；SHA-256：9d1a287b12088ad9277f11d27f894978bc47465cc17fc0b14b5ff41447285cc4
- model-response-d85c24bc-40a3-4b04-86e1-a409197d257f.json；ID：dc3679e3-7dc2-463b-91f5-61653a92d8fa；SHA-256：34d66f2ecfbdfeb4130a30b096e04ce2dd276e85ebfefc2afdaed6ecc60fcb18
- model-response-d892b9d8-4350-4130-9576-00847250c3b9.json；ID：9c3df020-914b-41e2-a6c4-fae255db3963；SHA-256：1317fcf7485136f947de8d7a9af86eaa41ea6d4fe5ae12b3268481fb50ef9c75
- model-response-dece4e9a-cfd9-4cc1-8542-dc667e171f65.json；ID：309de34e-d12a-4522-a346-bae1123a62d0；SHA-256：c13e0d5325ee478e337346deeca8888dfcfb6f3323d87fbb7831640bc8871406
- model-response-e1c16e41-6553-4148-a0aa-0bac2321ba01.json；ID：0dc0b996-2216-477f-bca1-dd3cb1307343；SHA-256：211e11a669d0a9a2e114411bc7157abd9693935fc42464f2db5649ea67195409
- model-response-e378f44f-4681-4c19-b3c6-4a83ca9b8f15.json；ID：4800b8e8-f2fd-46fc-a4d3-b797c3425852；SHA-256：a2b0e829ca15a1d9572b6db8e6cad825c2a0a2c8cb9eb3da97a7fff8c247a1e6
- model-response-e5b98b4d-8a88-40a6-adf0-e09bc703e2df.json；ID：bfae2219-a25c-4a74-9897-f6c03f263be4；SHA-256：6aa337b6e01817cbc4c371afa70c73f365b8c729d389279b0691f39e9661bf75
- model-response-edb8cc73-b1c3-4cbe-9280-c9a49b7b5cbf.json；ID：10ce48a9-11f9-41d5-b32a-dbd0020912e3；SHA-256：01885fa19d56031deff71d05409eb5972fadcef9afb0e217db74b4d2c80e3112
- model-response-ee13c3e3-2cf6-4a68-9eec-6dff9f7fb168.json；ID：ac180793-5bfa-41de-9af8-5b513bf38831；SHA-256：92188ecb48c82fa041514565e700b3de0c617d74a49cfe849e079c53ff22e85a
- model-response-eee130b3-ac23-4b8e-9173-4b0615e5c43d.json；ID：89cdfbf7-336a-4139-bb4b-aeffef610860；SHA-256：433da1ddebd55936dd6eb82a6f6fdcd45b1b4369604ac8981af3cb41a7a864d7
- model-response-f15eddb1-ad64-4a18-8007-b030178837f3.json；ID：b8de569e-6e0e-44ff-ae1c-732fc808e1d9；SHA-256：9fcd2dfb93a8a6fca5dcddfd71d803849463bd3ced8d36da6b35373680d92537
- model-response-f24f000f-e1d5-4770-adf4-1539211c9110.json；ID：58e4a511-1c46-4ec1-9de3-c44d7cd67567；SHA-256：3a01737e1bc7e1a13998c2ac58fbf5512f771840a9290615b9fb6aeede9ded86
- model-response-fe530588-c995-46aa-a06d-9ef645852ae3.json；ID：fff77523-2f36-4cb9-b350-47ffc7b70d58；SHA-256：103edd48bbb382ece98010c3ac98e4ee64cca215a8e3bdeb0cc5502fc9afefff
- model-response-ffc5376e-e63e-4aa8-a398-46247813b640.json；ID：1e581fe6-d3c9-4136-a133-701c46ee6948；SHA-256：6f03a77b006006861f2e47f11f8da3ed2741dabb64b791f2804059c1ba85fb8a
- p03-fastchat-xss-vuln.zip；ID：f07fa6e3-5bb4-4219-8286-082a887825b5；SHA-256：c3ce0f34cd591fa75c1815025538b377403307a93427e9a1a34a506a357dba5a
- snapshot-manifest.json；ID：ffa7aa22-afa1-42d0-a756-6cc15e835faa；SHA-256：6e6cd03fc66596239ab454741ae4f5f9b5a8955e547c593e43f292698ebe2ec6
- source-snapshot.zip；ID：b8a282a7-a772-4de4-8f9e-fd74bc38e17c；SHA-256：f0e549546608e38a56149170307630323e16d26e48989301b0b4c75383222421
