# AegisAudit 分析报告

项目：对照池评测 20260911-093526

任务：e4f8f8f7-bce2-43dc-ae4e-cd6df03fec0b

状态：Cancelled

目标 SHA-256：66e9a1994d0a499a9a720f586164336873495e65558bfb05ed6a1bae62145d43

结果快照 · 数据截至 2026-09-11T09:51:29.350Z · 导出时任务状态 CANCELLED。漏洞审计：CANCELLED；独立复核：PARTIAL；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L201–L235 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L2560–L2738 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L54–L95 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L171–L176 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama\_chat\_format.py | L180–L199 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama\_chat\_format.py | L2519–L2555 | PARSED |
| \_convert\_completion\_to\_chat | llama\_cpp/llama\_chat\_format.py | L308–L322 | PARSED |
| \_convert\_completion\_to\_chat\_function | llama\_cpp/llama\_chat\_format.py | L325–L499 | PARSED |
| \_convert\_text\_completion\_chunks\_to\_chat | llama\_cpp/llama\_chat\_format.py | L265–L305 | PARSED |
| \_convert\_text\_completion\_to\_chat | llama\_cpp/llama\_chat\_format.py | L241–L262 | PARSED |
| \_format\_add\_colon\_single | llama\_cpp/llama\_chat\_format.py | L791–L801 | PARSED |
| \_format\_add\_colon\_space\_single | llama\_cpp/llama\_chat\_format.py | L831–L841 | PARSED |
| \_format\_add\_colon\_two | llama\_cpp/llama\_chat\_format.py | L804–L815 | PARSED |
| \_format\_chatglm3 | llama\_cpp/llama\_chat\_format.py | L857–L869 | PARSED |
| \_format\_chatml | llama\_cpp/llama\_chat\_format.py | L844–L854 | PARSED |
| \_format\_llama2 | llama\_cpp/llama\_chat\_format.py | L774–L788 | PARSED |
| \_format\_no\_colon\_single | llama\_cpp/llama\_chat\_format.py | L818–L828 | PARSED |
| \_get\_system\_message | llama\_cpp/llama\_chat\_format.py | L748–L755 | PARSED |
| \_grammar\_for\_json | llama\_cpp/llama\_chat\_format.py | L871–L872 | PARSED |
| \_grammar\_for\_json\_schema | llama\_cpp/llama\_chat\_format.py | L874–L885 | PARSED |
| \_grammar\_for\_response\_format | llama\_cpp/llama\_chat\_format.py | L887–L899 | PARSED |
| \_load\_image | llama\_cpp/llama\_chat\_format.py | L2741–L2753 | PARSED |
| \_map\_roles | llama\_cpp/llama\_chat\_format.py | L758–L771 | PARSED |
| \_stream\_response\_to\_function\_stream | llama\_cpp/llama\_chat\_format.py | L374–L497 | PARSED |
| chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L506–L635 | PARSED |
| chat\_formatter\_to\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L503–L637 | PARSED |
| chatml\_function\_calling | llama\_cpp/llama\_chat\_format.py | L3160–L3581 | PARSED |
| clip\_free | llama\_cpp/llama\_chat\_format.py | L2543–L2545 | PARSED |
| create\_completion | llama\_cpp/llama\_chat\_format.py | L1973–L1996 | PARSED |
| decorator | llama\_cpp/llama\_chat\_format.py | L142–L144 | PARSED |
| decorator | llama\_cpp/llama\_chat\_format.py | L905–L910 | PARSED |
| embed\_image\_bytes | llama\_cpp/llama\_chat\_format.py | L2615–L2634 | PARSED |
| find\_first | llama\_cpp/llama\_chat\_format.py | L2776–L2781 | PARSED |
| format | llama\_cpp/llama\_chat\_format.py | L984–L996 | PARSED |
| format\_alpaca | llama\_cpp/llama\_chat\_format.py | L953–L963 | PARSED |
| format\_autotokenizer | llama\_cpp/llama\_chat\_format.py | L650–L658 | PARSED |
| format\_baichuan | llama\_cpp/llama\_chat\_format.py | L1032–L1044 | PARSED |
| format\_baichuan2 | llama\_cpp/llama\_chat\_format.py | L1016–L1028 | PARSED |
| format\_chatglm3 | llama\_cpp/llama\_chat\_format.py | L1254–L1267 | PARSED |
| format\_chatml | llama\_cpp/llama\_chat\_format.py | L1212–L1225 | PARSED |
| format\_gemma | llama\_cpp/llama\_chat\_format.py | L1313–L1327 | PARSED |
| format\_intel | llama\_cpp/llama\_chat\_format.py | L1122–L1132 | PARSED |
| format\_llama2 | llama\_cpp/llama\_chat\_format.py | L918–L929 | PARSED |
| format\_llama3 | llama\_cpp/llama\_chat\_format.py | L935–L949 | PARSED |
| format\_mistral\_instruct | llama\_cpp/llama\_chat\_format.py | L1229–L1250 | PARSED |
| format\_mistrallite | llama\_cpp/llama\_chat\_format.py | L1163–L1175 | PARSED |
| format\_oasst\_llama | llama\_cpp/llama\_chat\_format.py | L1000–L1012 | PARSED |
| format\_open\_orca | llama\_cpp/llama\_chat\_format.py | L1136–L1159 | PARSED |
| format\_openbuddy | llama\_cpp/llama\_chat\_format.py | L1048–L1066 | PARSED |
| format\_openchat | llama\_cpp/llama\_chat\_format.py | L1271–L1285 | PARSED |
| format\_phind | llama\_cpp/llama\_chat\_format.py | L1108–L1118 | PARSED |
| format\_pygmalion | llama\_cpp/llama\_chat\_format.py | L1196–L1208 | PARSED |
| format\_qwen | llama\_cpp/llama\_chat\_format.py | L967–L980 | PARSED |
| format\_redpajama\_incite | llama\_cpp/llama\_chat\_format.py | L1070–L1082 | PARSED |
| format\_saiga | llama\_cpp/llama\_chat\_format.py | L1291–L1307 | PARSED |
| format\_snoozy | llama\_cpp/llama\_chat\_format.py | L1086–L1104 | PARSED |
| format\_tokenizer\_config | llama\_cpp/llama\_chat\_format.py | L694–L712 | PARSED |
| format\_zephyr | llama\_cpp/llama\_chat\_format.py | L1179–L1192 | PARSED |
| from\_pretrained | llama\_cpp/llama\_chat\_format.py | L2799–L2879 | PARSED |
| functionary\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L1334–L1688 | PARSED |
| functionary\_v1\_v2\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L1693–L2475 | PARSED |
| generate\_schema\_from\_functions | llama\_cpp/llama\_chat\_format.py | L1414–L1446 | PARSED |
| generate\_schema\_from\_functions | llama\_cpp/llama\_chat\_format.py | L1794–L1826 | PARSED |
| generate\_shared\_definitions | llama\_cpp/llama\_chat\_format.py | L1777–L1792 | PARSED |
| generate\_shared\_definitions | llama\_cpp/llama\_chat\_format.py | L1397–L1412 | PARSED |
| generate\_streaming | llama\_cpp/llama\_chat\_format.py | L2002–L2304 | PARSED |
| generate\_type\_definition | llama\_cpp/llama\_chat\_format.py | L1364–L1395 | PARSED |
| generate\_type\_definition | llama\_cpp/llama\_chat\_format.py | L1744–L1775 | PARSED |
| get\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L135–L138 | PARSED |
| get\_chat\_completion\_handler\_by\_name | llama\_cpp/llama\_chat\_format.py | L123–L132 | PARSED |
| get\_grammar | llama\_cpp/llama\_chat\_format.py | L1940–L1971 | PARSED |
| get\_image\_urls | llama\_cpp/llama\_chat\_format.py | L2756–L2772 | PARSED |
| guess\_chat\_format\_from\_gguf\_metadata | llama\_cpp/llama\_chat\_format.py | L727–L741 | PARSED |
| hf\_autotokenizer\_to\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L663–L667 | PARSED |
| hf\_autotokenizer\_to\_chat\_formatter | llama\_cpp/llama\_chat\_format.py | L640–L660 | PARSED |
| hf\_tokenizer\_config\_to\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L717–L724 | PARSED |
| hf\_tokenizer\_config\_to\_chat\_formatter | llama\_cpp/llama\_chat\_format.py | L670–L714 | PARSED |
| last\_image\_embed\_free | llama\_cpp/llama\_chat\_format.py | L2549–L2553 | PARSED |
| llama\_cpp/llama\_chat\_format.py | llama\_cpp/llama\_chat\_format.py | L1–L3581 | PARSED |
| load\_image | llama\_cpp/llama\_chat\_format.py | L2557–L2558 | PARSED |
| message\_to\_str | llama\_cpp/llama\_chat\_format.py | L1498–L1531 | PARSED |
| prepare\_messages\_for\_inference | llama\_cpp/llama\_chat\_format.py | L1448–L1533 | PARSED |
| prepare\_messages\_for\_inference | llama\_cpp/llama\_chat\_format.py | L1828–L1889 | PARSED |
| raise\_exception | llama\_cpp/llama\_chat\_format.py | L211–L212 | PARSED |
| register\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L141–L146 | PARSED |
| register\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L105–L115 | PARSED |
| register\_chat\_format | llama\_cpp/llama\_chat\_format.py | L904–L912 | PARSED |
| split\_text\_on\_image\_urls | llama\_cpp/llama\_chat\_format.py | L2775–L2796 | PARSED |
| stop\_on\_last\_token | llama\_cpp/llama\_chat\_format.py | L228–L232 | PARSED |
| to\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L237–L238 | PARSED |
| unregister\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L117–L121 | PARSED |

## 审计策略与优先级

仅做结构静态规划：本目标为单个 Python 模块 llama\_cpp/llama\_chat\_format.py（91 个单元），无构建/入口/依赖声明，Semgrep 与漏洞审计均未运行，调用图不完整。优先安排能接触外部输入与信任边界的单元：聊天模板注册表与格式化器分派、Jinja/自动分词器模板解释、函数调用 schema 生成与转换、流式生成与图像嵌入路径。词法线索（key\_logic\_candidates 中的 CRYPTOGRAPHY/REGISTRATION 命中）只是候选，需用原始代码与调用关系独立复核，不能据函数名或字符串定性。

1. u\_f2ac36ce3fbcd06f12411017c7c9f4e6：hf\_tokenizer\_config\_to\_chat\_formatter：处理 HF tokenizer\_config 并可能解释 Jinja 聊天模板，属执行/解释边界与外部配置信任边界，需确认模板内容是否被当作代码求值。
2. u\_fd04ce51bd1afcdae2dec6066240f3b7：format\_tokenizer\_config：内部 Jinja 模板渲染逻辑，直接决定外部模板字符串的执行语义，是解释边界核心。
3. u\_d63709013f76b056f55db3a4bd327a83：hf\_autotokenizer\_to\_chat\_formatter：从 HF 自动分词器构造格式化器，标记执行/解释与身份边界，需核查对象来源与应用模板的方式。
4. u\_6eff4f971151b0fc0bf4e91b4577d0b8：format\_autotokenizer 闭包：实际调用 auto tokenizer 的 apply\_chat\_template，需确认模板是否可信及异常处理。
5. u\_c117537db64f08df8f71adf41e1778bf：hf\_autotokenizer\_to\_chat\_completion\_handler：把外部分词器接入完成处理器，属身份/信任边界。
6. u\_28ebf8e0f4c1bab5ce88ded7b4170e81：hf\_tokenizer\_config\_to\_chat\_completion\_handler：将外部配置转换为处理器，需核查配置来源与是否越权分派。
7. u\_3cf351053c85acc712f1b3b33b718df3：guess\_chat\_format\_from\_gguf\_metadata：基于模型元数据猜测聊天格式，元数据可被篡改，属外部输入到分派的信任边界。
8. u\_8982758c69c91db67c6ea53f6bf4fdd1：chat\_formatter\_to\_chat\_completion\_handler：格式化器到完成处理器的桥接，标记身份/权限边界，需核查是否可注册越权格式化器。
9. u\_1756d911f116155e2545f7e37eaec505：chat\_completion\_handler 闭包：实际处理请求并调用格式化器，是外部输入进入后的主要逻辑点。
10. u\_fd8ae249e132f4a7c218d273c8298a58：register\_chat\_completion\_handler：注册表写入点，含 overwrite 语义，需核查是否允许覆盖内置处理器造成分派劫持。
11. u\_846e654ca827d4bf28ab151a1962ad61：unregister\_chat\_handler：删除注册项，需核查能否移除安全相关处理器。
12. u\_3ac0d636fee58963a7bf8ebe64934d9a：get\_chat\_completion\_handler\_by\_name：按外部名称做分派，是信任边界入口，需核查名称未校验时的回退行为。
13. u\_2ef8d8b8e635a0e8ef47e1228104aa1a：get\_chat\_completion\_handler：分派解析逻辑，含默认/回退路径，需核查输入未匹配时的处理。
14. u\_f6ffe4e8ac99b4667ea2c9a340d176e1：模块级 register\_chat\_completion\_handler 装饰器：注册外部处理器到全局注册表，属身份/信任边界。
15. u\_f493a7a18882f0ae8df311924711bdf1：register\_chat\_format 装饰器：将格式化器注册到全局，需核查命名冲突与覆盖。
16. u\_34ea298bea63a3afd3ca8f1f575016e4：\_convert\_completion\_to\_chat\_function：函数调用转换，涉及将模型输出解析为函数调用结构，属语义授权关键点。
17. u\_97abe44f34a69cda157ba1a290aca743：\_stream\_response\_to\_function\_stream：流式响应转函数流，涉及增量解析与索引操作，可能存在解析绕过。
18. u\_1d717460e6764182b644095902a0b2ba：functionary\_chat\_handler：标记执行/解释与身份边界，函数调用代理逻辑，需核查 schema 对外部工具的影响。
19. u\_710601fcf8764dd82fbe15bda3b72510：functionary\_v1\_v2\_chat\_handler：同时标记执行/解释、身份权限与内存/索引操作，是最大的函数调用处理单元，优先复核索引与消息拼接。
20. u\_0697712c86a733e26289d23374abdc37：generate\_streaming：流式生成核心，标记身份权限与内存/索引操作，外部输入到生成输出的主要路径。
21. u\_934e9e72743af3caa855641cfc2262ab：\_\_call\_\_（图像处理器）：标记执行/解释、身份权限与内存/索引，涉及图像数据到嵌入的转换与释放。
22. u\_b1f97cf494f9965054295d9e52ca1eea：embed\_image\_bytes：字节到嵌入的转换，含内存/索引操作，需核查越界与释放生命周期。
23. u\_a794f31796f413e44b3e1f666ed83a83：\_load\_image：标记文件与路径边界，直接从输入加载图像文件，是路径穿越/任意文件读取的重点。
24. u\_d5fe8dfd7422463e0a6f1be4049bce96：get\_image\_urls：从消息中提取图像 URL，属外部输入解析边界。
25. u\_c8c402664f86ef1294dedddc4daa9342：split\_text\_on\_image\_urls：按图像 URL 切分文本，涉及解析与索引边界。
26. u\_99f7d2d4ee9c53aec722f03aafbfa953：from\_pretrained：标记执行/解释与文件路径边界，可能加载外部模型/配置，是关键信任边界。
27. u\_f590a9d91ba0d1246da0337ac8188341：chatml\_function\_calling：模块最大单元之一，标记身份/权限边界，处理函数调用与消息角色，需语义授权审计。
28. u\_b74c99a5a913eaa577d0bc7fdd50ec66：prepare\_messages\_for\_inference（v1/v2）：标记执行/解释与身份边界，准备推理消息时可能引入外部模板与角色映射。
29. u\_55189026cdfeba36eb6cc6707e4ed92d：generate\_schema\_from\_functions：由外部函数定义生成 schema，属输入到结构化数据的转换边界。

规划限制：分析未运行：构建、入口、依赖、输入接口均未识别，target\_executed=false，实际运行时行为不可验证。

规划限制：Semgrep 状态为 UNSUPPORTED，未产生词法扫描结果；key\_logic\_candidates 中的 CRYPTOGRAPHY/REGISTRATION 命中只是字符串/词法候选，非漏洞判定，需独立复核。

规划限制：call\_graph\_complete=false，调用图近似，动态分派与未解析调用构成证据缺口。

规划限制：本阶段为结构分析规划，未逐行审计任何单元；优先级仅调整审查顺序，不构成漏洞结论或结论性判定。

规划限制：无二进制/recovery 元数据，REVERSE 角色不适用。

## 发现与复核

静态结论范围：COMPONENT

### 未沙箱化的 Jinja2 环境从 tokenizer\_config chat\_template 编译模板（SSTI 风险）

CWE-1336 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：tokenizer\_config\[&quot;chat\_template&quot;\]（由 U0027 hf\_tokenizer\_config\_to\_chat\_completion\_handler 经 U0025 传入的外部配置字符串）

危险操作：jinja2.Environment\(...\).from\_string\(chat\_template\)（第688-692行：构造环境并编译模板）

防护缺口：未使用沙箱环境（本文件已 import 的 jinja2.sandbox.ImmutableSandboxedEnvironment，见 U0010 第195行），也未对模板来源做可信性校验或限定环境全局/过滤器；仅在674-686行用 assert/isinstance 校验类型。

前提：调用链上游（U0027 及其调用者）允许攻击者控制的 tokenizer\_config.chat\_template 进入本函数；模板随后经 U0026 返回的闭包渲染。

影响：非沙箱 Jinja2 模板可访问 Python 对象树（如 \_\_class\_\_/\_\_globals\_\_ 链），在渲染时导致服务端模板注入，进而可能执行任意代码，危及运行 llama.cpp 绑定的进程。

修复：改用 jinja2.sandbox.ImmutableSandboxedEnvironment 构造环境并传入受限 globals/filters；对 chat\_template 来源做显式信任校验或与 Jinja2ChatFormatter（U0010）统一实现，避免出现无沙箱分支。

- 证据：llama\_cpp/llama\_chat\_format.py L688–692 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    env = jinja2.Environment\(         loader=jinja2.BaseLoader\(\),         trim\_blocks=True,         lstrip\_blocks=True,     \).from\_string\(chat\_template\)
- 证据：llama\_cpp/llama\_chat\_format.py L195–199 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        self.\_environment = ImmutableSandboxedEnvironment\(             loader=jinja2.BaseLoader\(\),             trim\_blocks=True,             lstrip\_blocks=True,         \).from\_string\(self.template\)

复核 v2（MODEL，VALIDATED）：U0025 第688-692行用普通 jinja2.Environment（loader=BaseLoader）对函数参数 tokenizer\_config\[&quot;chat\_template&quot;\]（第678行取出，仅经 674-677 行的 dict/str 类型断言）直接 from\_string 编译，返回闭包在第707-711行 env.render 渲染；该环境未启用任何沙箱，模板中 {{ &#39;&#39;.\_\_class\_\_.\_\_mro\_\_\[...\].\_\_subclasses\_\_\(\) }} 之类的属性访问链在渲染期可达 Python 对象树，构成服务端模板注入（CWE-1336）。同文件 U0010 第195-199行对同类模板使用 ImmutableSandboxedEnvironment，说明此处为偏离既有防护的实现，不是无意的风格差异。在 COMPONENT 边界上，chat\_template 是调用方传入的符号化参数，已足以支撑本地静态缺陷结论。

反证：现有防护只有 674-686 行的 assert/isinstance 类型与键存在性校验，不限制模板内容；BaseLoader 仅阻止 {% include %} 之类的文件加载，并不限制属性/方法访问；第707-711行只传入 messages/bos\_token/eos\_token 三个变量，但 Jinja2 的默认环境仍暴露字符串等对象的方法与 \_\_class\_\_ 链。文件内无对 chat\_template 来源的可信性校验。

待补信息：部署层面 tokenizer\_config.chat\_template 的实际来源与调用方是否允许不可信输入（例如外部模型仓库/HF tokenizer\_config.json）在本快照的组件边界之外，未观察到，故不主张完整部署已被利用；渲染时机要求返回的 ChatFormatter 被实际调用并完成 env.render，这属于常规组件契约。
静态结论范围：COMPONENT

### 未沙箱化的 Jinja2 环境渲染远程 chat\_template 导致模板注入

CWE-1336 · HIGH · 复核 VALIDATED · 验证 NOT\_RUN

输入：tokenizer\_config\[&quot;chat\_template&quot;\]（由 hf\_tokenizer\_config\_to\_chat\_formatter 传入并固化在闭包 env 中，见 U0025 678、688-692 行），最终经本格式化器被调用

危险操作：env.render\(messages=..., bos\_token=..., eos\_token=...\) 于第 707-711 行

防护缺口：env 由 U0025 第 688-692 行用 jinja2.Environment\(...\).from\_string\(chat\_template\) 创建，未启用沙箱（对比 U0010 第 195-199 行使用 ImmutableSandboxedEnvironment，是库内已有的正确防护范式）；渲染未对模板能力做任何限制

前提：调用方将外部/不可信来源的 tokenizer\_config（含 chat\_template 字段）交给 hf\_tokenizer\_config\_to\_chat\_formatter/hf\_tokenizer\_config\_to\_chat\_completion\_handler，攻击者能影响模板文本

影响：模板注入：可在渲染时执行 Jinja 表达式访问 Python 运行时对象，导致宿主进程任意代码执行、读取环境变量或文件等敏感信息泄露

修复：将 U0025 的 env 由 jinja2.Environment 改为 jinja2.sandbox.ImmutableSandboxedEnvironment（与 U0010 一致），并考虑对模板进行来源校验/白名单

- 证据：llama\_cpp/llama\_chat\_format.py L707–711 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        prompt = env.render\(             messages=messages,             bos\_token=bos\_token,             eos\_token=eos\_token,         \)
- 证据：llama\_cpp/llama\_chat\_format.py L688–692 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    env = jinja2.Environment\(         loader=jinja2.BaseLoader\(\),         trim\_blocks=True,         lstrip\_blocks=True,     \).from\_string\(chat\_template\)
- 证据：llama\_cpp/llama\_chat\_format.py L678–678 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    chat\_template = tokenizer\_config\[&quot;chat\_template&quot;\]
- 证据：llama\_cpp/llama\_chat\_format.py L195–199 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        self.\_environment = ImmutableSandboxedEnvironment\(             loader=jinja2.BaseLoader\(\),             trim\_blocks=True,             lstrip\_blocks=True,         \).from\_string\(self.template\)

复核 v2（MODEL，VALIDATED）：在组件边界上，函数参数 tokenizer\_config 的 &quot;chat\_template&quot; 字符串（U0025 第676-678行断言为 str）被直接交给非沙箱的 jinja2.Environment\(...\).from\_string\(chat\_template\) 编译（U0025 第688-692行），随后闭包在 U0026 第707-711行用 env.render\(messages=..., bos\_token=..., eos\_token=...\) 渲染。Jinja2 默认 Environment 未做任何能力限制，其默认全局对象（如 cycler/lipsum/namespace）及通过属性链（如 &#39;&#39;.\_\_class\_\_.\_\_mro\_\_ 遍历到 \_\_subclasses\_\_）可触达 Python 运行时对象，构成 SSTI 并可能导致宿主进程任意代码执行或敏感信息泄露。库内同类格式化器 U0010 第195-199行对 self.template 明确使用 ImmutableSandboxedEnvironment，说明已有可用的正确防护范式，而本组件未采用，构成真实防御缺口。按组件范围，调用方传入的模板文本即符号化攻击者输入，模板内容经 from\_string 到 render 全程无净化与沙箱。这是组件级静态缺陷；实际部署中模板是否来自不可信来源（如远程模型仓库 tokenizer\_config.json）属于部署条件，不影响本组件判定。

反证：存在若干断言：isinstance\(tokenizer\_config, dict\)、&quot;chat\_template&quot; in tokenizer\_config 且为 str（U0025 第674-677行），但这些仅校验类型与存在性，不校验模板内容、不做转义、不加沙箱，无法阻止 SSTI。未发现任何对 env 的沙箱/白名单/能力限制代码。

待补信息：实际部署中调用方是否会把来自不可信来源（远程模型仓库/用户上传）的 tokenizer\_config 传入本函数；本函数自身不读取文件或发起网络请求，模板文本的来源与可控性由上层调用链决定，此处未证。未验证是否存在上层白名单或来源校验。
静态结论范围：COMPONENT

### 用户可控的模型/分词器标识直接传入 AutoTokenizer.from\_pretrained（未校验来源与完整性）

CWE-22 · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：hf\_autotokenizer\_to\_chat\_formatter 的形参 pretrained\_model\_name\_or\_path（由 U0024 透传，最终来自调用方传入的模型路径/仓库标识）

危险操作：AutoTokenizer.from\_pretrained\(pretrained\_model\_name\_or\_path\)（第648行）对用户给出的字符串执行本地目录/远端仓库解析与加载

防护缺口：该单元未对参数做任何规范化（如 os.path.realpath/白名单校验）、未限定允许的目录或仓库、未校验下载内容的完整性（哈希/签名），也未显式传入 trust\_remote\_code=False 之类的收紧选项

前提：应用把不可信（用户/租户可控）的字符串当作 pretrained\_model\_name\_or\_path 传入本工厂，且运行环境允许 transformers 访问本地文件系统或网络下载

影响：可能读取并加载预期之外的本地目录内容，或从攻击者可控位置加载 tokenizer 配置；在 transformers 相关配置允许的条件下载入远端自定义代码时存在更大的加载面。静态分析无法确认实际触发路径，故不确定。

修复：在应用层对该参数做白名单/前缀校验与路径规范化，拒绝绝对路径与 .. 段；固定并校验模型来源与哈希；显式限制 transformers 的远端代码加载能力，并在文档中声明该参数为可信输入。

- 证据：llama\_cpp/llama\_chat\_format.py L648–648 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    tokenizer = AutoTokenizer.from\_pretrained\(pretrained\_model\_name\_or\_path\)  # type: ignore

复核 v2（MODEL，REJECTED）：该组件把形参 pretrained\_model\_name\_or\_path 原样传给 AutoTokenizer.from\_pretrained（U0022:648），调用方 U0024 也只是透传（U0024:663-667）。但这不构成组件级的 CWE-22：在本函数契约里，该参数本身就是“要加载哪个模型目录/仓库标识”的资源选择器，组件并未声明任何根目录或白名单约束，因此不存在可被“穿越”的边界；传入绝对路径或含 .. 的路径并非绕过校验，而是正常使用该参数。另外，from\_pretrained 在工厂创建时只执行一次，而函数内部真正逐请求的可疑输入 messages 从未流入该 sink（U0022:650-658），故 sink 与请求级不可信数据之间无数据流。审计者提出的“未做 realpath/白名单/哈希校验、未显式 trust\_remote\_code=False”属于对第三方库默认策略与部署方加固的建议（纵深防御），而不是该组件缺失的必需防线。

反证：1\) 本单元无任何目录限定语义：参数即资源选择器，加载它正是函数唯一职责（U0022:640-648）。2\) 请求级输入（messages）只用于 apply\_chat\_template，未进入 from\_pretrained（U0022:650-658）。3\) 上游调用方 U0024 仅透传同一参数，未引入新的解析点或校验期望（U0024:663-667）。4\) 所谓“远端自定义代码加载”依赖 transformers 的 trust\_remote\_code 显式开启，目标源码中没有任何开启该选项的证据，不能凭函数名推断。

待补信息：部署层是否把用户/租户可控字符串作为 pretrained\_model\_name\_or\_path 传入、以及是否存在“只允许某个模型根目录”的安全需求，均未在目标源码中体现；若部署方确有该收敛需求，则属于应用层输入校验问题，需另以部署证据评估。攻击者控制模型目录内容（恶意文件名/符号链接）或恶意 hub 仓库的场景在本组件输入边界内无法证明，也未在本声明中成立。
静态结论范围：COMPONENT

### 聊天模板 tokenizer 的 apply\_chat\_template 直接执行来自不可信 tokenizer 仓库的 Jinja 模板

CWE-1336 · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：format\_autotokenizer 的 messages（来自 ChatCompletion 请求）以及外层 hf\_autotokenizer\_to\_chat\_formatter 传入的 pretrained\_model\_name\_or\_path（U0022:640-648，可为任意模型仓库/本地路径，其 tokenizer\_config.json 中的 chat\_template 属外部可控数据）

危险操作：tokenizer.apply\_chat\_template\(messages, tokenize=False\) —— 由 transformers 解释并渲染该 tokenizer 自带的 Jinja 聊天模板字符串

防护缺口：调用前未校验 tokenizer 来源或模板可信性，也未对 chat\_template 施加白名单/字符过滤/权限约束；本层只是把不可信模板原样交给模板引擎执行

前提：应用允许用户/调用方指定 pretrained\_model\_name\_or\_path（HF 仓库名或本地路径），且加载的 tokenizer\_config.json 中 chat\_template 由攻击者控制；transformers 的模板执行环境若可逃逸或未沙箱化即可升级影响

影响：在服务进程内执行攻击者提供的模板逻辑，可能读取环境变量/文件内容并写入渲染后的 prompt，导致提示注入、信息泄露，极端情况下借模板引擎逃逸实现任意代码执行

修复：对加载来源建立信任边界（仅允许受信仓库/本地目录、校验哈希或使用只读离线缓存）；渲染前使用 ImmutableSandboxedEnvironment 并对 chat\_template 做静态校验；在文档中明确该 API 不应直接暴露给不可信调用方

- 证据：llama\_cpp/llama\_chat\_format.py L655–655 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        prompt: str = tokenizer.apply\_chat\_template\(messages, tokenize=False\)  # type: ignore
- 证据：llama\_cpp/llama\_chat\_format.py L650–653 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：def format\_autotokenizer\(         messages: List\[llama\_types.ChatCompletionRequestMessage\],         \*\*kwargs: Any,     \) -&gt; ChatFormatterResponse:
- 证据：llama\_cpp/llama\_chat\_format.py L648–648 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    tokenizer = AutoTokenizer.from\_pretrained\(pretrained\_model\_name\_or\_path\)  # type: ignore

复核 v2（MODEL，INCONCLUSIVE）：被审查的可调用体是 U0023 的 format\_autotokenizer：其形参只有 messages（U0023:651）与 kwargs，而真正被当作「代码」执行的 Jinja 模板并非来自 messages——messages 只是渲染上下文数据。模板字符串是 tokenizer 对象的属性，源自外层工厂 U0022:648 的 AutoTokenizer.from\_pretrained\(pretrained\_model\_name\_or\_path\)。因此本组件并未把自身实参渲染成模板；要出现 CWE-1336，必须先具备「加载到的 tokenizer 仓库/本地路径中的 tokenizer\_config.json 内 chat\_template 由攻击者控制」这一额外前提，并且下游 transformers 的模板执行环境可被逃逸。这两点在本组件的原始代码中既未出现也无法证实——模板解释/沙箱行为位于 transformers 内部（静态不可见），模型来源的信任边界属于部署决策而非本可调用体的实参。故不满足 VALIDATED 的全部必要条件，也不能仅凭现有源码直接证伪（存在未知的额外攻击者能力），结论为 INCONCLUSIVE。

反证：源码仅显示 tokenizer.apply\_chat\_template\(messages, tokenize=False\)（U0023:655）被调用，messages 仅作渲染数据传入，不构成模板源码；本组件内没有任何对模型来源/模板可信性的校验或白名单（U0022:648 直接 from\_pretrained），但这属于设计预期外的信任边界问题。真正决定能否升级为任意代码执行的是 transformers 内部 Jinja 环境是否沙箱化——该实现不在本组件可见范围内，无法据原始代码认定其可逃逸。

待补信息：1\) 部署是否允许不可信调用方指定 pretrained\_model\_name\_or\_path（HF 仓库或本地路径），即模板是否确由攻击者控制；2\) transformers 的 apply\_chat\_template 所用 Jinja 环境是否沙箱化、能否逃逸至任意代码执行；3\) 是否通过 ImmutableSandboxedEnvironment 或静态模板校验等手段加固。以上均未在原始代码中出现。
静态结论范围：COMPONENT

### 聊天处理器工厂直接以调用方提供的模型路径加载外部分词器与聊天模板（信任边界缺失）

UNKNOWN · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：hf\_autotokenizer\_to\_chat\_completion\_handler 的参数 pretrained\_model\_name\_or\_path（Union\[str, os.PathLike\[str\]\]），由调用方传入

危险操作：第 666 行 hf\_autotokenizer\_to\_chat\_formatter\(pretrained\_model\_name\_or\_path\)，进而 U0022 第 648 行 AutoTokenizer.from\_pretrained\(...\) 与第 655 行 tokenizer.apply\_chat\_template\(messages, tokenize=False\)

防护缺口：未对模型/模板来源做白名单、本地路径限制或信任校验，也未在该单元内要求显式授权；模板内容与分词器资源的选择完全由入参决定

前提：上层业务把外部可控字符串（如 API 参数或配置）直接作为 pretrained\_model\_name\_or\_path 传入；运行环境允许访问对应本地路径或已缓存/可解析的模型仓库

影响：若入参可控，可能加载非预期的模型目录或聊天模板，导致模板语义被替换、提示注入或（在最坏部署下）从不可信来源加载资源；本单元自身不执行生成，因此不直接构成注入或内存越界。

修复：在调用侧限定允许的模型标识/本地路径（白名单或前缀约束），把该工厂视为信任边界并对来源做校验与日志记录；对模板内容与分词器资源做完整性/来源校验。

- 证据：llama\_cpp/llama\_chat\_format.py L666–666 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    chat\_formatter = hf\_autotokenizer\_to\_chat\_formatter\(pretrained\_model\_name\_or\_path\)
- 证据：llama\_cpp/llama\_chat\_format.py L648–648 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    tokenizer = AutoTokenizer.from\_pretrained\(pretrained\_model\_name\_or\_path\)  # type: ignore
- 证据：llama\_cpp/llama\_chat\_format.py L655–655 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        prompt: str = tokenizer.apply\_chat\_template\(messages, tokenize=False\)  # type: ignore

复核 v2（MODEL，REJECTED）：该单元是公开的工厂函数，其签名（U0024:663-665）本身就把 pretrained\_model\_name\_or\_path 定义为调用方必须提供的模型标识：接受并由调用方决定加载哪个分词器/模板正是本函数的设计契约，而不是被绕过的权限判定。函数内部没有读取任何会话、用户或权限状态，也没有跳过任何检查；U0024:666 只是把该参数转交 U0022:648 的 AutoTokenizer.from\_pretrained，随后在 U0022:655 用其模板渲染消息。因此在组件边界上不存在被违反的授权/信任边界：所谓“来源白名单”属于集成方应用层策略，而非本组件应尽的授权职责。把参数可控直接等同为授权缺陷，等于把库的正常入参当作越权证明，属把防御性建议当作漏洞。

反证：组件内不存在任何权限/身份状态的读取或跳过点；函数名与形参（U0024:663-665）明确表明由调用方指定模型是预期接口；渲染用的是该 tokenizer 自身的模板（U0022:654-655），并未让外部输入绕过本组件内的任何校验。

待补信息：上游是否真的把不可信字符串作为模型路径传入、该部署是否将模型选择视为安全边界、以及 from\_pretrained 是否启用 trust\_remote\_code，均未在本快照内给出；这些属于部署层条件，不改变单元内无授权检查可绕过的结论。
静态结论范围：COMPONENT

### 工具调用语法降级静默回退且模型输出未按声明 schema 复校验，参数被直接归属为所选工具

CWE-863 · MEDIUM · 复核 REJECTED · 验证 NOT\_RUN

输入：API 请求中的 tools / tool\_choice / functions / response\_format（第 512-513、594、561 行）以及模型生成文本（U0018 的 completion choices text）

危险操作：第 597-599 行 LlamaGrammar.from\_json\_schema\(json.dumps\(schema\)\)，失败后在第 601-603 行静默降级为 LlamaGrammar.from\_string\(JSON\_GBNF\)，该 grammar 交给第 605 行 llama.create\_completion，其文本再被 U0018 直接写成 function\_call/tool\_calls 的 arguments

防护缺口：except Exception 捕获后既未记录也未向调用方暴露，调用方无法得知约束已退化为通用 JSON；U0021 与 U0018 都未把生成文本与 tool\[function\]\[parameters\] 复核（无 JSON Schema 校验，也无工具白名单之外的执行授权检查）。第 588-593 行只校验 tool\_choice 的工具名是否存在于 tools，不校验 schema 可用性与生成内容合规性。

前提：服务端把 tools/tool\_choice（或 legacy functions/function\_call）直接暴露给不可信客户端；工具 schema 含转换器不支持的关键字从而触发异常；上层应用按 tool\_calls 自动执行工具而不另行校验参数。

影响：声明的参数约束可能被静默绕过，模型（可能受提示注入影响）产出的任意 arguments 会被标注成任意已选工具的调用，导致越权或非预期工具执行等业务后果；异常被吞掉也降低可观测性。

修复：grammar 构造失败要显式上报（日志、响应错误码或可选严格模式），不要在未告知的情况下退化；在 U0018 组装 arguments 前按工具参数 schema 校验生成文本，不合规则拒绝或标注失败；对工具名、schema 大小与关键字做上限与白名单校验；调用方应在执行前做二次授权与参数校验。

- 证据：llama\_cpp/llama\_chat\_format.py L600–603 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：            except Exception as e:                 grammar = llama\_grammar.LlamaGrammar.from\_string\(                     llama\_grammar.JSON\_GBNF, verbose=llama.verbose                 \)
- 证据：llama\_cpp/llama\_chat\_format.py L594–597 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：            schema = tool\[&quot;function&quot;\]\[&quot;parameters&quot;\]             try:                 # create grammar from json schema                 grammar = llama\_grammar.LlamaGrammar.from\_json\_schema\(
- 证据：llama\_cpp/llama\_chat\_format.py L605–605 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        completion\_or\_chunks = llama.create\_completion\(
- 证据：llama\_cpp/llama\_chat\_format.py L349–352 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：                        &quot;function\_call&quot;: {                             &quot;name&quot;: tool\_name,                             &quot;arguments&quot;: completion\[&quot;choices&quot;\]\[0\]\[&quot;text&quot;\],                         },

复核 v2（MODEL，REJECTED）：该候选把“语法约束静默降级 + 未对模型输出做 schema 复核”包装成 CWE-863 越权，但在本组件接口内不存在被绕过的授权判定。U0021 第 589-593 行对 tool\_choice 指定的工具名做了白名单式校验：从 tools 中查找同名工具，找不到即 raise ValueError，因此最终被归属的工具名一定是调用方显式声明的工具之一，不存在“任意工具名注入/归属越权”。第 594-603 行的 except 回退只是把 schema 专用 grammar 换成通用 JSON grammar，仍约束输出为合法 JSON；grammar 只影响采样约束强度，不构成任何主体对客体的权限判定。U0018 第 349-352/353-362 行把 completion 文本原样写成 arguments，本身不执行工具、不做授权，其“参数是否合规”属于返回数据的契约问题，可由上层调用方校验，属于纵深防御/健壮性建议而非本组件的授权漏洞。触发回退还需要调用方（服务端）传入转换器不支持的 schema 关键字，这是配置条件而非攻击者获得的额外权限。

反证：1\) 第 591-593 行已强制工具名必须存在于 tools，否则抛 ValueError，授权归属属性被现有检查保证；2\) 第 594-603 行回退后仍使用 JSON\_GBNF，输出仍是合法 JSON，并非无约束自由文本；3\) 第 627 行 grammar 仅作为采样参数传入 create\_completion，第 630-634 行不执行工具、不做权限判定；4\) U0018 是纯格式化函数，arguments 直接来自模型文本，未引入调用方未曾声明的工具名。无任何代码在无 schema 校验时授予额外工具调用权限。

待补信息：上层应用是否在自动执行 tool\_calls 前再次做参数 schema 校验与工具授权（部署侧条件，本组件不可见）；是否存在调用方依赖“输出必满足 schema”的隐式契约。这些都不改变本组件无授权判定的结论。
静态结论范围：COMPONENT

### 聊天补全处理器注册表写入缺少授权/所有权校验，overwrite=True 可静默替换同名处理器

CWE-862 · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：name（处理器名，str）与 chat\_handler（可调用对象）以及 overwrite 布尔参数；上游经装饰器 register\_chat\_completion\_handler（U0007/U0008）和 register\_chat\_format（U0041/U0042）传入，调用方来源未在目标内约束。

危险操作：self.\_chat\_handlers\[name\] = chat\_handler（U0003:115）对共享字典的写入

防护缺口：除“同名且 not overwrite 时抛错”（U0003:111-114）之外，没有任何调用方身份、权限或命名空间归属校验；overwrite=True 时直接覆盖已有处理器，注册与注销（U0004:117-121）同样无授权检查。

前提：攻击者或不可信上游代码能够调用注册 API（或通过注册名对其可选值施加影响），且已有同名处理器被注册（如内置格式名）。

影响：静默覆盖内置/第三方聊天处理器，改变提示模板、函数/工具调用 schema 生成与流式输出路径，可能造成提示注入面扩大、响应被替换或既有格式化防护失效。

修复：对注册表变更引入显式授权或私有注册通道（如仅允许导入期注册、为覆盖操作要求特权令牌或独立命名空间），并在覆盖时记录审计日志/拒绝来自请求路径的注册调用。

- 证据：llama\_cpp/llama\_chat\_format.py L115–115 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        self.\_chat\_handlers\[name\] = chat\_handler
- 证据：llama\_cpp/llama\_chat\_format.py L111–114 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        if not overwrite and name in self.\_chat\_handlers:             raise ValueError\(                 f&quot;Formatter with name &#39;{name}&#39; is already registered. Use \`overwrite=True\` to overwrite it.&quot;             \)
- 证据：llama\_cpp/llama\_chat\_format.py L103–103 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    \_chat\_handlers: Dict\[str, LlamaChatCompletionHandler\] = {}
- 证据：llama\_cpp/llama\_chat\_format.py L117–119 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    def unregister\_chat\_handler\(self, name: str\):         if name in self.\_chat\_handlers:             del self.\_chat\_handlers\[name\]

复核 v2（MODEL，REJECTED）：U0003 是进程内类级注册表写入接口（U0001:103 \`\_chat\_handlers\`），其调用契约是开发者在导入期注册处理器。该接口不存在“调用方身份/权限”这一信任边界：任何能调用它的代码已在同一 Python 解释器内运行，也就拥有同等之上的能力，再加权限校验并不能改变威胁模型。\`overwrite=True\` 是带文档说明的显式设计参数（U0003:111-114 的守卫仅防止无意覆盖并提示覆盖方式），不是缺失的授权控制。因此“注册表写入缺少授权/所有权校验”在本组件边界上不成立，属于把库内 API 误当作对外授权端点。

反证：U0003:111-114 明确区分同名未允许覆盖时抛 ValueError、允许覆盖则执行；U0001:117-121 注销同样按键操作；U0001:123-132 读取仅按键查找。检索显示所有注册调用点均为模块内装饰器/导入期注册（U0007/U0008 的 register 包装、U0041/U0042 的直接调用），未见由请求/网络入参驱动的注册路径。

待补信息：目标内没有证据表明存在把 register\_chat\_completion\_handler 暴露给不可信输入的上层调用方，也没有任何进程内非可信代码执行的证据；若真实部署存在此类上游，需另行举证该调用方与输入控制关系。
静态结论范围：COMPONENT

### 客户端可控的处理器名在做注册表分派决策时，被拒路径会把全部已注册处理器名写入异常消息

CWE-209 · LOW · 复核 VALIDATED · 验证 NOT\_RUN

输入：get\_chat\_completion\_handler\(name\) 的 name 参数（宿主通常来自请求体的 model / chat\_format 等客户端字段）

危险操作：LlamaChatCompletionHandlerRegistry.get\_chat\_completion\_handler\_by\_name 的 self.\_chat\_handlers\[name\] 取值，并在 KeyError 分支构造含 list\(self.\_chat\_handlers.keys\(\)\) 的 LlamaChatCompletionHandlerNotFoundException

防护缺口：拒绝路径未做信息最小化：异常消息直接枚举全部已注册处理器名；且该分派决策点没有任何身份/权限上下文，仅按名称成员资格决定接下来执行哪种消息格式化与工具调用解析逻辑

前提：宿主应用把请求可控字符串作为处理器名传入本函数，且把 LlamaChatCompletionHandlerNotFoundException 的文本回显给调用方（如 OpenAI 兼容接口的 error.message/detail）

影响：泄露内部已注册聊天格式清单（部署/版本指纹），便于后续针对特定模板或工具调用解析路径构造输入；分派逻辑本身未被绕过，无直接数据破坏

修复：拒绝消息只保留中性描述（如 invalid chat handler），把合法名称清单写入服务端日志而非返回体；对外层调用方统一转换为受控错误码；如部署需要限制可用格式，在宿主侧对 name 做显式允许列表与鉴权后再调用本函数

- 证据：llama\_cpp/llama\_chat\_format.py L136–138 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    return LlamaChatCompletionHandlerRegistry\(\).get\_chat\_completion\_handler\_by\_name\(         name     \)
- 证据：llama\_cpp/llama\_chat\_format.py L126–131 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        try:             chat\_handler = self.\_chat\_handlers\[name\]             return chat\_handler         except KeyError:             raise LlamaChatCompletionHandlerNotFoundException\(                 f&quot;Invalid chat handler: {name} \(valid formats: {list\(self.\_chat\_handlers.keys\(\)\)}\)&quot;
- 证据：llama\_cpp/llama\_chat\_format.py L123–125 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    def get\_chat\_completion\_handler\_by\_name\(         self, name: str     \) -&gt; LlamaChatCompletionHandler:
- 证据：llama\_cpp/llama\_chat\_format.py L102–103 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：class LlamaChatCompletionHandlerRegistry\(Singleton\):     \_chat\_handlers: Dict\[str, LlamaChatCompletionHandler\] = {}

复核 v2（MODEL，VALIDATED）：在组件边界内可静态证实：U0006 的 get\_chat\_completion\_handler\(name\) 仅把调用方提供的 name 转发给 LlamaChatCompletionHandlerRegistry\(\).get\_chat\_completion\_handler\_by\_name；U0001 第127行以 self.\_chat\_handlers\[name\] 做成员资格分派，未命中时进入 KeyError 分支，第131行把 list\(self.\_chat\_handlers.keys\(\)\) 与 name 一起拼进 LlamaChatCompletionHandlerNotFoundException 文本，因此“被拒路径把全部已注册处理器名写入异常消息”这一行为确实发生，且分派错误消息内无任何最小化或脱敏。分派本身确实是正确的允许列表（未知名称被拒绝，不会回退到任意处理逻辑），所以不存在越权或注入，泄漏内容限于注册表键集合与回显的 name，属低危信息暴露而非绕过。

反证：第126-128行的字典成员资格检查本身就是白名单，未知名称不会落到任何已注册处理函数；第111-115行的注册去重与第117-121行的注销报错都不改变本次结论。未发现任何对异常文本做截断、脱敏或错误码映射的代码。需要注意：所泄漏的键是 llama\_chat\_format.py 自身注册的聊天格式名（开源公开标识符），敏感度有限，更接近指纹/枚举辅助而非机密泄漏，故影响面应保持低危。异常文本是否被外部调用方读取取决于宿主的错误处理，本快照内的 U0006 只做转发，不含任何输出处理。

待补信息：宿主是否把 LlamaChatCompletionHandlerNotFoundException 的文本（如 OpenAI 兼容接口的 error.message/detail）回传给不可信调用方，本快照无证据，属部署侧条件；注册表中是否存在应用自定义（非库内置）处理器名亦取决于宿主注册情况。这两点只影响外部可观测性与敏感度，不影响组件内‘错误消息包含注册表键集合’这一静态事实。
静态结论范围：COMPONENT

### 工具调用参数直接透传模型输出文本，未做 JSON/结构校验

CWE-74 · LOW · 复核 REJECTED · 验证 NOT\_RUN

输入：create\_completion 流式分块的 chunk\[&quot;choices&quot;\]\[0\]\[&quot;text&quot;\]（模型生成文本，源自 U0020 第 605-629 行的 llama.create\_completion 结果，经 U0018 第 372 行传入的 chunks 迭代器）

危险操作：构造返回给 API 调用方的 chat.completion.chunk 字典时，把 chunk\[&quot;choices&quot;\]\[0\]\[&quot;text&quot;\] 直接赋给 delta.function\_call.arguments / delta.tool\_calls\[0\].function.arguments

防护缺口：未对 arguments 做任何校验或规范化：没有 json.loads / schema 校验 / 长度或类型限制，也没有确认文本确为目标工具的合法参数对象；同样没有对 tool\_name、chunk\[&quot;id&quot;\] 做白名单或格式约束（它们经字符串拼接进入 tool\_id）。

前提：服务端启用 tool/function 调用路径（请求中带 tool 或 function 参数），且下游客户端拿到流式 tool\_calls 后未经校验就解析并调用相应工具。

影响：模型（或可影响模型输出的提示注入者）提供的任意文本会以“可信工具调用参数”的形式返回给调用方；若下游按约定直接 json.loads 并执行，可实现参数注入、越权数据获取或畸形参数导致解析异常（DoS）。在此模块内不产生代码执行。

修复：在转换层对 arguments 做最小校验：json.loads 并确认得到 object，失败时返回明确错误或标记为无效调用；对 tool\_name/chunk id 做长度与字符白名单校验；在文档中明确该字段为不可信模型输出，要求调用方二次校验后再执行。

- 证据：llama\_cpp/llama\_chat\_format.py L423–423 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：                                        &quot;arguments&quot;: chunk\[&quot;choices&quot;\]\[0\]\[&quot;text&quot;\],
- 证据：llama\_cpp/llama\_chat\_format.py L383–383 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：            for chunk in chunks:
- 证据：llama\_cpp/llama\_chat\_format.py L630–633 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        if tool is not None:             tool\_name = tool\[&quot;function&quot;\]\[&quot;name&quot;\]             return \_convert\_completion\_to\_chat\_function\(                 tool\_name, completion\_or\_chunks, stream

复核 v2（MODEL，REJECTED）：U0019 是被显式命名的协议转换层：它把 llama.create\_completion 的文本块（U0020 第 605-629 行产物）重排为 OpenAI 兼容的 chat.completion.chunk，并把 chunk\[&quot;choices&quot;\]\[0\]\[&quot;text&quot;\] 原样写入 function\_call.arguments / tool\_calls\[0\].function.arguments（U0019 第 423、432、458、467-469 行）。这正是 OpenAI function/tool calling 协议对该字段的定义（arguments 就是模型产出的 JSON 字符串），组件内部不存在任何解释该字符串的操作：没有 eval/exec、没有 subprocess/os.system、没有 SQL/模板/命令拼接，也没有 json.loads；sink 只是一次字典字段赋值，随后被 yield 给调用方。所谓“参数注入”的注入点位于组件之外（下游调用方自行 json.loads 并按模型给的参数执行工具），这属于工具调用协议的正常信任划分，而非本组件未中和危险字符。因此该 candidate 描述的注入操作在本组件接口内不存在，属于把正常协议透传当作漏洞的防御性建议。

反证：本组件不含任何解析/求值 arguments 的调用点（无 eval/exec/os.system/SQL/模板解释器），无可被注入的危险 sink；arguments 字段是 OpenAI tools 协商中约定的模型输出载体，转换层做 JSON/schema 改写反而会破坏协议；tool\_name 与 tool\_id（U0019 第 388 行、U0018 第 336 行）仅用于字符串标识，未进入任何执行/路径/命令操作。

待补信息：下游调用方是否无条件 json.loads 并按模型参数执行工具（该行为不在本组件内，无法由本快照证明）；是否存在真实部署中把该字段直接交给危险执行器——这属于调用方/部署侧条件。
静态结论范围：COMPONENT

### functionary 处理器把模型输出文本当作 function\_call 名称并原样拼入后续提示词，导致提示词/角色边界注入

CWE-1426 · HIGH · 复核 REJECTED · 验证 NOT\_RUN

输入：messages 参数（ChatCompletionRequestMessage 列表）中的 user/tool 内容，经 prepare\_messages\_for\_inference 拼成 prompt，由第一次 llama.create\_completion 生成 completion\_text（第1573-1576行）

危险操作：completion\_text.split\(&quot;.&quot;\)\[-1\]\[:-1\] 得到的 function\_call，经第1583/1581行 f-string 拼接进 new\_prompt 后再次送入 llama.create\_completion（第1626行），并写入返回结构的 function\_call\[&#39;name&#39;\]（第1669行）

防护缺口：缺少对模型输出函数名的校验：未与第1536行收集的函数名集合（或第1589-1596行 function/tool 定义）做成员校验，也为 new\_prompt 增加“模型输出不可再解释为角色/工具标识”的转义或结构隔离

前提：调用方使用 functionary 处理器且传入 functions/tools；客户端可影响进入模型的对话内容（尤其非 user 角色的消息）；在此模块中 user 内容没有被转义为纯文本的机制（chat formats 直接插入模板/提示词）

影响：生成的模型文本可被解释为 “to=functions.&lt;任意名&gt;” 指令，从而让后续推理把攻击者选定的名称当作已声明的函数继续拼接，篡改出站提示词结构；返回体中该名称被回填为 function\_call/tool\_call 的 name/id（第1669、1674行），客户端可能据此调用攻击者指定的本地函数或误记工具调用

修复：把第一次生成得到的名称与 function\_call/tools 声明集合做严格成员校验并在不匹配时拒绝或回退默认路径；对插入提示词的模型输出做结构化转义（例如统一前缀/分隔符并在解析时要求精确匹配）；文档明确该处理器不承担用户→系统提示词隔离职责，并避免把未经校验的名称写回 function\_call/tool\_calls

- 证据：llama\_cpp/llama\_chat\_format.py L1578–1578 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        function\_call = completion\_text.split\(&quot;.&quot;\)\[-1\]\[:-1\]
- 证据：llama\_cpp/llama\_chat\_format.py L1573–1576 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        completion: llama\_types.Completion = llama.create\_completion\(             prompt=prompt, stop=stop, stream=False         \)  # type: ignore         completion\_text = completion\[&quot;choices&quot;\]\[0\]\[&quot;text&quot;\]
- 证据：llama\_cpp/llama\_chat\_format.py L1583–1596 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        new\_prompt = prompt + f&quot; to=functions.{function\_call\[&#39;name&#39;\]}:\\n&quot;         function\_call = function\_call\[&quot;name&quot;\]     else:         new\_prompt = prompt + f&quot;:\\n&quot;      function\_body = None     for function in functions or \[\]:         if function\[&quot;name&quot;\] == function\_call:             function\_body = function\[&quot;parameters&quot;\]             break     for tool in tools or \[\]:         if tool\[&quot;type&quot;\] == &quot;function&quot; and tool\[&quot;function&quot;\]\[&quot;name&quot;\] == function\_call:             function\_body = tool\[&quot;function&quot;\]\[&quot;parameters&quot;\]             break

复核 v2（MODEL，REJECTED）：该候选把 functionary 的既定函数调用协议误判为注入。第1578行 \`function\_call = completion\_text.split\(&quot;.&quot;\)\[-1\]\[:-1\]\` 得到的必然是字符串；而候选指认的拼接 sink（第1581/1583行的 f-string）分别要求 \`isinstance\(function\_call, str\)\` 的 else 语义分支与 \`isinstance\(function\_call, dict\)\` 分支，其中第1582-1584行只在调用方传入 dict 型 function\_call 时执行，模型生成的字符串名称无法到达该行，故候选所述“模型输出函数名经 f-string 拼入新提示词”的具体链路不成立。模型输出文本唯一被回填进 new\_prompt 的位置是第1579行 \`prompt + completion\_text + stop\`，即模型自身续写的原文，这是二次补全（第1626行区域）的正常输入，不是把攻击者选定的名称字段当作指令。此外第1589-1592行已按声明集合对名称做成员查找以获取 function\_body，第1414-1446行 generate\_schema\_from\_functions 明确把 functions 以 namespace/type 形式告知模型，由模型选择要调用的函数名正是本处理器的设计契约，而非缺少校验的缺陷。

反证：存在声明集合成员查找（第1589-1592行）用于解析 function\_body；函数名由模型输出的格式（to=functions.&lt;name&gt;:）是 functionary 的既定解析协议；模型输出再次进入 new\_prompt 仅是二次补全的续写文本（第1579行）；候选指认的 f-string sink（第1581/1583行）需要 function\_call 为非 None 的 str/dict 分支，模型派生路径不经过该行

待补信息：候选中引用的响应回填行（1669/1674）未包含在本快照的候选证据中，无法核对其是否对名称再做集合校验；也未证明调用方能确定性地操控生成式模型输出以产生任意名称（生成式不确定性属额外的模型操控前提，未获证据）
静态结论范围：COMPONENT

### 调用方提供的 function\_call/tool\_choice 名称未经校验即拼接进推理提示词

CWE-74 · MEDIUM · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：请求参数 tool\_choice / function\_call（ChatCompletionToolChoiceOption dict 的 name 字段），经 1894-1896 归一化后成为本地 function\_call

危险操作：prompt += f&quot;{function\_call\[&#39;name&#39;\]}\\n{CONTENT\_TOKEN}&quot;（v2 分支）以及 prompt += f&quot;{START\_FUNCTION\_CALL\_TOKEN}{function\_call\[&#39;name&#39;\]}:\\n&quot;（v1 分支）

防护缺口：未校验 name 是否属于已声明的 functions/tools 集合，也未对 name 中的分隔符/控制标记做转义或白名单过滤；缺失 name 键时仅有 KeyError 而无结构化错误返回

前提：调用方将用户可控的 tool\_choice/function\_call 直接传给该 handler，且 functions/tools 中不存在该名称（get\_grammar 查不到时 function\_body 保持 None）

影响：攻击者可借名称字段注入提示词控制标记或指令，操纵模型输出内容、伪造工具名，并使返回结果被下游当作合法工具调用处理

修复：在使用前把 name 与已声明 functions/tools 名单做白名单比对，拒绝未声明名称并返回参数错误；对写入提示词的字段做分隔符转义

- 证据：llama\_cpp/llama\_chat\_format.py L2361–2362 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：            if isinstance\(function\_call, dict\):                 prompt += f&quot;{function\_call\[&#39;name&#39;\]}\\n{CONTENT\_TOKEN}&quot;
- 证据：llama\_cpp/llama\_chat\_format.py L2316–2317 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：            elif isinstance\(function\_call, dict\):                 prompt += f&quot;{START\_FUNCTION\_CALL\_TOKEN}{function\_call\[&#39;name&#39;\]}:\\n&quot;
- 证据：llama\_cpp/llama\_chat\_format.py L1894–1897 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：    if tool\_choice is not None:         function\_call = \(             tool\_choice if isinstance\(tool\_choice, str\) else tool\_choice\[&quot;function&quot;\]         \)
静态结论范围：COMPONENT

### 内容拼接使用 completion\_text\[-len\(常量\)\] 单字符索引，造成响应内容截断

UNKNOWN · LOW · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：模型生成文本 completion\_text（create\_completion 返回，2389-2391）

危险操作：content += completion\_text\[-len\(&quot;\\n&lt;\|from\|&gt; assistant\\n&quot;\)\]

防护缺口：未按预期做后缀剥离（应为 completion\_text\[:-len\(suffix\)\] 形式）

前提：function\_name == &quot;all&quot; 且 completion\_text 以 &quot;\\n&lt;\|from\|&gt; assistant\\n&quot; 结尾

影响：仅把末尾一个字符追加到 content，丢失整段助手回复内容，导致返回给客户端的内容被截断/错拼，可能影响依赖完整文本的上层逻辑

修复：改为切片去除后缀（completion\_text\[:-len\(suffix\)\]），或在同一分支统一调用已有的 cleaned\_completion\_text 处理，并补充单元测试

- 证据：llama\_cpp/llama\_chat\_format.py L2397–2397 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：                            content += completion\_text\[-len\(&quot;\\n&lt;\|from\|&gt; assistant\\n&quot;\)\]
- 证据：llama\_cpp/llama\_chat\_format.py L2393–2399 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：                    if function\_name == &quot;all&quot;:                         if completion\_text.endswith\(&quot;\\n&lt;\|from\|&gt;assistant\\n&quot;\):                             content += completion\_text\[:-len\(&quot;\\n&lt;\|from\|&gt;assistant\\n&quot;\)\]                         if completion\_text.endswith\(&quot;\\n&lt;\|from\|&gt; assistant\\n&quot;\):                             content += completion\_text\[-len\(&quot;\\n&lt;\|from\|&gt; assistant\\n&quot;\)\]                         else:                             content += completion\_text
静态结论范围：COMPONENT

### 回传的 tool\_calls 名称来自调用方或模型文本，未与已声明函数比对

CWE-20 · MEDIUM · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：function\_calls 列表：来自调用方 function\_call 名称（2319、2364）或模型生成文本切分（2350、2380-2387）

危险操作：tool\_calls.append\({... &quot;function&quot;: {&quot;name&quot;: function\_call, &quot;arguments&quot;: function\_body}}\)，随后放入 function\_call\_dict\[&quot;tool\_calls&quot;\] / \[&quot;function\_call&quot;\] 返回

防护缺口：未校验 function\_call 是否存在于已声明 functions/tools；也未校验 function\_body 是否符合该函数的 parameters schema，仅依赖 grammar 提高格式遵从度

前提：启用 tools/functions 且走非流式分支；下游按照返回的 tool\_calls 名称与 arguments 执行工具

影响：模型（或经提示词注入影响的模型）可返回未声明/意外工具名与任意参数，诱导下游执行超出调用方意图的工具，形成越权或参数注入面

修复：返回前把所有 function\_call 名称与声明名单求交集校验，不匹配即拒绝；对 arguments 做 JSON 解析与 schema 校验后再回传

- 证据：llama\_cpp/llama\_chat\_format.py L2439–2442 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：                    &quot;function&quot;: {                         &quot;name&quot;: function\_call,                         &quot;arguments&quot;: function\_body,                     },
- 证据：llama\_cpp/llama\_chat\_format.py L2428–2437 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        for function\_call, function\_body in zip\(function\_calls, function\_bodies\):             tool\_calls.append\(                 {                     &quot;id&quot;: &quot;call\_&quot;                     + &quot;&quot;.join\(                         \[                             random.choice\(string.ascii\_letters + string.digits\)                             for \_ in range\(24\)                         \]                     \),
- 证据：llama\_cpp/llama\_chat\_format.py L2349–2351 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：                function\_calls.append\(                     completion\_text.split\(START\_FUNCTION\_CALL\_TOKEN\)\[-1\]\[:-1\].strip\(\)                 \)
- 证据：llama\_cpp/llama\_chat\_format.py L2447–2455 ；产物 b363eb1d-ad41-499d-adff-c220886d5d7e；引用：        function\_call\_dict: Union\[Dict\[str, str\], Dict\[Literal\[&quot;function\_call&quot;\], llama\_types.ChatCompletionRequestAssistantMessageFunctionCall\]\] = {}         if len\(tool\_calls\) &gt; 0:             if tools is not None:                 function\_call\_dict\[&quot;tool\_calls&quot;\] = tool\_calls             else:                 function\_call\_dict\[&quot;function\_call&quot;\] = {                     &quot;name&quot;: tool\_calls\[0\]\[&quot;function&quot;\]\[&quot;name&quot;\],                     &quot;arguments&quot;: tool\_calls\[0\]\[&quot;function&quot;\]\[&quot;arguments&quot;\],                 }

## 关键逻辑与人工修订

- u\_710601fcf8764dd82fbe15bda3b72510 · CRYPTOGRAPHY · v1（MODEL）：工具调用 ID 用 random.choice（Mersenne Twister，非 cryptographically secure）生成 24 位字母数字串，仅作标识符使用，未见其作为会话令牌、密钥或认证凭据参与校验；但如宿主把该 ID 当作不可猜测的关联/幂等键使用，则可预测且存在碰撞可能，故单独标注为随机数质量问题。
  - 原文：llama\_cpp/llama\_chat\_format.py L2431-L2437；                    &quot;id&quot;: &quot;call\_&quot;                     + &quot;&quot;.join\(                         \[                             random.choice\(string.ascii\_letters + string.digits\)                             for \_ in range\(24\)                         \]                     \),
- u\_846e654ca827d4bf28ab151a1962ad61 · REGISTRATION · v1（MODEL）：注册表注销入口，仅做存在性检查与删除，无权限校验；与注册入口配合可在运行期替换或移除 handler，属注册语义上的信任边界。
  - 原文：llama\_cpp/llama\_chat\_format.py L117-L121；def unregister\_chat\_handler\(self, name: str\):         if name in self.\_chat\_handlers:             del self.\_chat\_handlers\[name\]         else:             raise ValueError\(f&quot;No formatter registered under the name &#39;{name}&#39;.&quot;\)
- u\_e58936128bf73a74740ffc133e7d9097 · REGISTRATION · v1（MODEL）：模块级单例注册表的 \_chat\_handlers 为进程共享可变字典，查表函数按外部传入的名字返回可调用对象，注册与查表均无授权控制（名字来源是否可信取决于调用方，属未验证的部署前提）。
  - 原文：llama\_cpp/llama\_chat\_format.py L102-L103；class LlamaChatCompletionHandlerRegistry\(Singleton\):     \_chat\_handlers: Dict\[str, LlamaChatCompletionHandler\] = {}
  - 原文：llama\_cpp/llama\_chat\_format.py L126-L132；        try:             chat\_handler = self.\_chat\_handlers\[name\]             return chat\_handler         except KeyError:             raise LlamaChatCompletionHandlerNotFoundException\(                 f&quot;Invalid chat handler: {name} \(valid formats: {list\(self.\_chat\_handlers.keys\(\)\)}\)&quot;             \)
- u\_fd8ae249e132f4a7c218d273c8298a58 · REGISTRATION · v1（MODEL）：全局可变处理器注册表的注册入口：仅检查同名冲突与 overwrite 标志，无调用方身份或权限校验，注册项直接决定后续 chat 请求的格式化与生成路径；该注册在模块导入期由装饰器触发，属进程内信任边界。
  - 原文：llama\_cpp/llama\_chat\_format.py L111-L115；        if not overwrite and name in self.\_chat\_handlers:             raise ValueError\(                 f&quot;Formatter with name &#39;{name}&#39; is already registered. Use \`overwrite=True\` to overwrite it.&quot;             \)         self.\_chat\_handlers\[name\] = chat\_handler

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
  "audit_coverage_gap": "共 91 个可读单元，完成 19 个单元的语义审计；其余未审计",
  "audited_unit_count": 19,
  "edge_count": 605,
  "eligible_unit_count": 91,
  "exclusions": [],
  "files": [
    {
      "language": "python",
      "path": "llama_cpp/llama_chat_format.py",
      "reason": "",
      "status": "PARSED",
      "unit_count": 91
    }
  ],
  "finding_count": 13,
  "function_count": 90,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "PARTIAL",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 90,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "66e9a1994d0a499a9a720f586164336873495e65558bfb05ed6a1bae62145d43",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 207,
    "cost_cny": null,
    "measured_tokens": 1172508,
    "unknown_usage_calls": 1
  },
  "result_artifact_id": "b363eb1d-ad41-499d-adff-c220886d5d7e",
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
      "finished_at": "2026-09-11T09:35:29.123Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T09:35:29.071Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 91,
  "unresolved_calls": 502,
  "verification": "NOT_RUN",
  "vulnerability_audit": "CANCELLED",
  "warnings": []
}
```

任务错误：审计取消或控制服务停止；本次模型用量未知

## 证据产物

- aegis-report-e4f8f8f7-bce2-43dc-ae4e-cd6df03fec0b.html；ID：4632aa1a-4d37-4a44-a939-7a5a5bf7d143；SHA-256：af2ae6d1e9311bfe6a5b06cfec8cbbe1c0d78733a11060e551558548d101b2e8
- aegis-report-e4f8f8f7-bce2-43dc-ae4e-cd6df03fec0b.json；ID：8a95c909-e49d-43c4-a51f-437d2c1e34d1；SHA-256：d57c71384afad1ae8ef52decf072714822628c544881943b21c10a55abb031e2
- agent-AUDITOR-005d5f3f-0fcb-4a24-b608-ab708b7b23b2.json；ID：289710b6-090c-4d2d-bb98-005bedd7becf；SHA-256：4613c5e64b54f05bdc7e084343c0d8d31f0e4268fbbaabb046e30550256ca718
- agent-AUDITOR-024d593c-b6ca-480f-830b-45ca6de1868e.json；ID：b5aee51a-ec2d-48ec-91b4-5388257d6c76；SHA-256：10c0b3a231da899bcc80c51e9e9e61d093abf49bcddf7c689cf91080d62c891e
- agent-AUDITOR-0840ff74-2976-42b8-8dc8-104540593e61.json；ID：291c2520-5963-4974-b65a-5d6779a84596；SHA-256：0e80703ab21e36c2d26acabfe093019798fa42306d3717f7b3f7cb4a7ec2bf2e
- agent-AUDITOR-16a37081-8c12-491b-8ee6-dfb9cc821fff.json；ID：e9c36de9-c27b-4dfa-bdd1-58f55a0bc1b8；SHA-256：3019a6ad050d2a0ba61624a4de5255d230e4bc243a9d360186b971bf012b932d
- agent-AUDITOR-20d916d2-ed90-40b3-82ca-69563ca4d661.json；ID：3061ad70-f767-4edd-ad12-b669a710940f；SHA-256：844037c690818fb32c082ee06ee71e336bce4df04f90032a39f468020077af48
- agent-AUDITOR-23219a1c-80ad-42e8-842b-3fbb246566b5.json；ID：03cc7f86-a3ac-4b2d-b80c-d3c502f9bd61；SHA-256：8e677ade37e4bf99458275836c4bb1e7010952c03f50db8260a08082b2bc2da9
- agent-AUDITOR-4b2b984b-8848-45a5-ac1a-22ae4df860fa.json；ID：bbf23902-ed42-4d22-900b-e8d87d513d01；SHA-256：2d590747223be57bf8fa5ea391ff50ff91c24d2b41f0e5c125e2cd80cae05f3d
- agent-AUDITOR-670eb15e-1360-4f5d-9c66-b124d437352d.json；ID：ec70d47b-7441-45f6-a2f1-7da37209c362；SHA-256：29cf04e3e7971bbef8d5f1b6d0fdfb61e8fd4b41e9e14d4410c81d1d730b8cbc
- agent-AUDITOR-6a3dddb5-cb09-46d2-b961-52c664549cd2.json；ID：7c2c792b-1ec6-4c9d-9d69-8e9eb9c43fcc；SHA-256：295c84d2c4598d555a9e14c7b9a12a0c8a615229ca94bcd4f26becbd8bb04100
- agent-AUDITOR-7152e976-06f6-4043-aea7-0cbc9c99dd5b.json；ID：ceaf59f3-87f2-4242-9999-af2791eb6fb1；SHA-256：ce8fa797e426091c8a4db053c83b3ca0d5a8e6fdbb0bba841367c0e9f0523edb
- agent-AUDITOR-8a34e24a-dd81-4f62-a147-83843dfd8801.json；ID：cdc9bb09-f289-4eab-95f1-1edbea3631cc；SHA-256：a55a0c7891b1831f08ebd90ab522bcccb0a35d3b533632e2a7ba9cc44fc3628c
- agent-AUDITOR-9397e4ba-9b40-4193-82f5-e9223781ae5a.json；ID：dbbf94b8-7a8f-4954-9fda-6240bb485362；SHA-256：23b7f08d683b1cca9bbdb844fb76195a3077dde1d29eeb163feffec978e1f308
- agent-AUDITOR-a1745f55-d319-4a2e-aac4-f8207073d527.json；ID：b83105f9-329a-42d2-844c-3094b4414245；SHA-256：7894f4cac638c24379c1af9ba8cbb0ba4a9a0436041b8787efa5aacbd4c2ca33
- agent-AUDITOR-c795784a-8a3c-438c-a966-4ee5cda4dda5.json；ID：a7e60e13-f840-44ac-9f67-add306f8c13b；SHA-256：0de234eb7107c61d658d26ad5a6d0a79cd7a40df6558d2c85ec4db3c9d916adb
- agent-AUDITOR-c8bf5cda-0c36-4443-a933-4163de9dff10.json；ID：b90bac0d-3d25-4298-b82f-08ff6a502e7e；SHA-256：eeb9d683e04938411d7521b7c7fe646f6f293cd9f634609e1510a522cb00068e
- agent-AUDITOR-dc18ff2e-99d9-4684-a78f-3f040e396188.json；ID：ea2e2dee-6ba8-4545-b72b-58820986181b；SHA-256：8765fae23a6be5311c9460a63fe2ce5686d70e311a76145f60c74decba5eaabc
- agent-AUDITOR-e11eaa00-faae-4980-8d96-75ce87462f9a.json；ID：c44fae91-9102-40e4-b255-e9a3ccb66a81；SHA-256：38d36daf2146bb0a8f855a1351e335d9b9976d329a11e100f2751f4b5f9ac1c4
- agent-AUDITOR-ef5b551d-974a-46df-b03c-0c9dca57b07f.json；ID：8a426036-0f07-42bf-8a81-032a1094ee2b；SHA-256：8043a6039b461311aab32edf7eb3d479fddec5928be8134f93dae7f90c25be6c
- agent-AUDITOR-f4402185-cdc6-487d-af58-04c5fa667bb0.json；ID：600838f1-9d9a-402c-88c3-b528acb367d6；SHA-256：d13b13fd56b3b8884c5d3318513fe036b60667cf79ced85f56bef0f3f8c74102
- agent-PLANNER-90b9e240-756f-4ac0-af90-b488482cbf91.json；ID：e8cca84a-4ca3-4258-838a-edbc4dc1d16b；SHA-256：ee361f4f1e40962ff1b792c02b81e675f49462b2e253908832694e01eaf55d9a
- agent-REVIEWER-17cdaed0-f407-4e26-8904-d33c4a852032.json；ID：0caf6a14-83cc-489d-81a2-0f11b85caee1；SHA-256：4c1c85d33b93aab51459feec4d7ae660834e34a4f54e09d029e6d97b1122de77
- agent-REVIEWER-1b81556a-ca39-4164-8970-c03adb9f9189.json；ID：2d03a3e3-0596-4063-9482-4b820813a9de；SHA-256：e3c1b93aefb897b0188140dcc2c65bd7a87140d7c1e601a6ddc3fe9dfdb9db0f
- agent-REVIEWER-2c2f73f3-f3d2-4115-ad40-53cf37f4935e.json；ID：4b9baa3b-4c1a-4c5f-99f9-220e16a854f5；SHA-256：ada73a77194d88ebd7c7a53b660bcda0cf1b57d196a496d971bd4781b4be043e
- agent-REVIEWER-64970542-6d43-46e3-bd95-1f4b4eae746a.json；ID：54f8be60-ab67-4155-baab-a05c2582c227；SHA-256：33f16f4e90ea526f0ece425cdb76fff95bad6d04fed32a2beed1bc2fd62d303e
- agent-REVIEWER-b9bc81ee-c070-4134-bfde-a518991c2263.json；ID：013fd35b-8af4-4ad3-a9c8-be170e68d117；SHA-256：6202a38b23cd56494726e19c8e4ec858b2cdd8dd34c4bd74c81166df64ba4567
- agent-REVIEWER-c71c5138-622e-45ce-9e25-09bacb418aea.json；ID：8c5c3564-2dc4-4844-837f-fe803f50dcd2；SHA-256：9c2b623aef97a6b3ef6dd847183e88ef950f8b1f5830baf7f4e74ffa3fd24818
- agent-REVIEWER-c7323487-9887-4605-9a02-b9d4fdc38e0b.json；ID：2990858d-cf07-4cbf-9481-6a0885826de9；SHA-256：732c08954068e05e6749d3dac501d0b6c94b000ff7ad656601d855390d336cae
- agent-REVIEWER-d63d52a0-88ba-4d9e-92c0-ffc553c49f6a.json；ID：f04db9a4-02e0-4be3-b377-bfd8891811e3；SHA-256：bdaa48ae0e2c7f798e18a7392a5594a30f1b4bec2c816cebb49320132d801fcc
- agent-REVIEWER-e93a5d48-ee56-46f2-8fb4-51e4ce9f1b7b.json；ID：b7ff44f8-4ae4-434d-a24e-1651cf934f71；SHA-256：7ee81af52b024bcbdc97f85546524ca57f034d2bfff8ed6637bd8a10d75ba5a9
- agent-REVIEWER-f3d98fc6-3da6-4b9d-ac8b-85ff32f420b2.json；ID：8eff6803-d51a-4f4a-860c-9918942d822f；SHA-256：715ca53daa626127ef36b5af422f391e84a93655e5a1b068dc9f0efa2ad622a5
- analysis-result.json；ID：b363eb1d-ad41-499d-adff-c220886d5d7e；SHA-256：0c3d66a8a22b28b0822887d04f101222141b22cd4b5df0747067b1393df85939
- model-request-00a42e2f-3f3e-481d-95f9-22c3c7e8c02a.json；ID：40ff85dd-ae3e-47e4-b7c5-1be48137e160；SHA-256：be9e505222c6fe01716d4c84f57440da27e860c70fc326967927f82e7eadd848
- model-request-018f03c8-8d78-4cae-844b-46bd4ef86136.json；ID：906d7c04-9439-4715-966e-aeb319376905；SHA-256：b8ee585a13df0d495c131a4f40f26c63b1aa07fe90ff1dc82a4968f0ae846fde
- model-request-019929f7-1518-4038-9d62-3304b3bcd2d7.json；ID：fda8dff3-1481-416c-8bdb-c020f54e424c；SHA-256：328e077c5e4519929e9455badb11f07d85826628b803ecf49f3d1e23dce118b3
- model-request-035b7072-a6a7-432b-85f5-4b12fc38ae0b.json；ID：0f3f96dc-6697-4269-9ad5-99d50a8c5061；SHA-256：ca1965d7c6db3e821876cb814d5b8009206ae2bfb81145747fee732a185f1c03
- model-request-051001ef-85a8-4937-b114-b01c16a448c8.json；ID：3d14f5e4-0cd7-42b4-bdbd-bd67e075fe11；SHA-256：54343bcd7323927032f6aa497b553eef5fd98d02bdb82a2e2b4bb96c321b3fed
- model-request-0c076e77-f868-4181-8ffe-9c560d9ad266.json；ID：4501a1fc-da58-4b03-a8d4-3142947a1ef7；SHA-256：064c25490f27c1c991ee3062d42ac11a213a81b0ac18cc046b51d105bb4efa77
- model-request-0d53e571-f956-4e8b-bce9-819c527793b4.json；ID：6e9aaedb-ef89-4a79-acf4-b18f7857c34e；SHA-256：d485a10334a49e3f8a3e19fddb19bdfe081ca98fb2a74593cb0629536419e153
- model-request-0e64b4fe-0b7a-415a-b02f-7c3a18aa74d9.json；ID：2b274396-4e97-46f9-a50f-760264216fa9；SHA-256：edb1ad6f9371919ae543d670b80cbb72fb1002a07bff073ccc83b7d52810a620
- model-request-105631f1-3ae8-451f-9495-1c4bb73855e2.json；ID：def8f452-2fb2-47bf-9a33-acee8a47de03；SHA-256：22a54b4e22d99d10bd4388c1512949695555aa867d89ca0e16603e911a14aad1
- model-request-10791d51-f963-49e8-97c1-c04ad41a0570.json；ID：d7dcda69-9680-4fc4-9025-7e99355d42ac；SHA-256：378d8ceafa9625a3929a5bf5e94bdab3a706a0094deb507053aa4f9559d74082
- model-request-115bbcf3-f70b-4742-9ef6-6464c0529e96.json；ID：9597825b-f560-44d9-b511-20891286c589；SHA-256：7119abbe872ee3af2d2d696345fcca8f6636f399a4f989ad681f9408c738e98a
- model-request-13709bc0-9fbc-4e03-860e-202ffeb4c9fc.json；ID：c87c44f1-5c9b-4e2d-85fe-b862f0f25265；SHA-256：f677727a9d03cb24c8357362f56db5ade84177f7b82e36cc347de15efe2c7293
- model-request-139b582f-a31a-4c2c-8fc6-010bfd784e06.json；ID：55872f2a-7871-4d67-b1a7-4865f76edb82；SHA-256：ebffed3d3ce092916021e7365b1cad004ceef5b4721eb4e6353c4206a61c8059
- model-request-148d6b57-d7c0-4364-b297-72989a8dcc71.json；ID：24f52950-3083-408c-9bc4-a477a72348ab；SHA-256：70a9af04873fa064cbdc42410e35bde18ab55e158b37b61f97b5f2d360b752df
- model-request-14d064bd-00fb-42b4-806f-4fd5f61d73be.json；ID：d7027387-eaa2-473c-920e-233a77f50e9f；SHA-256：c4e9403c67ba9680510008f6c6ba660aa866c55ca7e5d4c3edfc0ff3a6519a64
- model-request-1ab69b7d-c9c1-4c5c-80c4-c73fac2e6098.json；ID：c00c76d9-9e69-4480-90e3-7e6910992504；SHA-256：0c1bd0f4d343716159f0633441520c112e1fbef69bc66577efc9312aa13eb9ab
- model-request-1b91649a-fe1c-4d2a-9c83-c5ffa93e6063.json；ID：daa2eae3-14f9-4eae-a396-1a17dfec4f77；SHA-256：b287aa58b761c4785cbb7c70c10083e8e5fdf41dc6e2b80275414c328ffe57a3
- model-request-1c29827a-c74f-4d52-9a1b-25d37117ceb7.json；ID：3057cb46-6cc5-4789-8218-699e247eeb60；SHA-256：77da54fd6cadccf4ee54aa36e704c176e78359907f5db13eed0f4e1d45f88c78
- model-request-1c6a3419-cb99-4dda-a4e1-964b32ad85e5.json；ID：1b79e78a-9533-42b9-b593-850136e246a2；SHA-256：1cc16d34cb25ea94b5d196e46dea6ed7e8d48ebbf5a7ed2d7a530b1652055b39
- model-request-1d3030f0-b57b-4393-9599-2699294de32d.json；ID：c048f5d8-96fb-4633-b6a4-3a2829ee464e；SHA-256：07df405a45c7d9eee6ffdd1a98992109a30705bea417e2e116e3e6465d5705cb
- model-request-1d6c03cb-bb2a-4b6f-965d-e5d2badb25fe.json；ID：f78d60a1-93db-4d39-a3a3-f5f06c45f86b；SHA-256：ea1726b9046f9fbf5a29bebd072bebf60936ca5e39fd91f26d69ea8e2538dd07
- model-request-1d886783-dfb8-4c7a-8c36-9b6275f99e85.json；ID：fb27b453-a334-43e0-b70d-74866e4d6298；SHA-256：0d83b3899453bf72218b8dc7b9c6bc40b1d09dee0fd6b9fe682245b4c5d8dc96
- model-request-1d94c481-0e62-4bc5-ad30-abae78630b52.json；ID：8f899f30-8bdf-4387-b7cd-65584b4df347；SHA-256：4ef400c7d6bb9598ebb887913b548e6e142fdb2ccfbfa947e8a0145ceeca03bb
- model-request-1e8037c8-5be7-49db-9427-747465333457.json；ID：79dba220-368a-4969-bb15-207004a9db84；SHA-256：2e5cedbab8481be9303fbd2f12d503c78bc5e07de9990a5b2ea52e3d6af4f4ba
- model-request-1e9613bd-ebd3-47bc-909a-21daf8be6ccf.json；ID：bb4ac5f1-afc6-4cc5-99ca-e01fdd8ec160；SHA-256：962fbd785e62e86c1075e04850dc1c569407df40190c1fa7f085c5cef5c46858
- model-request-1ed3d22f-c09b-492c-acf4-fbc570323550.json；ID：8a5019f3-7de3-4873-98b3-c8542ae2f551；SHA-256：d792853a3fe82ec8cbaeb0644600b956aaa724add587cd234269d53d24e9a272
- model-request-1f92d757-92d9-4178-9467-cc706b54efaa.json；ID：e488992d-4a69-46cc-8cda-ceb6e5085dba；SHA-256：18f216970560097c1a7386269f52419bdebcd6b6f2917b3efb809028ec3e0f81
- model-request-226f5359-5f0f-419a-a074-b4d2275d8838.json；ID：5930fdfe-83bf-403c-a376-5b71653182cb；SHA-256：2d2d7f669d47da21b9a5f3219bc262122f0f83e50ebcc19b3f73de9ec677dda1
- model-request-23620b57-ca83-43b6-875b-6c185c487226.json；ID：ae50f1e4-c833-49bd-8981-5f38aee43751；SHA-256：d3ea214b95f756ac5f585d3894ebb2a5c8b0f3e4a8aca18b621daa9527703665
- model-request-25b69701-f068-4c5f-9043-8c13f6c20ee4.json；ID：5120c220-55be-4a0c-a0e3-e3c1ec365f90；SHA-256：38dbf3f112154622c941df11a9776c28f62c093069adf4d9f094b560f3e4d632
- model-request-26404aa0-bdcf-4624-8fe1-0521a9866f2c.json；ID：cf898453-e1e0-48f3-9824-1d76a360c6f1；SHA-256：bd650d95f0ec404fc2f8651b83ed1f67c36a25828289c75dbd32d4d61d2e6cd9
- model-request-26df91db-0a75-4658-9f89-0a722931e28c.json；ID：83772ed1-5f3a-4321-9c12-e24e1ff71ad7；SHA-256：11152461ede711815644ac3106a83bd012e3769f19742701c347b48d97ede4df
- model-request-281a3554-5f47-49e2-a7e6-653804651304.json；ID：699822bc-1e4d-48d9-a34d-f4ed7314e11f；SHA-256：f2d2d62a4e12808877c4930e5aac8367e32ce62686e9b9613f3cc9555468b8b4
- model-request-28c7a6eb-3e60-408c-9a74-00960a4c70d4.json；ID：58b73556-97cf-4e35-9ad9-fedc895acf32；SHA-256：bc2a190a8faefa716521a0403a888c39f30e34cb6092d8d20ca19ee9ae31c787
- model-request-2afcfc1a-22de-457a-ae85-f051212a5dc0.json；ID：40fa1638-2206-4e9e-a1c2-329b467b82a2；SHA-256：4a3fd6982d7e13c28733c1fb2d67b88503f7b590670765261eb8dd02079657f4
- model-request-2b2c4e2a-176f-4bbe-8558-26a97eb00fb5.json；ID：2d392f60-1307-4fd4-b414-8f210e43a088；SHA-256：54901cc0211aed2a6c88612848bc18aca7ffb27b3b02bb3bdf4781cd2df4ba99
- model-request-2d316bd6-31e0-4f82-9d38-0520f815375e.json；ID：cc887080-9385-43cf-95e6-52a2d8020b7e；SHA-256：4b1baa6bd934b628d422ef14df767862361c97b6cd7f065f04fe6ad24df7d365
- model-request-2d6b9a3d-96e5-4c1c-b713-38506ade9e13.json；ID：1c9ea7d4-0a82-44b3-985d-bb0094889fa8；SHA-256：e75e8bd285729c5ff3fe8afa47a60a7f21ce288f24e612d93eb73ed5740aa573
- model-request-2dd817e0-2763-44a4-871a-99d755624076.json；ID：483ba5c9-daa4-49d3-a189-1278a36afc20；SHA-256：29b0ec30d450ad5f4dd822b4ca2cf5083f25baf5932f67ca3f584f934549841d
- model-request-2df72375-349f-4181-bba1-e6e5429dc2cc.json；ID：d36c0150-ea43-48ce-9c2e-4c1bfdc3ee7a；SHA-256：b59e71c35ed467f9f4653dd69bededc50d00a3b81eb9144f4b41251932468a9d
- model-request-32ae2086-b929-4909-97a3-3352bcdcebfe.json；ID：81949350-5365-4610-895e-6835b057ff9b；SHA-256：4ec9578f50c8bddf7ecc7a70a84d11bb63fdede2181c65453df3a48e42744fbf
- model-request-338dc2e6-a653-4967-864c-acc4913e01ce.json；ID：36e0d042-d3fb-4797-a638-5e677e5c2434；SHA-256：c88116bf98068c8b580457ed75161b21fb6d39ba39e8ff99ae372e6cdb8be2fb
- model-request-34539a05-79ef-40fa-93da-90d1b782fd98.json；ID：d87bca48-d831-48a6-adf6-9ce22d620f6e；SHA-256：8a345231c2fb144004ea4367f47f56e8d4a33f2e92c0aaee49c3bc4470fbcb7d
- model-request-3526f2c5-88e5-4fe7-b2d3-f97eb203f249.json；ID：287cc6e1-b7a4-4ff9-838b-539d6c57a7b0；SHA-256：60d6616c73e1ff118d5f67b9a95417301be6fe34cb3dfc40dbfa5d303d871078
- model-request-35be030a-3cdc-4964-ade9-2c357924e491.json；ID：98ce9f94-60e5-47b1-b56d-cca30abebbc6；SHA-256：40fe6e2a6026d9443bf134a09ae8ae9b94a9e0c0334ec316de975ceb06faba1a
- model-request-35de068c-7aa9-486d-8a74-89cb76d1e6c2.json；ID：13ca92da-b62d-4d82-849b-5ac03ea74208；SHA-256：5f8e96d24791664b54283b61bf618b056534152ac1bb4d970f410766209d5fda
- model-request-36d06d13-e418-4e29-abac-04bf207ef2e7.json；ID：85e35fe4-f6db-4be2-9dca-1599ced262bc；SHA-256：f1b7a1897bdaee36209931efe8dd27f445ba138f82120922e74fedb672f8aa4c
- model-request-37474b45-e4b5-4352-913b-6ef9bc5332c4.json；ID：780fd366-86e6-4cf5-a1d8-3e5581bff3ba；SHA-256：778df2af88d4c9652302bc79fb833ca89966e23b276d74bb10097ffadc838763
- model-request-37a004c4-f475-4fc9-9c39-75b0d309ab1b.json；ID：3c5033a9-a45d-4901-b3d4-b6d68d04db81；SHA-256：48a8628e9cfef2604b10ad25689bfc3620409cc0c0ff8881316a2b5cbc4d08c8
- model-request-3b80cc87-ecb7-46e0-b976-61286f7a25ab.json；ID：47516d16-859c-46d0-af36-797f8ff6741c；SHA-256：2b856f9c4e41fdd6f35c8139e2365bbb78cb8398bd304e748dc47ef605094a27
- model-request-3f2d603f-0836-48f7-bd58-d7fb477d9477.json；ID：f518c996-ce0e-4b02-aaf2-d645f0b42e00；SHA-256：02b3a6b5fa562008dd5a2fbb1215634352dc12ac7b73a90ec0d378c5ef914b4b
- model-request-3f594080-cc06-45c2-b895-0f3bfffd36dc.json；ID：059f6e4a-8ff3-4261-bea5-455f05f9f8bb；SHA-256：0c5dda4c0a09aef71fecccfac0492a0354922dfdd33c0edbdb368fd2c123f0a0
- model-request-3fb59eb8-0ecd-4ba8-b2d6-12ecebfd4710.json；ID：69a8ce58-1308-4c36-8ede-ecddd74f6ac8；SHA-256：c7fd32b99786599e4dd174e5a62912b06febbaacd972c93466982ff61362ca60
- model-request-40b4fbf5-470a-4269-970a-121eaa2b8a6a.json；ID：e8686e0e-35e1-4298-addf-8c5f47417643；SHA-256：2e28d9c3d99e8596c73e1ef17f576c7efbb327c15a811fe3ae6ea75d58aec8a4
- model-request-42d1ff27-313d-4366-8539-42ac81fe5d6c.json；ID：4b233603-c71c-48fb-ac4f-a45a65242a58；SHA-256：6c41483e6b8d057049f0ce2fffa9cd934f90635d6cdf7d6216b5b46af7da343b
- model-request-44791dc7-a91f-43ae-8598-488f192bba85.json；ID：3bc188cd-a943-4833-b66c-bd33c9537c09；SHA-256：10fb7a9c9503b69330f44d433a008391fbfa52f5fea23f35c467f34018737ec1
- model-request-44e931eb-4f42-4d75-b49a-bd7cd4446918.json；ID：e3c867e3-1284-4777-bad9-f3104811a9f3；SHA-256：3051ce68f52d5c2ed1eb0e3deee4590f1edc0b27bf41d0a8595929c8a934c47e
- model-request-47fbbe8b-091f-4847-a3df-8eab4fedded8.json；ID：68c3d12f-22f4-4d6d-8405-d688b8f1ed83；SHA-256：a6b44ec435d5059e60ecf773ee8466b67c154c0b8af1d23f4ee62d5c08b3e94b
- model-request-482769ae-169e-4da1-854d-a2022fe37725.json；ID：cad53401-09c8-4bf6-aaac-2806f66d9773；SHA-256：52f3cd104bb51ce98d8306eb444c0226e455282e211ac541e027fc02becae661
- model-request-48c279fd-51ec-48fc-a8e2-dcbc2e4f6522.json；ID：db586824-7562-4152-a158-8e08dc43f3af；SHA-256：d83e05e8953bc0c1aa45206b44583561539632afebc9325f07d8c6086bb7342d
- model-request-48fffdca-69f0-477d-8337-9f058db91928.json；ID：130606f3-98cd-433f-93be-b4a14031afbb；SHA-256：c94d9923ea814b4af51c52051f62cea6b20b9fcc7293c3e0f625ffa6e54e05ba
- model-request-49b10615-7189-4a22-a8d9-7a9a00b82246.json；ID：364afbf0-ef0e-430e-9f96-f8e34d9e4497；SHA-256：f7e545340d84225900e84d0b83caaa102a063048ecff659b8cabe8ff45201716
- model-request-4dbb732e-ee50-44e4-b1f5-825f3158965f.json；ID：51ff2c69-2885-4989-be26-9b1e2e4567ac；SHA-256：c5fb9ca5613f2feb257c49464d890b70042884c3167209ee2ce6aced8f59882f
- model-request-4dd0b6ef-f619-41d6-b1a8-cf1a0233d65c.json；ID：91a991b6-7914-4c79-9ca7-e1ccc39b0588；SHA-256：47f3a899380cebcdd9bbe6ca7c74028cd3af89ef0528aa7e71acdf53aa3704a8
- model-request-4ef95b0f-4b4a-4d3b-9418-b6284304277a.json；ID：646b2a1c-de05-451f-af34-45fe56cc6b87；SHA-256：9c5d7eb28c653782d0be19c2b9fa3fa6537191eadc5f306dc77730e4375ad017
- model-request-4f3c8883-7f42-4ebd-a605-3252d6937d98.json；ID：7ecd1b32-97ae-44fe-8c8f-df0d176cea8b；SHA-256：c24ccf3acc20b9e0df5979fcd35c755d4fd518b179b27e89af643e7cd7ccbda2
- model-request-4fe5081d-5dca-40a9-ada3-03404cc51794.json；ID：92a8297a-f59f-4299-9542-e01c0e0a7fde；SHA-256：dd157276fcce526de451110a8db7d6e7be7af79ff518f0687ce57db1ebebfe3d
- model-request-508982bb-6001-41b2-8abd-3beee58fd3fe.json；ID：9ee61430-18e2-4b91-b898-c4b7cdc112a9；SHA-256：84e9d9d7093cdb16288b1690b5b97be068a522739dfec3915a46c1d9f0b18e7a
- model-request-50a00a13-f828-40c6-89f5-73bc065d7a86.json；ID：77140f0e-5b03-40d7-9bcc-047f9e2720cb；SHA-256：69d502b0647c20edb08a2a822010c80fdc81e3e7563350d28ce56cd9ee9e0554
- model-request-51399543-8d07-47bb-93f5-2d48411e7255.json；ID：41ebc7c8-0a03-42af-a971-a4d9a3203f0d；SHA-256：02787f97bc29be2dc936bd63a1f6877c4acee3c1285f75237fa745f1a8c52d13
- model-request-53261507-65d2-4aa3-879b-ae1c37fe929a.json；ID：4a9f5cf2-bb49-4825-998b-4488468b4e6a；SHA-256：816f607d91bfb2fca34637602cbda6cb8ce577ffe7d19ba40ab014fad6650f23
- model-request-58b561da-dd7a-4ecf-9f3c-c7bc360623b2.json；ID：8433cd8a-4931-4903-9190-9d00f25a0135；SHA-256：25ac2eaa3ae766e36151129410bf03f4ec9ecd3bbb207e52941a9861e134fd0c
- model-request-58f744fe-b055-4fbb-a8bc-2fa42fb7e512.json；ID：f20728cc-e6b0-4fa7-8816-3ad5e9326abb；SHA-256：f4e0ae820c7cb3dcbae2cfd4da6a06aa75cb7058cac8ceb70f34800cafaf0555
- model-request-59316f9a-f101-46a2-aab8-1d4970b41c8d.json；ID：9fc1c73f-570b-4158-bfd6-5bc35075de4b；SHA-256：9ca77a48c1c89f753cb039078ae95583f4b61014a3c5a92828cac28a02afb448
- model-request-5942b025-fe25-464d-872f-63ec88889100.json；ID：0968b5f4-28a0-445f-a210-168d041db654；SHA-256：d865bb7592b8097ae9b6a7c1eb9a63a09ebed5bf71a48aa54b9883382afabc45
- model-request-5ed0f468-99c5-4c4e-b251-243728b8491b.json；ID：3729a3f8-9e54-4f42-b2cd-0caa8785353a；SHA-256：581841e21fd99130a2b0a0c15407f0acbdaed3af6b6e35ca4dfa08f4e1fcabfd
- model-request-5faf94ac-a231-49e0-a23c-2283054701cf.json；ID：e8dc0363-4eb4-4780-8c46-01eca755d1c5；SHA-256：fd8dfee71e59cdce754acab28f9ed2f70a5ae476429233f6f3be941b67288ac2
- model-request-6040eb28-a0c6-48e9-9516-95c25e9642a5.json；ID：ff88910a-dc01-4a3c-a429-f0750e33ac17；SHA-256：173c90527d89e2a55d4aaca67794c5de1fadbf95d2189a40b3412891eedb2cb5
- model-request-60a250b7-f4a6-4bfe-884b-bc869f0d46d6.json；ID：7135891f-67f1-4212-aded-32341fc647a2；SHA-256：d52bfd91d2f9b6d7ee0b4a7f060369a61d700d90601c0eb41464f7506ed0b7fd
- model-request-61009fb5-f284-44db-ab5d-56f01730ae99.json；ID：ec9d639d-52a7-4492-bc43-51662d4528f9；SHA-256：71cf159b390725c32f42fc3a25680f99afb479ec29a607e30f0c48c32c775670
- model-request-61c5373c-d4cd-458a-ae3c-26492a925a31.json；ID：63bf7c31-efdf-4379-b63d-ea764db41b3c；SHA-256：910f4079c0e3da84d10a8f98f5b871dea7234cf8e76ab98eaeb27691edac7e51
- model-request-675274db-871c-4f7d-a16b-f4a160cd8ab9.json；ID：e5bd9bbf-4287-4e25-a8c0-47e0428d7fad；SHA-256：71cc0d5afaaec166d822aa820ebfc1103ccc18c7c515d7b940b31ebe136128f2
- model-request-68c6c8fd-5762-41ab-81ce-43449430d7ba.json；ID：1c4ab956-4d33-46d9-be57-99330b030684；SHA-256：f9d277a1dc210129da147e43147c928ce41f96557b2c29ebb39354c355e82fdb
- model-request-68f0b4cc-9666-4bad-8092-bea091bfb5e1.json；ID：f1d36196-d487-422b-bbb9-07d3e3bab7e6；SHA-256：84ba1e4022d540d49359dc653c2891ee23b6bbc1a13d0729655881620b0b953a
- model-request-68f26ea2-5d61-45c0-b0fe-8843eb58d542.json；ID：7f918921-a1c8-4a15-8330-898e30ddf96f；SHA-256：232d7c93722d82baef29efc49323f2759338fce17f2476e52ea6d6179939c1ef
- model-request-6a56b88a-13e9-4487-bd63-679a6a550190.json；ID：a5492990-4dab-4c34-8bc3-0379e651acb3；SHA-256：e518ab2554ce29c7cbdecb919e413edd100714cd9a8cba6e87fa6ba14ae1f190
- model-request-6d44c402-6a7d-4b5e-8fbd-f736c3d9409c.json；ID：ba0ac8bc-6121-464c-874d-c8780d6d5950；SHA-256：3d9e8d797ec3288557604b0f2fcde052ad84277859cb3972552076cc9caf390a
- model-request-6f36ee03-dd68-4119-9c22-055a8955c8b8.json；ID：118b34bc-41c3-412d-90da-c562de6b7460；SHA-256：55b66d79aca1d02a0fba7fc4dfa2711f11be884451bdb86bccbb8b59a84088e7
- model-request-702508e7-1c8e-43e9-b9e3-7f082afedb8d.json；ID：13fb5528-a75a-4171-9be8-c70eac536e25；SHA-256：bc5400db391fc075cbdb0659a63268945a7b5cd7e15ede34089512831a995957
- model-request-7208907e-f94e-4b92-8574-5bd30a5aa391.json；ID：be8126cc-a653-4b62-a404-82d469310dd2；SHA-256：6759ae5496cda10e1f0ef515f915cdf58b0e316a86dc3d0581a142c30a785090
- model-request-76930cd0-d01b-4d6b-a321-0e76368e294d.json；ID：0f24fb7d-870a-4bb0-8844-8e0996104837；SHA-256：e736f2bfddd627117074e6f4472d5261bee403eb87c03b036c81fd53bd74ba67
- model-request-77551681-50b5-46e3-92e9-6077ad868ead.json；ID：d737c627-dc27-44c2-a97e-074239e34787；SHA-256：a3bcdfb4637cee1e244bf61b0b0ef268e77cdc144ba641f1597faa1ffe5ecdd7
- model-request-7793687d-0417-4793-806f-d1b501f1dd2f.json；ID：8b477db5-8de8-4413-8e5c-0e5c26abca57；SHA-256：1b7c1b87cbecb001f54a64c0b0d674329322bb6bcf24d915cc5296aa6a5cd14e
- model-request-7aea3004-4312-460c-a70c-f9881587e43a.json；ID：03414631-2e6a-41c4-bc30-511aa2f689dc；SHA-256：f1abd620ee272967b95ab09dd20af778c5941146e4e26cc15cb3e1c8bc0ea3dc
- model-request-7aeaee3c-b5f8-4661-a6ea-b79e4dca203e.json；ID：b5a23119-7ef5-4a55-a42e-dd296288a970；SHA-256：8d415e9d1fbeeba4586e4179e0272aa4e532e08d757959f0c967c0e495838a6e
- model-request-7b784ae2-3aa1-46b3-beec-f97d8d3f7f9f.json；ID：392ec8e7-da51-4a51-bbef-07d49e403280；SHA-256：c2d4814c0c9bed56c5f3d3e371fbcaf7d03e36ab7d647d15b5266bfc5481ac70
- model-request-7c94c657-1962-47bf-a4da-d633d8168c1f.json；ID：e479c854-03dd-4e14-8bd0-4b85f6b670be；SHA-256：8225740ff3bb32c93128fab74290b731a19222276dc114b13d658f501d5cd871
- model-request-7f0d41a8-674c-4c24-8ec5-9118ee2c776e.json；ID：642985bb-8ca8-4681-be67-cde29b533140；SHA-256：e32ba1f9389e7e18b9d37907b135e5b1f3e03904ac4f5bcf989929580d417a18
- model-request-7f351bd4-779f-430d-88b8-e22db04929a6.json；ID：096f7231-0d9a-4c34-84d3-7009db9a43ec；SHA-256：a27230ef04d73f2bed13006fc1e745fea43a2d916cdb5b79a6cce2f452c57fde
- model-request-7f5e1fdc-c5dd-4de3-85de-a149c3c6fe9c.json；ID：8a59986b-9c16-46be-94a7-ca5b5f82ddd9；SHA-256：8f65703640f80273bd449a6a7e10bef8d774cae781a953476b84be0e4eddfb7e
- model-request-8222b74a-4c26-4179-989e-a4eff658dce1.json；ID：016de153-8222-48a3-a927-b4dc15b94298；SHA-256：96cf8a1c855634f3fc5b63819217026dcaadfea0e3735e1864bbe53cef5e1091
- model-request-82785f42-13d0-45d3-8903-1db35edd3445.json；ID：28cec91b-4f43-48bf-b6c7-0e5134347b57；SHA-256：87d3a6d3ab8bbba8e618abc54a3386bc805c3844ab2326a608ac489162ce77d4
- model-request-82e9815a-b436-4bf4-b394-fce702ae40db.json；ID：5330ae14-7012-443b-a34f-b27ae495cddb；SHA-256：21c5f6af042d19bdd63f200c1399b6f6c5084ea752afc0c3a8fbc2399e71281c
- model-request-842aec8f-108f-4ff3-abb4-18a102b32743.json；ID：8ee9f137-a0ae-4ccf-9247-1402f0e31548；SHA-256：28d5243302e8f2c51d0b75aba18c1b167b846eb44d90b9a956e681a2a8be591d
- model-request-84dc93f8-8f93-4a70-807e-bf9eac467dc3.json；ID：2e73bbc2-2285-4d47-bda4-28bbdfe7b965；SHA-256：2370041ecfc14d0ec43cf0902f95bb738c66c6b6f28dbd18d141509fb2ed3aec
- model-request-89e4bbc3-d9ae-4dc4-abf5-bcd91bd8eba9.json；ID：93e7374e-c812-4426-a28d-715c77951faa；SHA-256：80ad4cceac6657b084003b512669ec015c7580610d6e298f12bd2b0581251892
- model-request-8a3bdfa0-0695-456b-9c9a-67ce4cf8dd03.json；ID：1303fe14-a600-4221-be45-73fc5c1d1961；SHA-256：8f934dd04e4e5ed65bbc501eb022f27cd82d5b273ff6bf5a0513ebf04f796a2d
- model-request-8b619f48-54eb-4635-8a2a-aac93d78f59f.json；ID：517fd711-7dec-4c7d-a262-bb93e6326465；SHA-256：de76e9f9ad60188755444ec1e1d4b7461b04b568bbcea17a4c4a619a74436808
- model-request-8b6edb33-0b43-4828-91d2-9442ef73dcdc.json；ID：16a58aa5-a834-425d-a202-318801645d11；SHA-256：5cd1e3d26a53cf37527835ad5f51d14350a0bad028c1923b1f370e390d4ccec6
- model-request-8bffda36-6bbe-46df-8f80-d650ba54acb3.json；ID：43bb5f17-d0be-4922-b421-68b0b7c4013d；SHA-256：d3a005455bf8740888f1a2b7ae792786b23567a0f08433efde36168fcf0b7471
- model-request-8cb7e89e-3cff-4a3d-8bdc-38f053758de1.json；ID：9e1ae13d-1226-4682-87c3-c5cf083f296e；SHA-256：0c9764fdeb70673e729e9019c0322314da11e1e42497f02ffce25a685d95b017
- model-request-8d03c790-eef8-48c2-ac04-c02f4990b24a.json；ID：862b69a1-0251-4d28-8a50-f4f2a1131a4b；SHA-256：83678a5f1cc59c9dea4cda4185355ee0dc73d3ee0ef4ed6a928e5618e90f1171
- model-request-8ffc9323-717d-4cf9-8e70-e57b8516f813.json；ID：a8ae5e7e-d8e6-4e2a-a7ce-b70e1f7a5889；SHA-256：080b7383cdd4a0511e4876ef9c47f0821343b42ad73a2655d1747439af038c74
- model-request-92f740b4-b713-4323-ba1e-9be518dacca6.json；ID：17e98bd5-b2a2-4a80-8494-d2dc9270bcc2；SHA-256：2e2b39ca8b1960e4afed2dd34fe5b32fbe0ea985a240d996e7bfaa76376d87e7
- model-request-95cb84f5-6284-48ee-af8c-2e4fba2d4640.json；ID：4b333a52-edd5-4680-a19e-554be08f0e32；SHA-256：42161b508076748b1cf3fe97696e57b9b176228aa381b989e2a8b7e3580969c7
- model-request-9a68d22b-233c-4a72-9451-add414c7e299.json；ID：3bfebe4b-eb81-4b49-8c83-8e0e05221cff；SHA-256：98ea6bf8a26eb976e43328747eb60f3c70f96d3ae61ed5fed90741196f514779
- model-request-9b46d08c-65df-4d89-b7ef-1c12d41caf2e.json；ID：7ea10434-78e9-418b-b63e-8b85f61b7f0a；SHA-256：0474e29abe244783f8f15fa1d93aa69ac86b0d9e1139656a5169e736510174c9
- model-request-9c66ec71-4d39-4c71-ba5b-c0d90279bc57.json；ID：38423868-ab51-4431-a662-e7f50e1c014c；SHA-256：abd4c29ee7f44cf1faac30a926438bf74c5d19e9b7abdb45b976cf52195d72a2
- model-request-9cecaf96-09f8-4e7c-bd09-d123a6517350.json；ID：79f8dfc0-2856-413f-8d70-726a6b2c3313；SHA-256：1666995ed83013791b054ee9b6e239cdc09cbfcd7102fb96a92402e686f81749
- model-request-9d0dc3d7-c07c-42f3-9235-5ee55bcd55fb.json；ID：d4b62b7d-b574-42a1-9486-173e66acd80d；SHA-256：c66705c70a3ec16705c571a2f9d92c42ebe6c5fee29bd7cde1cd77040fedce22
- model-request-9e3e2af1-6497-4dbe-bae6-5b56d659d102.json；ID：00477475-dc2f-4b6d-bf0f-e651ffb263c9；SHA-256：9bfce72b221c1f6de4c73fc3a110e1ec7788027278fd9f602cbb5578870e1f48
- model-request-9ea9b8ee-a235-47b0-92af-a0400eb791cf.json；ID：57a271d9-b167-422f-b2a7-15d83ae1a77d；SHA-256：0a181c3dbfe5b7c5ee3228437aa80d7af70b1b43db5b1153e53eda12d68ed6e2
- model-request-a13675ea-2cca-441d-94a5-1f980959151a.json；ID：6b577744-bd2b-477e-b9b3-dc59122a6124；SHA-256：5cdce00cfb376d4faa4c40c9d6a641ebf9c60df8abb5794c6bea01bfe9c93ff7
- model-request-a1e01f8c-2aa4-4d34-b15b-24533124fbcb.json；ID：06dc96c0-5033-48a7-bacf-9626e3355a0e；SHA-256：99ddfe951481eec30abb0c9dbc506d8222ccdc53e974c9ab44a580d27687435f
- model-request-a2b6679b-fe25-48f0-aca1-0a518ff33bdc.json；ID：c43b90de-abe6-4c3e-8a9b-cec924f104e7；SHA-256：93d7ce614dd7e02ed6db5b39e9f75d5c8bae98978c11701e6a2626103ad7fc80
- model-request-a4299018-0869-43f3-95de-420ea404a6fa.json；ID：6074b72a-5042-490c-8479-6d2087099c49；SHA-256：233839156af0c6d7ef27487bb771ab74af40ed4dff08b16096ba0bba800de0e6
- model-request-a5a3ad39-c2f7-4009-a1f2-9f9fa9ffaf71.json；ID：912a2a3a-9013-4566-b539-528e62148c53；SHA-256：58d6a058e8da7a874ba505a005f13adbce0038d121c8cc98cddd7f5dc973b2a0
- model-request-a5adb5bc-516f-4d7a-b489-138ac277b09c.json；ID：1555122a-9b8b-4af6-a931-08e210caf91f；SHA-256：f26009a58c47b3fba18c97837343dc72d232a92be31e13792cd6c5129e0620c4
- model-request-ad7683f8-969d-4b81-be98-e7d388c61e49.json；ID：f08856fd-ba37-48e7-bf96-f89e881182ea；SHA-256：f166d594f524fd07d31ed1f634c940a99c71d23839f53c635f055e740e4e2fe2
- model-request-adbbf6b1-6117-4ebd-a2f7-2e8a6793ecc9.json；ID：98a54567-ad92-4762-ac7e-f0fc8d51e1d6；SHA-256：c950fc8f5335126cc518d884682f373335ed9a826bb9e6d0a8b853b09cca296f
- model-request-aefe188d-0577-40e4-9a25-21d99fa00019.json；ID：0f314183-1c33-4cd8-8ed1-03f62fcf85f4；SHA-256：433870ec284594d0fe813704a6bb5640cb266a4dd11bd6ae8b822589b098cfdb
- model-request-af36a9a6-8cc1-423c-876a-ebc730434774.json；ID：d256fa94-5e24-4a5f-ba09-806e94c3e31e；SHA-256：d7d010e37dc0acb5cf39a40489a352b57eb9de65728b434564f3923513b6113b
- model-request-b160ebd9-af6d-4395-85e1-9b038056c631.json；ID：02ed5ac9-efb8-4a70-9fd3-16e638c22ac6；SHA-256：8b17be3ca2d8a07ff008b371e42203c937c8576e4bc87b446ec6803ad8ee834d
- model-request-b17cf2fa-94ad-4d84-a32a-82ba8ba75a58.json；ID：db89a9aa-36a1-4d77-8ef9-05cdb7f066df；SHA-256：344ba5c88fb71a92b92387ab99f01dbca0ec7d2f621e707737155a20ba2e4339
- model-request-b1aeb273-d2dd-49f7-9868-c978d3dabfcc.json；ID：fa2cd808-8e50-4132-a07a-fa8dd967d3a2；SHA-256：8277622739e75b685d6ba68f872da211dcfd6d78fe6fbf26aa1347c2d98fd967
- model-request-b232df9f-b1fe-4fb7-89c4-ca67193572b7.json；ID：7821b2d2-308e-4b59-8ddf-3522a27e6a8d；SHA-256：f18651e970c5388fdde93cd24cb23653ca099f0b48d43e1f371371eff47a0661
- model-request-b30bec4b-9020-46d6-9052-7851101690f8.json；ID：05fc4de8-746a-4d40-bca0-a50c9a27cd1c；SHA-256：f291b9fa8cdf316a7ed849f3bf028118c47b1b45afdfcd0ad23ba61fc8ffe5ae
- model-request-b37d8d87-71fd-4829-8b10-2d16b3efca69.json；ID：c13bd619-bb34-4a00-8c0c-5811c5464315；SHA-256：f51da468325893f952e4fbc0aa4c6c22b77c7bd937922befb95cb12a0597f2ac
- model-request-b4371315-2c2a-42e6-95d6-d9b873c5ea55.json；ID：52e7b7e1-f7a5-43c6-88a2-e60a3fc275fc；SHA-256：7e098a2184389ccd32abd294afaa9530b35d1eb6afaaa8807ae78ecefa94d019
- model-request-b532eccb-8610-491c-b179-40931a1c94dd.json；ID：ba48b077-42f1-424d-a7f1-1488c4e74d07；SHA-256：dd11ca81742cf34d46fd6f5ed951ed276b1119558c7d025a65796ac33b5b1b7e
- model-request-b7be0c4b-fa73-4aa2-aeca-a77322b2a6e5.json；ID：4ee5cc66-2e35-4dd1-9af7-1d4c963adf5d；SHA-256：29e521072740ede2a2183a651b3c66a1d618374951284cf797797b5c27016f48
- model-request-b955fa76-9ada-43bb-99ca-907ebcec6c20.json；ID：bcc6966b-1564-4649-a03d-061511aa1bad；SHA-256：bad9339afdb0ab824cf5806434520dc374a9601184792b8021c3be8b542310da
- model-request-b9628b02-8dc2-4c30-97b7-5e8326d31952.json；ID：8d47acb5-c982-4afd-b13c-8ecbcbe41d36；SHA-256：18834ba592cd1e819fc8dabf63fb3320ef135244b8868f4f8b7c8dc137a6b80f
- model-request-b965c9c3-cd9e-4dd5-9246-0bcabc07434e.json；ID：2a0f02de-093d-4035-9089-4f1c7bd6ba40；SHA-256：b2b4bdf168eeb8becb75e3c3d971bf6036684095324d05ccb2b09450c5b1045c
- model-request-bb0e915d-a738-4cd8-8122-d33e14b8de96.json；ID：f98c70e7-709d-4330-ba9c-eeb75bf37e19；SHA-256：760baeddd0cf0edf8061001fecbbb7c7a10ed4fd6829de02af898121ad3c52ad
- model-request-bb1f8199-43fb-4a4e-bba2-d1d4dcede2c9.json；ID：ebc6537a-920f-449c-b573-4af614bbe211；SHA-256：6f4dfcb8eae0e0c18c71aca998f937f8c5bc19e9f7555d9f7570eb4bed8cc15e
- model-request-bb539e98-1931-4bc8-838f-26731ae640c5.json；ID：810e4b39-eddc-4fd4-b82c-3c2326b9ddc8；SHA-256：20a0131681eeafe7fabc3ac12378fe25f30794edefa70c4d8b1f2872b902dcf1
- model-request-bd1d7df7-99e4-4270-ba9e-129f56f7b19d.json；ID：0564d80c-3bb5-4551-aa9e-a950974f2832；SHA-256：9191d7ba1f69318b86dc49d6efe1bbdef3780d476f9d14c6461f18fffe63c206
- model-request-beb21448-8d8c-4b78-b78c-0e0089717924.json；ID：27a784e2-9f30-430b-97d1-5b1d8a3e461a；SHA-256：8ff9aed39aa13af560a700616b57c702c8f257887dfe6fedfadc561d73db89c0
- model-request-bf428567-001c-49ad-8a5b-70cc5f6907e5.json；ID：ddf1ecd9-8d85-4164-a9f0-e7b499609b09；SHA-256：6ab818e1ad950912deb73525e47be1fa269ab4a756a1045a8db81aa9ff8697d7
- model-request-bfc37715-68eb-4774-8bcd-cd3077749fa6.json；ID：7c64eb45-583b-425e-91fa-b8cf1557d449；SHA-256：3b94dcc2092c285df2be1b8b50b5c508b7361cfea1784d155df6e00c5a49a5be
- model-request-bfc3e3cf-83d7-43a1-a2ef-cbb2d9fbb412.json；ID：f6f50f7f-dcde-4b8e-8a09-0a2ce8192f0a；SHA-256：9ad83fb8066439e3128d105fe9ac4a463225a7813b45afad1077cc951e91ebbe
- model-request-c1d7e965-1756-450f-ac4f-e6a806cfab47.json；ID：9ce87c19-6d5c-44c2-aea5-8a68fc6887e0；SHA-256：57b92627a369060962764017905d0781b4ef2e2f9abff9b6464ff220467638d9
- model-request-c207f71e-c147-4b2f-a3fd-635a6994830f.json；ID：4ea2fdf5-e173-4066-8dde-03e11ac28ca1；SHA-256：59a205bafb15a536bd1fd3eb2fd8d27ba4913cda12e9edba069105b753ed11e7
- model-request-c2aea2ba-d65c-461a-8778-a8081bd49b3d.json；ID：934419d2-50a6-4f53-bd33-f0eceaca2803；SHA-256：6eb9bd91e29879a0e5e75887fe1c32d3414ec55a469adf4048435b61cc4437d0
- model-request-c6049712-a961-4b9e-8b98-8323ffa7d72a.json；ID：14f1a361-2cd9-4b82-8588-30f217bd035a；SHA-256：9468a54fa5f73eb64a900bb06536e4cfebee6909e71f6a3c061916b5764e49f1
- model-request-c73ea485-74ba-43ea-9523-2b5ad34883ee.json；ID：e361c125-6700-4dcd-be6d-996a882f9387；SHA-256：0ce575e7f0f960cfbd5eb5f0eeff7258aebfded896bec6b82a0fd27debaff35e
- model-request-c853fbe7-82c2-4312-bc2e-8c407fb4abe1.json；ID：0d3cad19-a0ee-49a4-aeb5-827cd10b5970；SHA-256：035d9a413543815a89b54acbb13bfd1f207521891bd34c6c30d2b30a00f20801
- model-request-c94fab1a-0061-477f-a5fb-098520c5a8c0.json；ID：94b9eca4-67b0-4e2c-91fe-41597ac4dc1e；SHA-256：bf43c0eb54129352486dbced89bfac7cdbecc3a7591ad0b18b136752c8c0ac8b
- model-request-cc6ab6d4-24bd-4fe4-9c9d-eb16098e7ac6.json；ID：f8e0c259-c579-4dcd-9a72-228ec0e0f22c；SHA-256：73fa00ef5dc90e7ee3938117b42f3b4da440ddb5b4996597fa6a106e0cf8a789
- model-request-ceb593c4-b962-4620-ab6e-ae741d7e7c87.json；ID：eff6bfe8-c142-4bb0-a740-fb3d02c9ce71；SHA-256：d5d9cacdb5d5e6ae7f4ec87c107b7cb0f82725d49bb6032eca5eddd544a7d22a
- model-request-d0727771-64b6-4193-a075-f16cd146ba92.json；ID：9f6abcb1-dd64-4592-8425-08978c4ccea3；SHA-256：6c15412bdf210ad088db70dea787d9dfd0306490a540ecf4c89eef25be6231a3
- model-request-d10e03a5-57ce-40ea-8cd3-23c0d34b1bdc.json；ID：262ba86e-03c3-491f-b67a-a42a9babbd25；SHA-256：ee2ac0aacfc9eda18bb17f32e6b8a08d1cac3b1e6f36948028ec7da0aa024bb7
- model-request-d1d2029a-5f43-4f9d-ac5a-d5886f782bfc.json；ID：08f0ef43-60a3-4d34-b0f1-976c22349fee；SHA-256：cc5edf5625bd626ffc10446b49dacf57f742d93ba28be0d80144f0fe3c67b3fe
- model-request-d3bf9fb0-81df-4a6c-88ac-9680b48444bf.json；ID：744b49f9-e552-4ccd-a425-a33b0df406d0；SHA-256：7d5735db9089b9bdf921bc761bd8fec3659c0d97a93aef302534ac725695fae8
- model-request-d4d37f56-ef43-481f-904e-eb7c9e7a2bf5.json；ID：54bb503e-ca2a-415c-a98c-64b970bafea5；SHA-256：ef8342910900fdc1ed34815163edb3020f37eee36657db8059d47f1f4383e108
- model-request-d5457c1d-0c7a-4885-9843-fccfaf62663a.json；ID：d3dcb061-0de6-4dd7-99d2-59d89b91f3d8；SHA-256：42b895dcb4689a18564d017a685c5d0e8cdfda582821a83ee7111dc42eccf8b7
- model-request-d57e3ecb-ea3d-4061-837c-58d99a5b9c67.json；ID：cdea6b58-0efe-4d55-8d9b-0173549ca69d；SHA-256：928f29059b0724a2bcf2a8a2218d9694ed297e1287e677a6bc9a78da87ccf7bb
- model-request-d58c2b71-aeb8-446f-8a3b-64c7a8a3d638.json；ID：fa6a26d5-4869-4571-bb01-fc784924133e；SHA-256：3b24d609607a057491cc44a7f8937f4e2d205703c35ad432bbeb869b269def75
- model-request-d5b97e7b-dbaa-4aae-8317-e92503b56a3d.json；ID：e7fa91b5-8c9a-4ea9-90fb-3889ada3ba9a；SHA-256：9a6d8553d0639629cf9c57f635305db75fe0787a5f1659454e739fcd5efa0d4d
- model-request-d8885e69-bc2d-4684-a043-9dfab7bf322d.json；ID：ff010d10-9189-453a-90a3-aa56a71eaec4；SHA-256：c8ddfd59f6c623edd529d21328e4a5fb2c336adbeefc18666b685f9b9edba38b
- model-request-da0233bb-cb72-4ce6-a820-68b357b9e272.json；ID：94ea8575-c7f9-4b87-9cb5-7a6d5103096e；SHA-256：6c7220201b38668798b132eb38d69a5f4101e0dde241d5aa9907ad0e0fc77eff
- model-request-db1caf7b-c5f0-4bfd-bfbe-7dfa884dd0cc.json；ID：ba66eadd-2055-4b8a-ad57-58d2b5f9fe09；SHA-256：af81f0bc309fe089c6e58169743a0bbcbe983415575e952652a390930c432e3a
- model-request-dc06f7d1-7681-450e-b204-2ad258938b64.json；ID：f97add88-bdf2-47b2-8e9b-0a523c433805；SHA-256：85b0a38007a66405ea348a3aebf0dff0dca947661d9588f2fa687e3eae6cc352
- model-request-dec5546b-1f27-4426-96c2-ca65dadb4605.json；ID：03d3ff22-99f4-42ef-b37e-1dfa4735e7a5；SHA-256：451666f2aeb6c0455b12b67434c0d001a0a9bae4eeabfa4306aae33e058e6724
- model-request-e115b1df-8db7-4735-9671-91fe64407d34.json；ID：c0f51466-dec4-4e17-9b15-813b21a217e0；SHA-256：af800eb7425db53ab6e502c098265b1a6a9e4e55af017cb1550fc7db2c2c228c
- model-request-e130dec1-8421-4c84-b444-d86f1f47e833.json；ID：dfab45ab-04ba-4d2a-bf77-eff917d77920；SHA-256：d7a2f0cba716dc4fb2ae2b2a59199782641666a5ccdcfcddc8cb888fd3a53977
- model-request-e20132d5-b05d-4c8f-b7d5-eabdd1c645c1.json；ID：47dfeeaa-e303-4adb-80c9-8aa82e3e6f17；SHA-256：269eb643d5118023ddb11be9ebdef440baeb0b513466eb67ecb162e999d79fe0
- model-request-e22cea8e-e631-4d23-8a41-b4e72ebb1630.json；ID：86d3870a-8396-463c-8a1f-259887424705；SHA-256：67623540f12b2a125e76d6b26d660cbb7a978c7bf54b9de24d2f263e9aaca954
- model-request-e295dbd1-b40d-4260-877b-48f29291004f.json；ID：8fe253cf-27f0-480b-b346-f6bc71944434；SHA-256：6ab0c438e9f4e588b715316dec509ffa2cb69a491ab05975519e807a44e03e1e
- model-request-e2f2b2b8-de43-4f65-9d28-4ca34fc148c2.json；ID：ab499bd3-95e9-4916-a19b-215ab3a91037；SHA-256：104b50f299373a30550e8c794c5d3801931e5fc91adea017495049cc97d0baf8
- model-request-e352ac8e-80f0-4aaa-bce7-8191d2e41301.json；ID：5c8d2b20-226b-426e-a5cb-b65332d924a9；SHA-256：028972967c9b86180abc9608c0bf24d1fd7750ddb2e0aacf4a23a8fa936fc8d9
- model-request-e3e71a6d-bb6c-44e8-83bf-da4a4f7bf1b4.json；ID：9548113c-42c9-481b-8a2c-79473d6874a2；SHA-256：b508206153f297e8c7864738cb8b15975c8770d58c86cb20684f013ccd85a02d
- model-request-e4017e6b-ee3b-4e4d-9e86-9d6c99333a32.json；ID：c5be02d5-f786-4fd1-8c21-89ba7e96f029；SHA-256：958cc873da0031008cc7f3ad4e36be1c4f85b05de35504d3b807fe6c681f92ed
- model-request-e44f89bf-071c-4f2f-bef5-3cf90b809af3.json；ID：fe170f69-0062-4fb7-afad-8c47957596e6；SHA-256：16380d56f4ecec32531db51798fbf87cdc0b2c8642eacba9f4ae8dc67cc6004c
- model-request-e497bf60-d6bd-4ce8-bffc-e81e284d3dd2.json；ID：ae65828a-ee7f-4237-96f4-3d8f2d5e9194；SHA-256：b92e6fdeda8e7268700223d8ac9b8c1626e463a4138c2e108c9ff7aa7ae49b31
- model-request-e534ca78-8c2f-41ed-b4fe-d70c445e6597.json；ID：832d35b5-bc3e-4b57-beac-51a3106e6ddb；SHA-256：f71fbcf6e4fa0eb9b8678ed01d9e2676589ef5f5eb4a1d232153ce688fbf0d82
- model-request-e8a8f199-f79d-4fa2-8332-1a410f476a23.json；ID：a51653bf-2794-499d-9518-ec9950287746；SHA-256：4ba369f6d830e64718e8da5d49a60720f6d3ddcbf2f01af61dad518593efbcc2
- model-request-e918d55d-cacc-4e30-b2ea-ebcfbc2ad1c8.json；ID：b4d60789-b8f5-47ea-a6d9-9870140ecabc；SHA-256：1fd60ef5303975bbd13d1a5288fb1b7a1ac0b871b66d3d9fa4451752e868d213
- model-request-e93bae65-1925-47f2-8667-d73a07a7e15b.json；ID：edf2f3e8-0d34-453f-ac95-cf1d24d7e90d；SHA-256：11157fcd009db71e866713baf529519ed6690af160186997c9d508dbd1401947
- model-request-e9f72f0f-3b48-46af-aab6-079aaa9125a2.json；ID：da2b0ce3-a86e-4425-9995-15b94e953f09；SHA-256：7cf2abe0b41930268f0087a3e2bfe3d5be4daf63586f164975c00b73b40211ff
- model-request-eb49482d-8640-41e0-956a-2d03a926dd84.json；ID：9fbb1ebd-d60f-450c-ad0d-7fe6d7cf7cb7；SHA-256：45c0be655db5eea32e3a27decf890fce0d699251e93828b49d6afa005a8e5804
- model-request-ebd6c78c-38f7-4e53-8e02-46e8ba979e61.json；ID：6883228e-cae7-4c4d-bcb0-4b4d1743b835；SHA-256：c1b37b0833fb7e60d3fc863f87710cfa507ea6c4d7bebab7f3d80af53ca4b85f
- model-request-ec6c2215-411a-4b53-b434-0e4db73e34d1.json；ID：7256b38b-2d0e-4ce2-8f0e-61eb223398b5；SHA-256：ecc52ddfa890fd4a6bd066763301236177919ea1f98030cc39195f5b2553adec
- model-request-eecbfbd5-f9aa-405a-9a8d-b1c9e303840b.json；ID：0804482e-41ad-481f-bdd7-894f7bf15df6；SHA-256：38a1f5c745ae894ab4451f0e6ff795d4ef208cd00f4ade3142f717327c75b8c9
- model-request-ef938c30-c52d-44c9-9174-df26a432417e.json；ID：c2750000-ab57-4f6e-b6b0-4197ecb6de72；SHA-256：fd709f36299bca1e20af663728bcb1f375f6ceb399cc8360600158b3e9580d12
- model-request-f0cdf5d9-63d3-4ea7-bfb3-4513a02aeef6.json；ID：241aca85-51fc-4b19-a549-5f29a945f190；SHA-256：c2567ce6585c9bc09e0eba221760ae9c932c83c72a78d58db2c969b4fdcd9cfd
- model-request-f41a1d65-0370-4654-b9ed-a06a9deab796.json；ID：67276ee8-9df1-4427-b60c-c5d1d3a33aca；SHA-256：2f3c85712937bde7f9342e4adeee67cc8cf217912f6d4e9f62f9c27445c3903e
- model-request-f48aa519-ef24-4c87-a099-4e107efa79b0.json；ID：dc4a5f99-5eb0-47ad-92e1-af86967fde28；SHA-256：c3a1f57322552bfcc4237a3517532a79196ce75c5f2d9508ad1d175a9c825444
- model-request-f6fec8c8-7ad8-4844-9486-fa2a645c4dbb.json；ID：4c618acb-039c-4854-9121-0ac384b9cbfd；SHA-256：db2254fb256600f24bce411390a3f6620cd60874fbb1f2d57a934524088f7e62
- model-request-f8289876-b547-442a-875c-46ea09500c74.json；ID：20a08cc5-a894-4a58-b7ee-68ceca35a992；SHA-256：77a510243f2f628fc4ab3b7919bea36ab5ad44ade99e82f5337276c5dedad576
- model-request-f8a2cdd4-5d64-4ea5-9d37-0b3d872ea3b1.json；ID：de3f0034-03e1-47eb-b7fd-b19b5e174a19；SHA-256：3d2ecb1c4614f86f13a5cf348a86d81a7bae7baad6b0c883432ee3e19acfc28b
- model-request-f99f243f-0848-4acf-8221-0e8981573449.json；ID：db9b386c-c46f-4178-8f73-39c7d2ae9552；SHA-256：cbac690783414942a97d9b4cd06db739722829bd8dde535e7aef9b9ff5b8fc43
- model-request-fa2a34ac-6bab-4c84-bc48-b1da7ff06fc2.json；ID：6a9c09e5-b53e-4612-80df-154617935071；SHA-256：75e9dbad7743bbfd2f66a7f5096384471e6d519469b57da396636980454032d4
- model-request-fb8fd7af-23b0-41c9-9f9c-3f0c1cdfc224.json；ID：d8b31c78-be93-4c2e-9dff-c890c7444b8f；SHA-256：72db2b60eb77c2a90d9c79f04624ba933d5b37ba84d4db4981d3d92ddabc35ad
- model-request-fc584efe-ea2f-4c0a-a9d6-fb7e49a6c275.json；ID：942eb182-98bc-4f88-8f59-fb848f053fef；SHA-256：ea00a605498b0683e575ea98746b8601da99287bdd3a119b5a878c036e5617e5
- model-request-fd2f3dfe-b490-40df-916b-f60790f27044.json；ID：1929398d-0bab-44c1-8db9-7db7c94f2f6e；SHA-256：bb60832d387c09a89ee6ff9676ea611d618288781c6b309cfa14c49c658b3faa
- model-response-006760e5-b510-4131-8c51-dcb3fcb159df.json；ID：f5e839cc-e78a-4c6f-8c75-000807afb6b8；SHA-256：217426b4bc417ecc95ac8acd754ad3ed781d3ebd3227f25494ce0e3c3d65501d
- model-response-007f65ce-86a5-490b-b204-88a36ac2fc74.json；ID：3f5e7419-efc7-4089-bd7d-0a3925169c81；SHA-256：ed9de659eb6ff8eb6552c354054b4030b6d69aaf4680d09376ece883ce162b5d
- model-response-008bac27-d215-4ba3-9d89-404dca850cac.json；ID：c03825f1-8375-4749-ad4a-2a65f055130f；SHA-256：4c1fd4def7e260e0c829146497f422dfa38e03f01d7efda6ce256101ae51ca0a
- model-response-03a2b8a0-539e-4847-8b81-2b6efac6aa90.json；ID：dfbf3b26-2d71-46d4-bc3f-57e9a9d10e8f；SHA-256：fc9be67249cdf4d20e343ea3630b1b571fac001e477b0060e597dc1e608a31ec
- model-response-098af4c2-2061-47fe-a127-8dc96b436f5c.json；ID：38d8ec83-6f2d-4fc4-baad-aa7183cf36b0；SHA-256：5cfe91e3235214b8320f1152511cf449cbb8d500b12cf30884a2f03abc4b5204
- model-response-09c4c808-907b-48a9-a77a-4419adae1c02.json；ID：3880ad17-6558-4740-bc09-39546052653e；SHA-256：1b3c932ba774d5c6e4ce3cf3fdc7e79bd5f4874eb1e9e86ab6df4c28e5256959
- model-response-0b324bf6-b6e9-417e-bf4a-a1c3e0e57253.json；ID：bd603625-21cc-4be6-8689-6d954f91f162；SHA-256：8f214df8b58092572dcb323ee3f9669abf8acd403acc73dd738257c4c45ecceb
- model-response-0b6eefc5-4ad2-4529-a7da-827f94c194e1.json；ID：f262dfc9-9f43-4699-ad41-60b18f54bf52；SHA-256：ffe07af94f316a714d42652b3fefcc68882179678112fc630fbab91940aca3bf
- model-response-0f41e2d4-4d29-4a13-a478-ec3375b11933.json；ID：2b480ecf-b5ac-40bf-b979-1de9d3a53da8；SHA-256：89fa1bea23b6635a9dd9281d7085d8f7e46052d9e52938a70bd8c3d663e6deed
- model-response-10aa61b3-4492-44fb-b719-241b9ff2891a.json；ID：7e9e1d27-7e4a-4921-a280-ebac69e03cbd；SHA-256：b54555d0f09e37027bcd2e00c42cebb3ff9abddc8652e1b51daf6b73bc881a71
- model-response-10abd90b-797d-43ad-80ff-e77dd4dc28c8.json；ID：b9305f6c-f030-4ec6-bc71-4fa271f536fa；SHA-256：149a720b644181d7a06c9e25a351e6e9af653dfa9cf2cd2db89b3cdcb74de506
- model-response-112912ca-938c-4d0b-b4a2-dbf4583a1f58.json；ID：01876510-e74e-4e91-ac2b-075bf90693a7；SHA-256：9e4f18d0e216bf551bbfed6643cdd05d065d2c2cc7fa9f57a11f530012c579d0
- model-response-11c8f321-0be5-42d1-93a2-da5257d6147f.json；ID：dbf980d9-753b-4fcb-b7e9-2be07e8d3a87；SHA-256：0dbbf535e1ae6f7381deeaf8d1a7148ae0a346ec9a9952dfbeb8d88c14a30be1
- model-response-12732629-1328-4ff4-a110-c85907fa218b.json；ID：2fa452c9-e7d4-4e39-9da4-da72c58f1966；SHA-256：d6d45122c1628b837d1511bfa4a706a13737253e1e08d6e34b3d9c3a09d6f338
- model-response-130ab265-ac85-4c93-81f6-a412f2008a4d.json；ID：d0a8412d-41e2-4407-9e9e-4ddb21685669；SHA-256：cbe3cd7466ce104d7f910584a91c3fcfb2e1fd2d1c4706ccd67b29914d47e225
- model-response-1330e1b7-1078-4a90-bbd0-630b5ba24120.json；ID：f940d03b-db38-4f78-bc3a-7b4138eee457；SHA-256：91d6a680cce9939d1e9ca2b9594b2df527db7270d609f98ee8d29992f429b052
- model-response-1419cee7-4856-4743-9f7f-053efcbb4acd.json；ID：7583fe57-aa10-4de7-8b27-4bd7a1cbb551；SHA-256：ff850845b9715c756b0c2a37a814cda6d009603cf7e913d81b471c85fd5051e4
- model-response-143249fa-6b55-4683-ba41-a302e307c51a.json；ID：dea2c505-0e7b-4f43-ba99-49660302688a；SHA-256：081755f62a39f418da62a8ad6569847b91cf98f8f40289036fb699337f0a3134
- model-response-1445bbf2-500f-4788-90ce-605b3512f63b.json；ID：c91096a6-1f92-4cc1-a8ef-99287e72b098；SHA-256：5c0bf20d757b54a94c42c1c9bb71b3586ddc2c0c88b0c96bc54fda8bc310891a
- model-response-148677ae-bfa7-49d5-a671-b88a307072b8.json；ID：a523c9fa-1352-486b-b545-bbeb28321fd4；SHA-256：90ce45c312c56753d0619e3b673645c67f548c041079f7b988f55bca10608cc2
- model-response-15a3b775-4170-47c6-b92f-f29e0e54a313.json；ID：f6081e7a-f17e-46d0-8271-cc502b7c51ee；SHA-256：4c6bdfd29fcc1b67245ac5267f92748161434ba097f2e71bbd0087c38ac1078a
- model-response-15d70f82-fcb7-4335-92a2-18609e1cefbf.json；ID：60ca2dc9-4cd6-4cdb-81da-d48c03b41de0；SHA-256：21c07ae7e39545c26a29dade1d3f983751327997aeb325f24155bffb327a802a
- model-response-1a1dded4-a604-49ba-b352-672ce2f7dd94.json；ID：c990e91a-5512-4da1-93b6-94f997ac82ba；SHA-256：e18c9f9feb883e03ed588db13db1c12e77a8b5a1d7c2f8b4d382296e21f47b4e
- model-response-1b1d3252-084f-4c2a-8731-9302cb8511a7.json；ID：97dd967b-b7df-40e1-90aa-23802b2738de；SHA-256：87f3ab48d6cd3780e2d92272f947636b9bfc76948bc10bd214cdc907fb4df059
- model-response-1cb12445-ed62-4b2f-8f50-c258ff14405b.json；ID：2da9f755-1b74-4ecc-b487-101c3e661bf9；SHA-256：dc3f8fc36cf3e7e4ae7f73a9fc4adedd3ad7e4377ddcd556a512f297d147e3a4
- model-response-1d7c6202-8475-49af-a9d7-dfde980d0c58.json；ID：4139a865-7b26-41f9-99b7-035f43896e08；SHA-256：83b087b830d5f3e2a486fbb0057299125e1901db9303030db7612f21fe7399e2
- model-response-1ddfd9d9-ea8a-4c7d-a902-da425f1d6807.json；ID：1a54fff7-8297-479c-8811-ae4a6b4eed0e；SHA-256：2e0e88f4958445a12ee2f83613dd5e013616d3255f993a7069cca499cd574134
- model-response-1de7dc26-3ae0-4fa9-9759-c7769e20a7aa.json；ID：1071857d-cfe0-4e68-8a9a-513780d910ee；SHA-256：eb574c6f881ecb7f83f470075bf8af725b93db9d2de38f47ed3439bf4496330e
- model-response-1e6490ca-9135-49d4-a58a-dd3b336bf72b.json；ID：d2907101-4b54-4a77-b036-e049f7f290e6；SHA-256：c7ef996945254287d130e91c27bdbb74b1b63f819b7b880b711f4d8df890b806
- model-response-1ee0f99b-3f30-43c3-a60c-dc1629ce7ca6.json；ID：2ec133f8-bd5d-4594-881e-53ed9cf666aa；SHA-256：ac24b77a5774ae0a5514b2f7028125cd71e756090f4a360192d22c5b43946f3e
- model-response-1fddc46c-aac4-400c-b7b5-a34ef55b575f.json；ID：ed16d3e7-699e-46f9-a7e8-799e4b0b1315；SHA-256：8fdafb6cfb029bbb5afa8f6ad52e307cb049f2cdad2aa730762ca4c70d9483f4
- model-response-206c00a2-0da3-46ae-936d-c33b76ec1cce.json；ID：2614bb2b-fa24-49ad-91a0-9ee0cb736dac；SHA-256：e0fefde7c36de71c7e0b3599f91aae3f3d094e839286c6658fe782f79aebc1e8
- model-response-20809281-eabd-4d29-ac5a-98406a6fcfa0.json；ID：e54d38dc-4801-49d9-8047-f6f8803f1b0d；SHA-256：c398bad82af10f1b507371348708f010ecfe6f1b7a3e6a526c5a897768ba227c
- model-response-237d73e8-330b-41ad-9c6f-ac6a21813b6a.json；ID：23fe9afb-f1f7-4bd1-b1ee-fcaaaa07312b；SHA-256：885d2b25d4c164e18bcb71041654619b28653fb64ae77534a7d9bd3a248f288d
- model-response-23fa146f-ed35-45eb-b394-dbb9bcfc258e.json；ID：a6d58bfc-3700-4384-ae26-ab2374e06c99；SHA-256：a1b5f3f54df77d3a85ab901fce97ca6e5ef2205984d1937bf02a911125991c0d
- model-response-24065e17-20eb-4382-9a20-c8210885799d.json；ID：907d9454-d1b1-4069-8c13-8ebb3e1b9d0c；SHA-256：fcde0a9d4d8c834f77bbc051e256c8ef38ee19d8cc761d3c40093c5444826a12
- model-response-24cea978-729e-48cd-8e95-df0e1f07f348.json；ID：f23bb8d9-b0fb-4867-92f0-a5c3221baa8f；SHA-256：d78a445fecd283b2986761f1ed87e3ac8d2eb3d19790f3c5b1207915f26c1db3
- model-response-26576ee7-5c99-4506-aef7-4803bb87fd89.json；ID：420db517-4ee0-4daf-8e5b-b47391122621；SHA-256：fb755399a82dd12fa9e851d7246b2c59c1494bc5ff7b78f0c68931781b69660b
- model-response-265a55c8-d679-4463-b6f1-4d620146957a.json；ID：d07a8c2e-ef5e-409e-b80c-8e353e207a42；SHA-256：81fdb2a516b4ddb32bdf7f04141df22f6ba38629bef7bcc57ce47007dda22c06
- model-response-27a1922d-0392-4f43-bb71-4a9b219daab8.json；ID：fc74bb49-f44a-4f9b-8902-b2ab08bf55a0；SHA-256：9ec9397259cd73e75f6fd9400388007579b87891aafadad24e9db98a8892f6f1
- model-response-28af3de6-bb77-4fc4-8566-1c00b75578ac.json；ID：05a2c977-e424-4dbb-aa2b-b377654b2ace；SHA-256：6cab407329c56ee0015af2b1f10411e027b14852b4b3f873398ad03e38d7e2aa
- model-response-2a7583cd-53b8-470c-9e26-8d7fb923c766.json；ID：e6513079-a798-48ad-906f-c1078961c7d5；SHA-256：eec00e4db61787aa692627d2db06e42e57547c88f300575ded9fcec6d1395535
- model-response-33f4fde9-d274-460f-be91-213a8344bd84.json；ID：ccca9bc8-8627-42ad-a0c5-0c501c13f51b；SHA-256：ee81b0931ef7e2a416d066ac7bc87887539e795938256fc971b1a1a63eaa27d6
- model-response-340a9eb7-674a-4dcc-b5af-0c722c4fc492.json；ID：43ad2927-0ba3-490a-89c2-25df33729f70；SHA-256：9e6286885f33b2795a38ba01dfaec7778f57b63f628de370786cfa5093243269
- model-response-34d2ed0c-5a6a-4957-af3f-9016ed53c439.json；ID：5d36c08d-576f-4e56-af60-235cc1e771f3；SHA-256：47d49e5c81280bb17396db07f7a4f99e5927ee19e7435737f4b7588668a52318
- model-response-3778a094-a983-42f7-a003-41d32d78859e.json；ID：4251a449-69f2-480a-9bfb-d600614af9aa；SHA-256：5c08f2d7ad8173702c1a85995628a24d6dcc22a5e760a81e1a255b0a707bbe2a
- model-response-38730b89-ea07-435e-bfba-ce289260232b.json；ID：8514a674-9ade-4574-b521-e4736887b2f3；SHA-256：45f657eb2e505eff96c996dca75e0905d44f38fba62a7e6df0ae3f43444e5fc8
- model-response-3bb046f7-1a97-4c00-a6f4-a8882d2cd2b0.json；ID：8162a0f6-4027-4f52-9613-23655feed573；SHA-256：18321254b7aa4ca66284b003c5c6f9401688c09955754ab6bd0e4c7446843780
- model-response-3bb28bd2-15ad-4afb-9eeb-171e1ada60aa.json；ID：c9b27c7a-444b-45d5-9c61-0d3233ba64eb；SHA-256：cc236fe8a45e9cfed072f937ddc2db7f400d0811d1c32fa22b0fdd7cb47ce794
- model-response-3cdca581-1c96-46a7-89bf-1df92d6abf3c.json；ID：bebc4b1a-43d4-49cb-827e-12770ae194d2；SHA-256：47c648b0f0b2094a9e8d066f8c5f254c5c37a5211305129978a1e637c125bb04
- model-response-3cfb038f-b2c0-410e-9dd2-e38274cf415c.json；ID：ecf8dac5-d16b-4b90-8708-a22de9dc1f2b；SHA-256：d17e5f674382c2c1c58a4f4748ef800be74af28abdfeba410a782c359db2f808
- model-response-3f70f8a3-d6ee-4934-ade1-2f14317e84bd.json；ID：7e736971-a10f-42d5-9511-2624d1da5b77；SHA-256：24c1c65cbfa90364e6df0d72b5a686f4157ae8517aa4369f4923fefb1f86cdc8
- model-response-3ff0e964-1f51-42a6-9468-1419f5e92a4a.json；ID：fad4d015-6283-4e67-a353-18da47aa98b1；SHA-256：d9076f29757194e89b14730ddf4ed4039b08da5fed59283c9534fc20f31729e9
- model-response-3ffd6a69-ec22-4e26-8d0c-6ebf13187f80.json；ID：301f0077-f258-49eb-929f-9bc2b49a4e6f；SHA-256：41bcbbd6487aa027511ab73afb67de63b8a29412a069a4ae4ba884d400a0bc76
- model-response-407affd6-7768-4df9-9f62-c64ccc00d8da.json；ID：d1a69652-5eff-4d75-a5b7-6a288f06c10a；SHA-256：36e144a8a4c4ae21d0e0a5eb3a0924ddfc8ec0cbb6a8c17b2e3f82db5875ad2b
- model-response-42506fc5-a851-448b-890f-52359e793ca3.json；ID：2ed0ad51-1029-4bc7-8d09-73641400780a；SHA-256：fc03289be74e1738df9dac93d371a38b56dca61db739c21db688e39cff5e3baf
- model-response-42ae9b47-0f3f-46e2-9440-f9797da515c9.json；ID：3c363d11-65a9-4736-b5be-ccb3aba8e486；SHA-256：9f0c2b73fbbc60fcdfb4346c08676ef1457fb3c80ab09730859ae6d56721bb96
- model-response-46c35e63-e899-4915-8b6e-cfa91b16e384.json；ID：94c8bca0-9a6e-4265-8bd2-3576cb09f504；SHA-256：f15352762ca58628c48a7ceff3aa216219cf0cdd3093a854f166b0129aba3063
- model-response-47dfcf78-2d40-4ea3-986a-35920a858fd6.json；ID：e4262bcb-80f9-40ca-8d21-c33d45ac3dd4；SHA-256：e2f82f44e6353dfec9a7e2c589ca13a28d3d1e66dedfded5d948b5ff1dfbbb5a
- model-response-47edb0de-7d58-40cd-b33b-2b0257633be6.json；ID：af41b40c-45da-4cb2-9857-1fc17b07c251；SHA-256：594a4b00480d572d94bd69a6b3cce84c6390b95d1ed655014708aff0a0d1f6ef
- model-response-481a5da8-a349-4015-b3a2-db126d878276.json；ID：27b9ae17-ce04-4604-9fdb-d001abe4188f；SHA-256：e6919547563085ff01353f3f3e1c345c2824c0c366992cc85c28ed6bedfb663b
- model-response-4b6a8edc-4301-4f7b-ad6d-321be226d77c.json；ID：030ba3ff-17ff-4c2a-9922-a7ae122ac3e2；SHA-256：600aa56285ce881ddd2aec33527c35f1ec606ee4c42fe723529bd0e8a948c12f
- model-response-4bf65494-512e-4781-af67-e9b2cfe257e2.json；ID：f09c094b-4ccf-412d-8a7c-4300de6f51cb；SHA-256：7bc415d59f713ea7c7945bbf180af3ef5608c80792d6972981acd3b781e90957
- model-response-4c6d01b3-6a9a-47ac-89c5-40ac89071807.json；ID：390278b9-1762-4116-a1d7-32146f8f6101；SHA-256：05193addef9d2862a4777f85681a7a8c11c87be50539b511c27980ec6e6c2697
- model-response-4c7c8897-fc8a-4514-a470-0884d176a7f2.json；ID：163eb359-1ccc-417f-b921-83113a6fd8b5；SHA-256：be010e5746409b06bc4118663890198dc78164588654f1c7838380d97ed95f50
- model-response-4fd9b8b5-3e01-4f6e-a782-ed99dd940a71.json；ID：5b913a67-6ce0-48f9-9eff-58af4042bd55；SHA-256：7c0305b9853445472aee574d4c478627291aa9d7e3269f9f73efef0466979127
- model-response-50fedf88-6adf-43dd-9171-2dac0e157b0e.json；ID：163215a2-90b2-46d3-b3a5-d4f18427a6e1；SHA-256：81e4837bf38d7d4748615b35bc8e1ec13f0475360205d2352ca4c38c7e8b667b
- model-response-51337f50-cc10-4396-b2b3-4c757df774bb.json；ID：6534a18e-ced6-4aad-887e-95a3783b300e；SHA-256：da728e10dffab75de67636bac556760f49060394eadddf85de59da51a2010876
- model-response-55259bde-1e0b-40b0-b7b7-18cf21b8456b.json；ID：7fe352ea-857d-44b7-a55a-187623ad9b2a；SHA-256：244dd71e4b06e6faf5b031ac0de2a55e9a91861b10912d69947245f5568fb74c
- model-response-55d3cfee-42ec-4425-9310-3eacb1855b14.json；ID：fb7c8e23-5018-427e-ac68-26eb66b99ae5；SHA-256：9ae060d374f2621de4cca471687815741181ab6d6c2aa180c1e46e8d9bb4a409
- model-response-57c1a2ca-c52c-4ee3-b9d6-b34479f0dd3a.json；ID：f2f048eb-3771-445b-b093-5449eceecd9e；SHA-256：113f28c426a1ea6c8270deb9383f3afd6e2777e20888e08860fcc3789788f8b0
- model-response-5a3d5a42-a16a-44bb-9a35-c3b6a5a96480.json；ID：fdd21084-9375-4276-ac7a-c61a0a1945e9；SHA-256：10ff3bb711960c045ecfc1840879948a02767427b337e8f441a74035b3354886
- model-response-5c9a2fbe-8705-44e0-bf58-745d743d42db.json；ID：c2b6c13d-c4ec-4afc-afde-9e3e03f2c879；SHA-256：f20d2b4aa97eed5d3eac5f2fbdef438412f4d8aeccb30ff7af424494387193b1
- model-response-5ce1884d-95a7-4e3a-86b7-978cccb5995a.json；ID：ab13a9db-3e62-4d6e-a101-516b856ac8ce；SHA-256：2a72c5c589bdb655574b78bfab96b6cbdfbb06ef41b7ec6ca5dbb41fb9d80a15
- model-response-5e09bd41-890b-475f-b938-19f6843aaa1f.json；ID：df8a969b-91c7-4bc9-bd58-84b6748354b4；SHA-256：71b35f7c98373098bc139fb2a1fb1e7fd8213a89bd7a5e7bc359215f774624b8
- model-response-5e8d8896-0b0c-4604-a0d3-1ff143af8d1f.json；ID：e648ca69-0366-48a9-875c-d8964a13ce10；SHA-256：5af6fd6731761082492a5f4d468f982bca0edc9bc4096532afae3a8cbdf3ff65
- model-response-5ec17790-0075-4936-beb6-e48b40b58dfe.json；ID：ef75d4b2-f7c6-4e98-a7e1-f850456f5c36；SHA-256：96f2160820c1f1964a44f65fc42e3c6c435f056f4a17995e50b93067cf58d33c
- model-response-60453d67-e478-4389-b52e-f977ba91e116.json；ID：8d32db80-4157-463b-818e-79fb815cb6be；SHA-256：e3b59d522bcf73d3dfc7c688e0703181ceec5b03b214ac94c77cc7bd5c7cc509
- model-response-6069be83-6dd3-429d-a65e-19607f2c9cd1.json；ID：2f13a334-54bb-4ac1-b9f5-5e5e0fa30898；SHA-256：b59917bbd4398cb2db923648a1fe2f2da41d28c7005d1c9b251a982ee98654ca
- model-response-63421946-cddc-4540-a85d-4dc9864393b7.json；ID：f2e44939-b6be-409f-aaa7-8f219a41c6b1；SHA-256：ea3ffc1cf9f4a42334193ade02f91d84bbacf3b11facf7014870bcabc98918c5
- model-response-641f64c1-a349-41ed-b0a3-6fa80f6c8a5e.json；ID：0ff2b652-3f0e-4274-aa87-29dc4bfeef57；SHA-256：eac069a44e6827f89ef708923f2deca6ab1d8cc257126cd1bacd78c6d67ed1c6
- model-response-645c34b0-21e7-43a1-b0cc-f3c6e9d59eb9.json；ID：13f57152-3523-4e0b-b8d7-d1c2f2e33c54；SHA-256：da3a12de08984ea8eb87c92a019d41b4ff31b1ae30ca66ed6d6fa524ebee6542
- model-response-648806ce-006a-419c-960f-ab720c5457fa.json；ID：48da3026-d9a4-40f5-b580-bd2fa66ca46e；SHA-256：a6adb939979f4ff85ca1509ec32ec3ac09471a2c7c8cbf18f18b5d21c8070335
- model-response-6560e948-087f-4c3f-b660-cbec55472071.json；ID：9a2aa3f6-5f09-4397-b814-7dd49286ba4d；SHA-256：4b7b6ca451bf34b647f25c0a3c0e1be9902c768355e4d5d3df37966353b089a6
- model-response-66cf6c54-e400-4ca5-ad07-95d5741f6ec8.json；ID：55468f4c-92eb-4d63-8539-86be0d06eeec；SHA-256：0c7efc7008edf3b81174c9fca48142063bb91fe0aeb3e8df9c1b7746902038ce
- model-response-6876e713-cb31-4d91-a27e-25aa754d037c.json；ID：1e174360-f742-40cc-b040-3488ffd1d0b4；SHA-256：38a3f511f7190e7ed3d75f9e8622bdb48ca9db4e69291ca246482599d8ae3bdd
- model-response-6aeacb92-b291-4c16-b58d-5db0ca78903d.json；ID：c4a54a20-343f-40a0-9dd1-1ebaf39a43f1；SHA-256：1c31aa2656bf0f43ec3bafd30b7f97164a13a1b4afa0a0df1722b6993257197d
- model-response-6b0da6e6-a5fe-4645-83a1-488532021ff4.json；ID：dd65004a-0828-47d5-86d0-1bb1cdb43f1f；SHA-256：f955b56d28503315acc6cca2150e5b4d293d53ae217bb9dbf2cc28c3da574a86
- model-response-6b540390-2fec-4ed6-9f9d-239d64b5df95.json；ID：83e6facc-fc27-4c6e-ba82-32e473e5e170；SHA-256：2a9e53352721e1f4aedda8c3318d166b7d994f940d8bc18edbbaed66fe5484b5
- model-response-6cdc449b-df02-4e4e-a611-ae2d842b08a8.json；ID：0c02f11e-7bd7-47d2-95db-17708b2cb0a0；SHA-256：06b9e6705c331701d16d7b30f1ed774445b919a911b98d05ce077c3d06e8ceb3
- model-response-6df3c10d-583e-4b8e-b649-20265c8277cc.json；ID：9e02448d-faae-4b53-9744-3a607758722e；SHA-256：7644d169e68ddc2216e5301535c41058308fb0bc7f94c3a1eb46db83c2287850
- model-response-6e8243a8-9ac3-40c2-9e4d-dc9c69b0547f.json；ID：df0a3f6a-3aca-4895-9de2-b89ae3526b73；SHA-256：b0e8ce35b13a553675d8b3d7578122a96fbdc9871d6263d498fc404012f4e01d
- model-response-717da5bb-0e56-42ea-9a4e-f8c1de426668.json；ID：4c3f9760-7db9-44a9-95f8-40fe5be9c948；SHA-256：3df434fd44d7868c3c5b641b6b91e8cc96dcc1b930f2291374a2c6b25e204ff4
- model-response-719d9fb2-04e3-4f92-9244-1bf52c21abe8.json；ID：f2a88506-0118-4baf-b5fe-71035c9641d5；SHA-256：fa35863b85a9918dec72e8fb4bdc9ca0869b16dd888c432ba6bef6c44898ea34
- model-response-71e504dc-5dd3-4acd-add0-d3ae1543f688.json；ID：340ac512-b2e5-4f60-8de9-2a31a78ede9c；SHA-256：889ce7a8066fdbee340c50fdbde645e0a943ab35c2cd91ba7a598ebdb4fc44b7
- model-response-726c62e9-df6a-4e16-ab45-b2b744a6d3cb.json；ID：8e9eb76c-200e-4c85-8393-72f0f0f4e610；SHA-256：e906b2990691dc75ace75041ced9516eb2e80918ce65b3937c2228311e0e7efb
- model-response-7352b258-59be-4b02-9011-8de0c8d5b23d.json；ID：babe2586-c252-4326-8a40-cca3b4589924；SHA-256：73d9a710a5c98a1bc6eb09c36612f09b975150834a48aa1979cdcc58528cde7d
- model-response-74ce47a5-c2ca-4c7e-a8a0-d640bc0a82f8.json；ID：46c11e88-736f-442b-b6e4-5d70f57a2f92；SHA-256：afaa66e70bc06f622e378a5702a5165eee9fad18c0f28c30c874ecdb9871bc12
- model-response-74ce5fdb-8ee2-4df9-a795-c1bda76df31a.json；ID：eeb14d0f-8f3f-46de-81de-251f8c4f2f24；SHA-256：bd3447363e5d701811af66b0ac63025aa2199324895478f358da070ffd4ce24a
- model-response-76573482-406d-48d2-a61f-9cc3fab4e684.json；ID：bdcf1294-7b1e-48f5-9a5f-c1b1671ed86e；SHA-256：90958f8a8801cfab387f4a2ee842d8e956a71b4f8a5794b594e57b5b0243a88b
- model-response-76d40150-324b-415b-be5d-76ca6ea6f337.json；ID：d21e3460-087a-491f-8e6f-d95a48e7bc37；SHA-256：79ebac616dd3c1fceee952bff3a124872aff939975adcd2038bc933632efa91e
- model-response-7a003918-9940-4276-b24d-54d16699fe5f.json；ID：2426e448-6b49-4863-b5f4-918d51691dac；SHA-256：d39b8b20cd34db30fb0f82ad79b848b74f24f6a720b84328db4838af6f0b1e69
- model-response-7a98c78c-fce8-4b2a-984b-c028b57f397e.json；ID：ee23a7e9-1ebb-415f-84ed-00a7853540af；SHA-256：ec4b6553553d9e45f1e2fbadc0541ef97950d0fd1e3c4215479e7377e67ca6a0
- model-response-7c90c897-e22b-457e-9763-c23b69d41389.json；ID：ac2751bf-6955-446b-9191-75ee6efde597；SHA-256：fcac8e923fe0dbd1b11374ffbdb9a3bf7d7bb8fc41d7ed0028415b552125bd9e
- model-response-81c8047b-cd7d-4dfd-ab22-1839e41abdb3.json；ID：d426e0fc-74a7-4a73-9a1f-02f6814ec018；SHA-256：65de7447e467129bf508803fe5605a84cba07c9a0df8865e668b63f8ab3ee298
- model-response-81d531bb-d177-404b-af29-ad161637de6b.json；ID：8a28a4d6-a10e-48fa-8db6-2eb8b7dcbedf；SHA-256：13a58b867f8bb73efa3c1bee3309bf62b2d2920a34710b841f383497ae393a58
- model-response-8213010e-3ca3-40b2-9f45-427a5554c733.json；ID：0adde4d4-e318-4b94-8cff-984d6bbd6fc1；SHA-256：f28dec6a788584e692b2feea20899631e098b9982e9fcdf391de859cf736b809
- model-response-864fd2bf-dc7b-4c6e-a4a2-6d69541e57c9.json；ID：5f9696e1-9e6a-4413-b25c-c26ad1cea336；SHA-256：2febd20dd66d0939a7dd9d93b7ff2e62a2080e5fd456c76e1efae14de13f54bf
- model-response-86bbc78b-55b6-41b6-a43f-bfd887cdc1c2.json；ID：8fe9dfa6-9de7-4a8e-85f7-f72e02eb5959；SHA-256：a8251865e0e8d36552ccbf4c451bdb3ca96afab8db881cc7101cdc8a813215a7
- model-response-8941404e-e71b-4195-8796-199cc108e513.json；ID：a6c41bcb-73db-4f69-af18-a1c57e342885；SHA-256：20a9948cef70b9151e8eb5ec0412bd473738d6c9858964e4abfece7676079b30
- model-response-8a7a45a2-6a7b-4bbf-884a-fbab572481c4.json；ID：0b22c7ef-04ee-4f84-b918-3553319f0b2d；SHA-256：b0b15c2a5d65531fd90ce265ab5d01019f2434f28c3e2bb1329b8152cb5e980c
- model-response-8a89f578-c2cd-4100-b489-9073d845a296.json；ID：c0c66a7e-1b91-4063-a983-f010292ccb93；SHA-256：841f7fcee25bfcc7ef94be39072385c18b6840b786eb59c599a681b1d194b3a8
- model-response-8e917c6e-3a76-4b40-906b-b2baa24b32ed.json；ID：c474b1c3-550e-4b17-b95e-0bc4b6d200e5；SHA-256：5d80d014720cb696e348ad7eca436f078059f5e895999a45f18143dc154cdc57
- model-response-9132affb-7add-4a0c-8145-e0076d6fae50.json；ID：67c6a731-ee8c-4a37-aab0-a6503900a286；SHA-256：07404878dcc92298a6f008e280b4be1b73c5cd9d1dfcafe1f7779365e4d28689
- model-response-92c98fb3-8e3d-4a9a-9adc-c6b2303403e5.json；ID：b94e1e61-3d3e-44a1-9361-21e27f27f4b1；SHA-256：abaf8a8365a5f178305467996cbc9be9d3b75bbadac55825a72315fdd7d49fd9
- model-response-9456e7da-02c3-42eb-bc19-57bb6e8896bd.json；ID：877eedd4-e6fd-4851-b6fc-a797936e35e7；SHA-256：5f303267e3c47142f6c2284da22410e79234a7b86e998178c72f0406a147d6b2
- model-response-94a39b47-2a37-464f-8b7e-7c50d234ab58.json；ID：381cbdc8-676b-4f7b-83f9-68a86614844d；SHA-256：522ffbfb85165c4ca74660ddbd237590944c292e9973bb1ea02ceb095facf64f
- model-response-9527a5ae-5261-4387-baec-3ad354fe44d6.json；ID：40154417-fe7f-4490-9a1f-793f344453ce；SHA-256：7e15b3ec9da1443d31518cd42d3573ec35c434c708358051c61fd82470081691
- model-response-973daf26-9fe0-48d0-8a20-31b0fc97e714.json；ID：cedea65c-ed9c-455b-86ce-8eaa25f0cd02；SHA-256：e05d4e9aceea136ba0ab95454b7a0cefd643ef9b3219c43dae511de5b09fb5a0
- model-response-97ae9c89-3b85-4299-a6a1-5ceb4fff6407.json；ID：9b30f4e2-7a7e-4575-90d8-ab1c18573357；SHA-256：f71fd63e4d7cf81fe0e1c6cd43a6c7f1f1c246a2358ac05de3574110f87cedef
- model-response-98152ad0-cd23-4ac2-8d9d-0b4ebbfa96ed.json；ID：9ced61f7-18c6-457c-909f-8c8bc50cd967；SHA-256：d53b85929d01893eb6d17d8fa4d06c559a6b6d698efb26cc0ef7f2a5e1de31a8
- model-response-9824f6b3-e0a3-4ba3-89f5-557a5c8effde.json；ID：0c7127a6-e448-4ac8-9b1e-85336102b9b1；SHA-256：afdfc479ad13d427f0d2c2513c10057701d2de74a3d2890c66bc625dd25729dd
- model-response-9c7fc4a5-5b3d-4e74-91c8-41fe2672aa82.json；ID：7a499bbe-e79e-406e-a231-554649c0d61a；SHA-256：2e4b22beb06d9d84a7e8916a765578c891528f3c696bc6da221d98652fd44804
- model-response-a413a280-9301-47a9-96b3-c03ba807c89c.json；ID：f0755c17-28cc-4a7c-9f90-fc41b74c1e00；SHA-256：1f73409f764df85b5794afd697aaaff9b008ceaace6d5441b5988990343ee655
- model-response-a47bc8bc-9dc5-4581-a403-66c592ccb8e6.json；ID：2b3b4f22-b6c9-4057-bfed-2f5b6385904d；SHA-256：c93361d5ab201d4a06ea7682b19961347d7847bcd3298ef2d1aef3d79e8d62c8
- model-response-a48cd533-614b-490c-9626-f2fd5ce4a37f.json；ID：22c1f148-4bae-4d2b-b418-c9659b388589；SHA-256：56855bf10327031c8ae96cd91e58dae312f130251bea52fb9345de672a3be345
- model-response-a54e391c-560d-4c02-b092-9267b7aa4f36.json；ID：10966edd-73aa-49bb-8e99-5b5fab0db4c5；SHA-256：2e9f4221f1bcf0998cb481e7c302220d7f5b6f161ac517f8835257b1b967de24
- model-response-a58d6b16-c53f-4940-8e1c-d53ec4dedfc6.json；ID：0311909e-284d-4b01-b629-7e58e9cb3662；SHA-256：96645809327ac01650488923416fe28a19fc01426f3daa563c012658723e5d1f
- model-response-aaa96775-5b5e-498c-b323-2e700901330b.json；ID：2d725d3d-a932-4053-8192-2ee79fc82c3f；SHA-256：09c710220c1e87eb3481f7ac662746d4994b6d35bc913d43956846dbdf443f63
- model-response-ac2add99-9d8b-4ada-9a9a-ed4e0e693dd6.json；ID：16aeb1da-83fc-46f2-b27d-9cc260811bcb；SHA-256：3153a4423245b9eb9615c809f373302ffba0c5328bce31dcb8875b73ef41ed43
- model-response-aca39394-30e9-4d32-a600-d2d6f7422b74.json；ID：6b4a0cec-e827-4a94-b14a-5a006a7f2716；SHA-256：35eef6b6ec1622ebb8ad5adf7fd85cb130d328dfd9d04d35872b2f945c40d658
- model-response-ade1a524-5bda-498a-861d-0a250827c81d.json；ID：222a7faa-9816-40ce-9bfe-aff817dd71d1；SHA-256：166258d7369e035e4f01de8739bebe3653ee2ae99cae6f6a411d54a77920ffb9
- model-response-ae479370-4f86-43d3-85b4-4221a67df548.json；ID：fb7571aa-c296-4cce-a179-d992d3a1b280；SHA-256：3f743b745683f876fcb68fcdc96fdaab686d9f7499cea0bda92590f452020f40
- model-response-ae88e30d-a55e-42e5-831e-110ff232b887.json；ID：2e47c806-9a63-42bd-b564-75252977fa4e；SHA-256：2761bf650bce14b49f818fd91f0d5d3860f3feaedfd4410b937e4a99446c8c76
- model-response-b0ca9020-7beb-4bde-9de5-c374dbf2802b.json；ID：a751c69e-44cc-4ffd-9c2f-490023e61009；SHA-256：68c04ad2635030a99cfe32cff9340b152c049ebd42e8faace4816ee8402d6966
- model-response-b1509673-620b-4267-81a7-920b30b75dbf.json；ID：0a007c27-987d-478c-8ee1-9e3b14ef5787；SHA-256：1ac2c38bac9260d8ec9ee6d5d4846a21a98596e6a6c863cea471dbb6f2dd124a
- model-response-b3e5cfdf-4427-4fe1-ad4c-2ca244f575f9.json；ID：2de5d5d4-2065-4fc2-8dba-8dc6bbc0560a；SHA-256：a2c4f5375823c21ebdcabf3c56cb3c50385981c070772178db3471b7e653d226
- model-response-b54bb394-7d15-4453-bc75-dd9c82262c78.json；ID：b18eff88-d743-476f-8d52-d65e61ba1060；SHA-256：90148cf23e88d49a029c7a41cea4c0da3e662f3b9f90cb225ad23b91fb42647c
- model-response-b73bc998-d2a6-49fa-8d5c-d4bc91fd3859.json；ID：e41b5666-0f81-4e55-89bd-d39e196601cc；SHA-256：104d86a00859ebf12248ee9f9e6d30d2746e715bbdd38bccf497b26b5f5ffb0b
- model-response-b8728279-f4ad-4e5e-83fb-e192d85c33df.json；ID：576f33dd-3bf2-448d-8355-cca8a2dbbc3f；SHA-256：66bba1447dd192b89eae28ade1f2d830458db14d9f52bf7ce2e7e6c7a0a66a9b
- model-response-b92d2e1b-329d-421b-a1e6-125da943dd65.json；ID：c120064c-3a93-492c-b060-b69c51310524；SHA-256：771bb4ad297fc1a0e07ac450f28f57b3744099aa9fb60b379cdfc4adce24dcfe
- model-response-b9666fce-25cc-49b1-b879-ddbed4e89174.json；ID：f9dc889a-c3be-408a-88b5-4c0c282b08ca；SHA-256：81f83d807e9a224f8a429bb1e9bcb035488a045271ec14a7cc7d0b11287da56c
- model-response-b9df1f04-6065-426a-9091-feae438d09e6.json；ID：4512af11-1df2-4f99-be01-3900488fb143；SHA-256：a651a290a64d546ddee69d3da01b82af4fec18304e168aeb7cbf47bd310c0ace
- model-response-baa5f38f-446a-4076-a504-24b9554c8879.json；ID：19936dd0-8bf8-409d-9e67-f4b46a42b831；SHA-256：2759cd9eac07e65fd7a4448d4ed5a8aadae6c62be760b1add1d2d7c17eeadfa9
- model-response-bb39cc38-32f1-47c8-b2fa-92fe7591093d.json；ID：770fb7aa-15d5-49f7-9703-cf6942dd25ba；SHA-256：fdbd4bbe2bba48a01c639c0c22925932d8eec05ae1381309e853157c31af0a1c
- model-response-bd0023b5-cdc7-4035-8eca-cd4bf85b0c1d.json；ID：0c765eb8-394f-440d-b2eb-9731ba2ac98f；SHA-256：387bff7c53b399aa70c0ac8e62979a4743c4f75b18715f71050d6a3541b7f547
- model-response-bd36afe9-3d57-4fcd-a6b6-f4ee457fda2f.json；ID：56ad6d25-d4b4-4414-91a1-28eb5d2e96c7；SHA-256：f6bd65cf434b52b683868d2ce644a93adc1319234dc5f2b747ec41c23637ed67
- model-response-bd90b865-8850-481e-9c26-1e370a3331c2.json；ID：eaa144a3-5833-4f50-8bbe-5b5ab68d1808；SHA-256：a9593dbeea486e087ce1e067808efaf20ca1ba9afd554bdd03e67ee61de927ed
- model-response-bde14cf0-c624-4c50-acee-ffdef630f87f.json；ID：ab1caced-4c54-4f3c-9398-ec17ec997216；SHA-256：92e1a96956cb71e28219cdc7b07b339cc534a99dad6ecfafc0e74eef11078948
- model-response-be26db32-132b-4220-bc49-a8b37e28e5b5.json；ID：f3419d36-d10f-4dac-adc0-7990c74f1695；SHA-256：8674a1c51b9283c9df3da5e151397fab1cd02d9be16684f0664f55ff9da88dec
- model-response-be5a983d-1e0b-4ee9-9dc2-a670f88a55dc.json；ID：fb8f3622-6f4a-4c1d-826b-83a570183d42；SHA-256：abc3f8465149fca31883948a746c1b4bbbc19e4b550b5062ba5c392178b277c5
- model-response-be80335e-0f4e-4ab9-84e8-602db9d066c1.json；ID：b9de8b86-f29d-4df6-b0f2-66243728ca7e；SHA-256：13df4d18cba3c6a827746c2e60d7a6aed8150bf6f3aaa681b0662d5bfd9482bf
- model-response-bee917f4-ea6a-460b-836e-e39165acbaf6.json；ID：a0bc056c-4fc3-4a54-aa19-4614c54e447e；SHA-256：d45d6d85109b39f9953882aae73fabf6d36857f8c3471376ab1100df583dd2d3
- model-response-bf94b687-825e-417d-9b87-5eb2339afe3d.json；ID：145ddd93-8638-4941-96bf-62e2e9755631；SHA-256：d3ec136aae788af96d57ea8b58d728c2d8dd7ba3ba7547bc7588765c50c59f5c
- model-response-c04d4f71-ff81-4aee-a9a9-07e91731910c.json；ID：f41a16cb-cf13-4548-a917-ffcb581f4431；SHA-256：c177980f598fd40fd6ada7a810752717ebecb5268cb963685d27fce5ff434569
- model-response-c27b3fca-ebae-4aa1-8f11-0043186fdd11.json；ID：51eafd5d-f0f7-4715-b17e-2917c4363241；SHA-256：d5f2e50edce2e1982d4557d98499ae00a99ad57325dc4b6d8c0dd6b5da62afcd
- model-response-c2a2fc51-37e4-4ef1-b492-19282f865b97.json；ID：d18c657c-ed65-4a7a-87a2-3a2736dd8af5；SHA-256：1d2cea84c3dd7249782b60000f65d9800777042aa65437fd57abc79d909abd43
- model-response-c2f4df6f-b9b2-499e-b5e4-c4688e03342e.json；ID：974cc8cb-9a1c-49ae-b3c3-787cda1b2887；SHA-256：a11dd4f79d45649ee2a7e99dd122e9f8aedbb8d3172fa320d5d98ba93d7cd56f
- model-response-c4ada406-4162-431d-a5b9-01f334ba66c7.json；ID：cedc732b-7e6d-4c83-8b98-83c4b578aa09；SHA-256：e60b844012d79c8ad3ced928fecfd846cd90587458e750e8601816db716cf74f
- model-response-c4fee184-fa02-455e-82f4-1cee9d8c1529.json；ID：e4169665-26ff-4b99-a9c3-0a03d18c9c6e；SHA-256：dce6e4cc1a04434d7edd765672d95df7d5becf1053150281e300ffb84237c90f
- model-response-c539d1cc-36d0-4392-b6b6-b14d76f45214.json；ID：0b9f032b-3ac9-409e-80e3-674c9a30e66a；SHA-256：f36c16bad7aa590784644f48315e574463a1f5b1a1ea9feec13aaa2aa9269449
- model-response-c8451307-639e-450b-b5a4-6cffbd4697f2.json；ID：8c66f12d-944a-4259-bc05-15a439240e79；SHA-256：551de096cf380bc6d74aed4a36f1a926c2c8c7340bdfa63d46c601c2e871f52e
- model-response-c8d6bc12-7c67-45d4-b021-617891fb4a2b.json；ID：fcd1f8f9-30bc-4bb8-91de-217a7c155293；SHA-256：a5a3d48bf580be37ce11e33ec8c33b4d205f70fac222903cc4ec85b0bf4995ec
- model-response-c98990e3-e4ff-48b7-a252-8335ca3bfc73.json；ID：75e9b91c-27fb-4df8-baaa-2ee5e038f985；SHA-256：7b6f685cb50b3ad1ce6150b02707ee4cc780f0ea0cfb6e40871b6dce4e12aff5
- model-response-cac6d217-fa64-4f8f-824b-463c784aea2c.json；ID：042a881b-a421-4506-83fd-14f1656906b2；SHA-256：45007374e7ac43db5d9895a8c95239302fcebb5f6bfec2276e12d49b5901fa30
- model-response-cbb8334e-7dbf-4e10-b957-77234cc370e2.json；ID：bee91101-2f79-4648-aaed-633db2afdbda；SHA-256：c355b6c8e87648e119170505885bd6b8e675db15ecd41760e541fe36c2ee7095
- model-response-cbc8ea02-10a9-4153-93f3-6b410f98055e.json；ID：4c95af76-89c1-428e-93ff-e0fbbe709cb7；SHA-256：73195347d8e86c387576baafec6900e7815b0f2201187f50ba87dc0dc9ec6701
- model-response-ce46a9c1-48fd-49b9-bc3a-8c58db70e6c5.json；ID：5469d944-c370-4ac7-8084-e53c070afbbb；SHA-256：9340b9a15e63b6718b5a113bef61095fc3a94046ef48a36209fd69153c2547c9
- model-response-cea0a592-2e7b-4be5-8584-e15576462121.json；ID：7e365dae-140f-437f-9a71-b1b2ff8b4115；SHA-256：2fb7ab7deea2ebb5d5e0a51bcf85067227091d7a06d47bdbd57aea631086b731
- model-response-cfff641f-ae7a-42fb-8aa3-04cc30ffd68a.json；ID：84aec8bd-d331-4fdf-8a5a-0ef9aca016fd；SHA-256：1a56d6383ad7896141693b6213afab3b84c3deefa31b3d1a7d80a38e80c62491
- model-response-d2220f59-5a59-45bb-ab99-adaa39807d2c.json；ID：ea65317e-6a56-44b0-8938-b7bdd452f01e；SHA-256：7c7a53c21059cf74c14614065351fac99464917641ddb8c59d40e1e214f6b3dc
- model-response-d23915b1-7245-42e8-b5a6-e7cf024734a2.json；ID：88b16b06-d39e-4eb4-9921-5417244fb808；SHA-256：95ed48ba97db2ef0b707432f2df699c24bac4f0ef739a43522a7faf2ae42278a
- model-response-d41fc84a-3fe5-4192-bb9e-3b47810513fa.json；ID：0fdf3806-383f-4430-9029-ab903debde3c；SHA-256：dd480ab4e4b06876ffe83045ed6bcda0f91ae1e68c13763d0b88cb343549ab27
- model-response-d6a46b73-bceb-4f5f-ae27-c0ef802e0a91.json；ID：7ea57ae6-181f-4504-b6b9-edfbb11f1629；SHA-256：7ad6fe51aed6398c7210383538fcd8086dce1b010e3d442bbae477ce1e9e1891
- model-response-d6e8a836-bc6e-4fe0-9837-7e43c41d67cf.json；ID：1ae375ab-f885-406b-8461-411e713a058f；SHA-256：6991400d12407569fbe44380898ec54ca7b34219e676d39d4a9919d3491c72c0
- model-response-d7615196-3cc2-4121-a6b9-e86a6f90c992.json；ID：b0d21bd5-36df-4ad9-95f1-1caa21756dbc；SHA-256：a8832b5ad4c0f92b70147b86f344db0d23d9fb2b911ffe21b7b240f8ddd477ff
- model-response-d924cae2-0960-40ea-8197-59e1775f758b.json；ID：f03ed4d6-607a-413a-aeee-c14a0e0ad5c6；SHA-256：82d0b167ba0c3f0f0746657924f5fd702b7cef8b152b012ff25aa099b7ba69e5
- model-response-dae1b8ac-8ddc-49f0-9eac-4101ced32e23.json；ID：3a957fec-9561-4759-b8f0-604102cbe0ea；SHA-256：05f1fd4b8ffea9f714570982da0e0f017d2c7086b9827dff4dbfb5f5c87035db
- model-response-de5f30db-cb67-4842-9a4f-e722301d18b8.json；ID：c6d18d0f-7c02-4a6d-b162-8fe9451ad63c；SHA-256：fff28c9b45da14b51ab6b19e53034003730cacbeb332035a98c4ade58f34d7b1
- model-response-dedd0805-e7f2-4ea1-b7d4-c5c8858be406.json；ID：5a330231-abd2-474f-ae10-b3cca5d0439f；SHA-256：c8c1ef5ed3eb6a2823cd403b6a2dd06634f1723cd4a2e1b393f9cf13ec0904ed
- model-response-df00c41a-f7b9-4f7c-87dc-94921137eb6b.json；ID：74734ff5-d3fc-48d2-82c7-d734179a856f；SHA-256：8d6ae5b192184b4351629f37cc2cdfa1352b20950ef35d90cc93f4f27f01bf8f
- model-response-e10c9078-4a2a-4882-b537-8fd8ea417905.json；ID：d46fbc5f-c8d9-4f02-9dd9-c514395b8cad；SHA-256：2c2fff04beed32585a47a7fb721b3f8e5ea588b6dd1a4eac68567b9db55c190b
- model-response-e123789a-af7e-4480-a986-937b846c4c81.json；ID：5a2a05c8-9d5a-4a80-ae67-63058e42db62；SHA-256：adcbd0d51d1958ecc0010ed569e5a5ed7597663fecf1e166c6b94936381b15f7
- model-response-e3147fca-c26d-4995-a7a8-ca63761154b1.json；ID：246416ba-5991-4690-b95d-b81da2af1458；SHA-256：197ac0d70b6a156179b79ebc96d443e7cd08e33e9b82d8b37a4495e263135850
- model-response-e32ffc87-f016-4abe-b58f-4568e9175faa.json；ID：55d9ccf3-36c6-409a-b10f-71d3f0292f61；SHA-256：00d61c477204c9b49fa776b831e303a97e1458c1345666543bed241a39445ea2
- model-response-e46c46d5-1525-4b45-a348-f4addd4b26ac.json；ID：064b10b6-852c-423e-b6cf-25eb160ffd3f；SHA-256：33f62f8dc0f9193fcef0aa12ab8034650eab5f59f8746e166be386ecc4347539
- model-response-e5ad31ba-69d1-4e4d-872b-3f6091ad3798.json；ID：ded11ca6-f618-4e74-a00d-028a07486a0d；SHA-256：7665e1555d2d8862d9a1ea47e8fcd6664d5f0a981b09c9a581dbbf63e448b1b7
- model-response-e66ee2d8-a3d4-4a02-92df-0cac7436b58f.json；ID：d505c16c-68d3-4a12-a553-4ef85ccf04b4；SHA-256：a95d53e5679cb934ad7415dbf4cb0d25595526eb8902d1d483a928ece812ccb6
- model-response-e937d564-c6b2-4d4a-81a7-36218597df84.json；ID：123f2eee-3d4e-4c58-936d-e4e39c62d1d7；SHA-256：a5375841b10d4284e668b2fc1b569df42af3e2a7a275beb8226899f0ef4b685b
- model-response-eb88c9d4-4751-4f35-8011-13b98e50479a.json；ID：5cbb175e-6e86-4abb-b343-1e98570495ef；SHA-256：c7adfc9d9d166c3210d5fc12eaee15ac72c54dcf156c4bf46ec7461ccd4f5a0c
- model-response-ede1d90b-bb0e-4037-a702-f3b99891e99f.json；ID：e0fd6dce-980e-46c9-9d24-3f2e53726c5d；SHA-256：0c67d0b8d0075da5517d51f45140b075338b00ddd6f6b6a39adf08a3292d2c9e
- model-response-f1537aa8-3bde-439c-b6b8-cbf411865a31.json；ID：23d49667-5b27-48ef-98a3-a3a0ef566328；SHA-256：a2c4374381fd5e0f447e599976131c165f8a1aaade5d2f4a899db81368c05806
- model-response-f1c091ca-5e1f-4be8-ac9d-8f430329ebba.json；ID：598a88b0-9b9b-4f1f-acd0-6cc5fc6d124b；SHA-256：25fb74b9676abd1764eccc2acd89e64a63e4fa3505150b8cdb81b3c0e7f4051a
- model-response-f28ee5e2-1236-4e63-a6c5-2ad650b10f7a.json；ID：0b0248fc-08ae-44ff-8bb8-b76096879674；SHA-256：46d78669290e8e566336ffd84c1a596c590ac0b74177b6dcc927872247c18e89
- model-response-f36e19f2-6409-4d0c-98ad-1d022243b1a0.json；ID：a2615426-f410-4ddd-a8dc-879ce07e6892；SHA-256：167f411e0c84dcbd32da23cfbd94146dfcbab8a78c45b188394baef3168d17e7
- model-response-f4119d1c-1ad5-415e-b346-46fd01cd9118.json；ID：2243811b-7d90-40f6-ae3c-a78e52c2df55；SHA-256：d91288db3563c8ac25e2b85aa572d823f9f33c15e0a12e0a41690d5381800579
- model-response-f4413ff7-afe5-48fa-80c5-ef2a1bd6daa8.json；ID：935a55bf-b45c-492d-9f03-6235e3953b66；SHA-256：e4647d741e5168adbf7924cbedb13e9f1f328ce15212fc24ec5cd77caedb3829
- model-response-f5f0ebc3-b52c-4f14-a126-59665b91c401.json；ID：ebce69ec-b035-4ec9-8988-7bf733758c49；SHA-256：429fa853050c827b241aa284bf2b28c05f306631e4214f3be930f07685194ecf
- model-response-f642e63a-7613-43ea-a9c2-64f9ba167f8f.json；ID：aad952c1-c749-44e0-b627-6f5b149877a8；SHA-256：9aac2691da4146393f7f21a08bb30b25631833b4d0531e6e51faa9409e90dc34
- model-response-f6efb9ef-7af3-4429-a647-18e0fa2e4e07.json；ID：1db672e8-1b66-4197-9067-09e0934f91b1；SHA-256：9f7b9830ee92d0bd7e49aa26ef94137bd37740615326d3a9f298d277aa1ff73a
- model-response-f7a9a0a0-7bd4-468c-b0a6-ae1e13b611f2.json；ID：c67ee30d-5bbf-4ddc-988c-6b676fd1bb13；SHA-256：7c06fbb19e618c1b0743f0bb0c82abb616dc4f792372b95f0327f0d656416c49
- model-response-f7df37a8-6cd9-4dd4-b712-7c3cb80529f0.json；ID：d1e05c76-e7f0-4fcf-b323-66c2b4f20ec9；SHA-256：d56cf4d87089adfcd41e3ef3667f98346894b78b9c41fa0d8a701865b31e6039
- model-response-f8b60f39-d08e-49b8-b86b-cc5d452acf99.json；ID：4105d951-8428-4f33-bbde-654ce6816cdb；SHA-256：4cdee6a7974ed66c72530639ea1d7184f69f4e71ccde883d3ffc5d9576135f18
- model-response-fa29f28d-bd36-4615-ac5a-9230dcacf426.json；ID：646b3e28-5046-4adb-9b76-5879be0be58d；SHA-256：196cc671110bde8bdbfa98668fc58d2deca3418bd729f38681d473bfd9d31356
- model-response-fd953510-2874-45db-b22b-3d94125eacd6.json；ID：2366e6a3-e3d4-4a29-906b-25b78b9f6896；SHA-256：deea3917be2a42a781daeb1f78dee9768b68174636533b9faf8cb587f5348d75
- model-response-ff907cee-ed19-41b8-b620-8a23ab914b42.json；ID：145a316e-e8a7-498b-8fe0-525ce2486ede；SHA-256：a74a485a429fb50f6ff1c396cd221e6ff9b07bf729fc42601b9756947699bbc7
- model-response-fff3b9f8-b6e4-435d-b783-5f9c35070643.json；ID：85606028-ec7e-4b28-a684-b7f32e075e22；SHA-256：0697154ee1014076842b28e99cc8915ae9a8798a53e4bfc52b1f2df137b640ac
- p01-llama-jinja-vuln.zip；ID：3980f52d-2b76-4cac-9c5d-aa5e3bc6f204；SHA-256：b4d55828cb45908fd45d525c60d6de050a0b4bc93e818470754276299822eebb
- snapshot-manifest.json；ID：e6921fc7-abb8-474f-8d1a-41de12207dc3；SHA-256：24da6383cb8374e4974d7de9116375e12deb172079a14d868fabb0fc734d62d9
- source-snapshot.zip；ID：ed6c1b78-141d-41a0-aa81-16a99ee3d248；SHA-256：66e9a1994d0a499a9a720f586164336873495e65558bfb05ed6a1bae62145d43
