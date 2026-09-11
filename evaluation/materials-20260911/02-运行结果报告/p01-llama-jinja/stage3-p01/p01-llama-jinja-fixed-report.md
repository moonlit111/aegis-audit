# AegisAudit 分析报告

项目：对照池评测 20260911-093526

任务：3b149981-84e0-4a33-a96e-233167df8aa9

状态：Partial

目标 SHA-256：b2b6a5bc5067d4bba323c7533ea38f132b5f2ee6529ebff458f8961e43b9f53e

结果快照 · 数据截至 2026-09-11T09:52:41.741Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：PARTIAL；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L54–L95 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L201–L235 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L171–L176 | PARSED |
| \_\_call\_\_ | llama\_cpp/llama\_chat\_format.py | L2559–L2740 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama\_chat\_format.py | L2518–L2554 | PARSED |
| \_\_init\_\_ | llama\_cpp/llama\_chat\_format.py | L180–L199 | PARSED |
| \_convert\_completion\_to\_chat | llama\_cpp/llama\_chat\_format.py | L308–L322 | PARSED |
| \_convert\_completion\_to\_chat\_function | llama\_cpp/llama\_chat\_format.py | L325–L499 | PARSED |
| \_convert\_text\_completion\_chunks\_to\_chat | llama\_cpp/llama\_chat\_format.py | L265–L305 | PARSED |
| \_convert\_text\_completion\_to\_chat | llama\_cpp/llama\_chat\_format.py | L241–L262 | PARSED |
| \_format\_add\_colon\_single | llama\_cpp/llama\_chat\_format.py | L790–L800 | PARSED |
| \_format\_add\_colon\_space\_single | llama\_cpp/llama\_chat\_format.py | L830–L840 | PARSED |
| \_format\_add\_colon\_two | llama\_cpp/llama\_chat\_format.py | L803–L814 | PARSED |
| \_format\_chatglm3 | llama\_cpp/llama\_chat\_format.py | L856–L868 | PARSED |
| \_format\_chatml | llama\_cpp/llama\_chat\_format.py | L843–L853 | PARSED |
| \_format\_llama2 | llama\_cpp/llama\_chat\_format.py | L773–L787 | PARSED |
| \_format\_no\_colon\_single | llama\_cpp/llama\_chat\_format.py | L817–L827 | PARSED |
| \_get\_system\_message | llama\_cpp/llama\_chat\_format.py | L747–L754 | PARSED |
| \_grammar\_for\_json | llama\_cpp/llama\_chat\_format.py | L870–L871 | PARSED |
| \_grammar\_for\_json\_schema | llama\_cpp/llama\_chat\_format.py | L873–L884 | PARSED |
| \_grammar\_for\_response\_format | llama\_cpp/llama\_chat\_format.py | L886–L898 | PARSED |
| \_load\_image | llama\_cpp/llama\_chat\_format.py | L2743–L2755 | PARSED |
| \_map\_roles | llama\_cpp/llama\_chat\_format.py | L757–L770 | PARSED |
| \_stream\_response\_to\_function\_stream | llama\_cpp/llama\_chat\_format.py | L374–L497 | PARSED |
| chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L506–L635 | PARSED |
| chat\_formatter\_to\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L503–L637 | PARSED |
| chatml\_function\_calling | llama\_cpp/llama\_chat\_format.py | L3162–L3582 | PARSED |
| clip\_free | llama\_cpp/llama\_chat\_format.py | L2542–L2544 | PARSED |
| create\_completion | llama\_cpp/llama\_chat\_format.py | L1972–L1995 | PARSED |
| decorator | llama\_cpp/llama\_chat\_format.py | L904–L909 | PARSED |
| decorator | llama\_cpp/llama\_chat\_format.py | L142–L144 | PARSED |
| embed\_image\_bytes | llama\_cpp/llama\_chat\_format.py | L2617–L2636 | PARSED |
| find\_first | llama\_cpp/llama\_chat\_format.py | L2778–L2783 | PARSED |
| format | llama\_cpp/llama\_chat\_format.py | L983–L995 | PARSED |
| format\_alpaca | llama\_cpp/llama\_chat\_format.py | L952–L962 | PARSED |
| format\_autotokenizer | llama\_cpp/llama\_chat\_format.py | L650–L658 | PARSED |
| format\_baichuan | llama\_cpp/llama\_chat\_format.py | L1031–L1043 | PARSED |
| format\_baichuan2 | llama\_cpp/llama\_chat\_format.py | L1015–L1027 | PARSED |
| format\_chatglm3 | llama\_cpp/llama\_chat\_format.py | L1253–L1266 | PARSED |
| format\_chatml | llama\_cpp/llama\_chat\_format.py | L1211–L1224 | PARSED |
| format\_gemma | llama\_cpp/llama\_chat\_format.py | L1312–L1326 | PARSED |
| format\_intel | llama\_cpp/llama\_chat\_format.py | L1121–L1131 | PARSED |
| format\_llama2 | llama\_cpp/llama\_chat\_format.py | L917–L928 | PARSED |
| format\_llama3 | llama\_cpp/llama\_chat\_format.py | L934–L948 | PARSED |
| format\_mistral\_instruct | llama\_cpp/llama\_chat\_format.py | L1228–L1249 | PARSED |
| format\_mistrallite | llama\_cpp/llama\_chat\_format.py | L1162–L1174 | PARSED |
| format\_oasst\_llama | llama\_cpp/llama\_chat\_format.py | L999–L1011 | PARSED |
| format\_open\_orca | llama\_cpp/llama\_chat\_format.py | L1135–L1158 | PARSED |
| format\_openbuddy | llama\_cpp/llama\_chat\_format.py | L1047–L1065 | PARSED |
| format\_openchat | llama\_cpp/llama\_chat\_format.py | L1270–L1284 | PARSED |
| format\_phind | llama\_cpp/llama\_chat\_format.py | L1107–L1117 | PARSED |
| format\_pygmalion | llama\_cpp/llama\_chat\_format.py | L1195–L1207 | PARSED |
| format\_qwen | llama\_cpp/llama\_chat\_format.py | L966–L979 | PARSED |
| format\_redpajama\_incite | llama\_cpp/llama\_chat\_format.py | L1069–L1081 | PARSED |
| format\_saiga | llama\_cpp/llama\_chat\_format.py | L1290–L1306 | PARSED |
| format\_snoozy | llama\_cpp/llama\_chat\_format.py | L1085–L1103 | PARSED |
| format\_tokenizer\_config | llama\_cpp/llama\_chat\_format.py | L693–L711 | PARSED |
| format\_zephyr | llama\_cpp/llama\_chat\_format.py | L1178–L1191 | PARSED |
| from\_pretrained | llama\_cpp/llama\_chat\_format.py | L2801–L2881 | PARSED |
| functionary\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L1333–L1687 | PARSED |
| functionary\_v1\_v2\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L1692–L2474 | PARSED |
| generate\_schema\_from\_functions | llama\_cpp/llama\_chat\_format.py | L1793–L1825 | PARSED |
| generate\_schema\_from\_functions | llama\_cpp/llama\_chat\_format.py | L1413–L1445 | PARSED |
| generate\_shared\_definitions | llama\_cpp/llama\_chat\_format.py | L1396–L1411 | PARSED |
| generate\_shared\_definitions | llama\_cpp/llama\_chat\_format.py | L1776–L1791 | PARSED |
| generate\_streaming | llama\_cpp/llama\_chat\_format.py | L2001–L2303 | PARSED |
| generate\_type\_definition | llama\_cpp/llama\_chat\_format.py | L1363–L1394 | PARSED |
| generate\_type\_definition | llama\_cpp/llama\_chat\_format.py | L1743–L1774 | PARSED |
| get\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L135–L138 | PARSED |
| get\_chat\_completion\_handler\_by\_name | llama\_cpp/llama\_chat\_format.py | L123–L132 | PARSED |
| get\_grammar | llama\_cpp/llama\_chat\_format.py | L1939–L1970 | PARSED |
| get\_image\_urls | llama\_cpp/llama\_chat\_format.py | L2758–L2774 | PARSED |
| guess\_chat\_format\_from\_gguf\_metadata | llama\_cpp/llama\_chat\_format.py | L726–L740 | PARSED |
| hf\_autotokenizer\_to\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L663–L667 | PARSED |
| hf\_autotokenizer\_to\_chat\_formatter | llama\_cpp/llama\_chat\_format.py | L640–L660 | PARSED |
| hf\_tokenizer\_config\_to\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L716–L723 | PARSED |
| hf\_tokenizer\_config\_to\_chat\_formatter | llama\_cpp/llama\_chat\_format.py | L670–L713 | PARSED |
| last\_image\_embed\_free | llama\_cpp/llama\_chat\_format.py | L2548–L2552 | PARSED |
| llama\_cpp/llama\_chat\_format.py | llama\_cpp/llama\_chat\_format.py | L1–L3582 | PARSED |
| load\_image | llama\_cpp/llama\_chat\_format.py | L2556–L2557 | PARSED |
| message\_to\_str | llama\_cpp/llama\_chat\_format.py | L1497–L1530 | PARSED |
| prepare\_messages\_for\_inference | llama\_cpp/llama\_chat\_format.py | L1447–L1532 | PARSED |
| prepare\_messages\_for\_inference | llama\_cpp/llama\_chat\_format.py | L1827–L1888 | PARSED |
| raise\_exception | llama\_cpp/llama\_chat\_format.py | L211–L212 | PARSED |
| register\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L141–L146 | PARSED |
| register\_chat\_completion\_handler | llama\_cpp/llama\_chat\_format.py | L105–L115 | PARSED |
| register\_chat\_format | llama\_cpp/llama\_chat\_format.py | L903–L911 | PARSED |
| split\_text\_on\_image\_urls | llama\_cpp/llama\_chat\_format.py | L2777–L2798 | PARSED |
| stop\_on\_last\_token | llama\_cpp/llama\_chat\_format.py | L228–L232 | PARSED |
| to\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L237–L238 | PARSED |
| unregister\_chat\_handler | llama\_cpp/llama\_chat\_format.py | L117–L121 | PARSED |

## 审计策略与优先级

对 llama\_cpp/llama\_chat\_format.py 做结构驱动的静态审计优先级排序：先看外部输入（聊天消息、tool/function 定义、tokenizer\_config/chat\_template、图片 URL/路径、GGUF 元数据）如何穿过注册表、模板渲染、转换与流式返回等信任边界，再覆盖多模态加载与动态模板/分词器加载路径。键值候选（key\_logic\_candidates）只作为线索，最终需在原始行上做语义确认。

1. u\_1f6cc8fbdd7cbf730037718cf86b3ee3：\_load\_image 处在文件与路径边界：需核实图片 URL/路径/base64 的处理是否限制本地路径或远程获取（SSRF/路径穿越风险），以及失败回退行为。
2. u\_fb027aa6bfa58843309f0a457bff6bad：from\_pretrained 同时有执行/解释边界与文件路径线索：需核实是否加载外部 chat\_template/tokenizer 配置并执行，路径来源是否可信。
3. u\_226d76c1643795af0e204bbd8552fd88：embed\_image\_bytes 涉及内存或索引操作，需确认嵌入字节校验、越界与释放逻辑。
4. u\_e69c1f739dd2f320c24ff0a593919f97：多模态 \_\_call\_\_ 兼具执行/解释边界、身份边界与内存索引线索，是图片输入到模型的主入口，需核对输入校验与资源生命周期。
5. u\_f0c3813692aac57fe775d9c353e31d12：hf\_autotokenizer\_to\_chat\_formatter 有执行/解释边界线索：外部分词器自带 chat template 渲染属潜在注入/执行面，需核实来源与沙箱。
6. u\_de1f86ce5bb959451eb7b7c1208700e7：format\_autotokenizer 实际执行模板格式化，需查看是否把不可信消息直接注入模板并执行。
7. u\_4cc3b11d508d2ef79de645bf814150a7：hf\_tokenizer\_config\_to\_chat\_formatter 从外部配置构造格式化器，属信任边界，需核实配置来源与默认回退。
8. u\_2b143e370145dfd774eae23797e06324：format\_tokenizer\_config 具体渲染外部模板，需检查变量注入与异常处理。
9. u\_9f4742381dee75f33b5c6cb732ed3123：guess\_chat\_format\_from\_gguf\_metadata 依据元数据选择处理器，元数据不可信时可能改变行为，需核实映射与校验。
10. u\_f399d0d600b76fb56c87dca97dfafe38：chat\_completion\_handler 是聊天主处理闭包，连接外部请求与内部格式化/补全，需核对参数透传与边界。
11. u\_089521be6b9a589b21a7c8f051442cd1：chat\_formatter\_to\_chat\_completion\_handler 将格式化器适配为处理器，含身份边界线索，需核实注册与调用一致性。
12. u\_a150215dced58906ad615682156a9eab：模块级包含全局注册表与多个 Jinja 模板字符串（含 raise\_exception 用法），是模板/注册信任边界的汇点，需确认全局可变状态与模板来源。
13. u\_e003a1c95f3efac85e808d7aa47b1be3：register\_chat\_completion\_handler 可重名覆盖/抛错的注册逻辑，需核实是否允许不可信代码覆盖已注册处理器（identity/权限边界）。
14. u\_085ee8e397895c637f6e65bdeb0c5406：unregister\_chat\_handler 允许注销处理器，需确认调用方可信性与对运行时行为的影响。
15. u\_a3f3c6a22c818c9d5a01afc7323ec324：模块级 register\_chat\_completion\_handler 装饰器入口，属对外注册 API，需核实名称校验与覆盖策略。
16. u\_161a7cda5c0b56285690caed5bde3b7c：register\_chat\_format 注册新格式，属对外注册面，需核实是否可被外部输入影响。
17. u\_e791f1b38f0704233f7be9c9a48711f7：\_map\_roles 处理角色映射，属语义授权/信任边界：需核实是否严格限制角色集合，避免角色混淆绕过。
18. u\_8a0c7bcc58f259dc0504c5a5665d2528：\_get\_system\_message 决定系统消息取舍与优先级，是提示注入语义边界，需核对与用户消息的合并顺序。
19. u\_831fafb95885f315c2b6562bb09f7f92：\_grammar\_for\_json 构造语法，若拼接受外部 schema 可能影响生成约束，需核实转义。
20. u\_993ee8ae8c00b3c4f249b8c313d54858：\_grammar\_for\_json\_schema 由外部 JSON schema 生成语法，需核实 schema 校验与注入面。
21. u\_827e582a779807aaddd9c1fb510d9c15：\_grammar\_for\_response\_format 依据响应格式选择语法，需核实不可信格式字段的处理。
22. u\_5225013ed9c1a0c02b47dcb1a97a4195：\_convert\_completion\_to\_chat\_function 解析模型输出中的函数调用，需核实 JSON 解析与异常路径。
23. u\_0a2299c23ba7bc81a130879c17886818：\_stream\_response\_to\_function\_stream 在流式输出中增量解析函数调用，边界切分易出错，需核实状态机与缓冲。
24. u\_b6adae9bded102de9bf8f862169e056c：\_convert\_text\_completion\_to\_chat 转换补全结果为聊天响应，需核实字段映射是否被外部输入影响。
25. u\_8c00bf2715433a4c59b81a51e5425e6a：\_convert\_completion\_to\_chat 分派转换逻辑，含流式/非流式分支，需核实分支一致性。
26. u\_95bb8e6e86c973a8971b28c6ea626ce7：functionary\_chat\_handler 有身份边界线索，处理带函数调用的聊天，涉及工具定义与消息构造，需核对授权与解析。
27. u\_ce6624efb5335c533dca04e382a8104b：functionary\_v1\_v2\_chat\_handler 同时有执行/解释、身份与内存索引线索，是最复杂的处理器，需重点核对内部解析与索引操作。
28. u\_022cdfb8013449e760654a49f011be15：chatml\_function\_calling 处理 function calling 输出解析，需核实工具调用参数解析与错误处理，避免把模型输出当可信指令。
29. u\_83e928ab6e910e74d74e51859b17fb63：generate\_streaming 含身份边界与内存索引线索，是流式生成主循环，需核对迭代终止、缓冲与停止条件。
30. u\_3b9f46479f6b3feb313876c53826e2b8：get\_grammar 汇总语法生成路径，需核实外部 response\_format/tools 输入到语法的完整链路。

规划限制：未配置 Semgrep（Windows 原生执行器缺失），仅有词法线索，需语义复核。

规划限制：构建与运行均未执行，无入口/依赖/输入接口声明，无法验证真实调用路径与部署形态。

规划限制：调用图不完整（call\_graph\_complete=false），候选中的 INFERRED/UNKNOWN 边与动态分发（注册表按名查表）仍是显式缺口。

规划限制：无人工标注，全部结论需在原始行上独立验证。

规划限制：vulnerability\_audit 与 verification 均为 NOT\_RUN，本计划只排序审计优先级，不给出执行结论或漏洞定性。

## 发现与复核

静态结论范围：COMPONENT

### 图片加载未限制 URL scheme：用户可控 image\_url 经 urllib.request.urlopen 直取任意 URL（file/http/ftp），导致 SSRF 与本地文件读取

CWE-918 · HIGH · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：chat 请求 messages 中 content\[&quot;image\_url&quot;\]\[&quot;url&quot;\]（由 get\_image\_urls 收集，经 \_\_call\_\_ 传入 self.load\_image -&gt; self.\_load\_image）

危险操作：urllib.request.urlopen\(image\_url\)（第 2753 行）并对响应 f.read\(\) 全量读取

防护缺口：未对 image\_url 的 scheme 与目标主机做白名单校验（仅以 startswith\(&quot;data:&quot;\) 区分内联数据，其余一律按 URL 抓取），未阻断 file://、ftp://、内网地址或云元数据地址

前提：该 LLaVA 聊天处理器被不可信输入调用；image\_url 非 data: 前缀；运行环境对目标地址具有网络或文件读取可达性；模型/CLIP 上下文可用

影响：服务端请求伪造：可探测并访问内网服务与元数据端点；通过 file:// 读取进程可读本地文件，并把内容带入模型上下文造成信息泄露；亦可作为向外部主机发起的请求代理

修复：仅允许显式白名单 scheme（如仅 https/http），解析 URL 后校验 host 解析结果不落在私网/环回/链路本地/元数据网段，禁止 file/ftp 等 scheme；必要时改用受控的下载器并设置超时与大小上限；对不可信调用方禁用远程 URL 抓取

- 证据：llama\_cpp/llama\_chat\_format.py L2753–2753 ；产物 61cb4503-a23e-4e86-9926-087ae9d03513；引用：            with urllib.request.urlopen\(image\_url\) as f:
- 证据：llama\_cpp/llama\_chat\_format.py L2750–2753 ；产物 61cb4503-a23e-4e86-9926-087ae9d03513；引用：        else:             import urllib.request              with urllib.request.urlopen\(image\_url\) as f:
- 证据：llama\_cpp/llama\_chat\_format.py L2647–2647 ；产物 61cb4503-a23e-4e86-9926-087ae9d03513；引用：                image\_bytes = self.load\_image\(value\)
静态结论范围：COMPONENT

### 图片抓取无大小/超时限制，全量读入内存后可触发资源耗尽

CWE-400 · MEDIUM · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：用户可控 image\_url 指向的远端响应体大小

危险操作：f.read\(\) 全量读取（第 2754 行），返回值传给 \_\_call\_\_ 中 embed\_image\_bytes 的 \(ctypes.c\_uint8 \* len\(image\_bytes\)\).from\_buffer\(bytearray\(image\_bytes\)\)

防护缺口：未设置读取长度上限、响应大小校验或网络超时

前提：处理器处理不可信 image\_url；目标 URL 可返回超大/无限响应体

影响：内存耗尽与拒绝服务，可能拖垮承载推理服务的进程

修复：限制单张图片最大字节数并分块读取、超限即中止；为 urlopen 设置 timeout；对 data: 分支的 base64 长度同样设上限

- 证据：llama\_cpp/llama\_chat\_format.py L2754–2755 ；产物 61cb4503-a23e-4e86-9926-087ae9d03513；引用：                image\_bytes = f.read\(\)                 return image\_bytes
- 证据：llama\_cpp/llama\_chat\_format.py L2630–2631 ；产物 61cb4503-a23e-4e86-9926-087ae9d03513；引用：                        \(ctypes.c\_uint8 \* len\(image\_bytes\)\).from\_buffer\(bytearray\(image\_bytes\)\),                         len\(image\_bytes\),

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
  "audit_coverage_gap": "共 91 个可读单元，完成 1 个单元的语义审计；其余未审计",
  "audited_unit_count": 1,
  "edge_count": 604,
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
  "finding_count": 2,
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
    "target_sha256": "b2b6a5bc5067d4bba323c7533ea38f132b5f2ee6529ebff458f8961e43b9f53e",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 25,
    "cost_cny": null,
    "measured_tokens": 143236,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "61cb4503-a23e-4e86-9926-087ae9d03513",
  "reviewed_finding_count": 0,
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
      "finished_at": "2026-09-11T09:51:33.508Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T09:51:33.460Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 91,
  "unresolved_calls": 501,
  "verification": "NOT_RUN",
  "vulnerability_audit": "PARTIAL",
  "warnings": []
}
```

任务错误：智能体响应再次未通过校验：存在未知或被反证的必要攻击条件，不能判为 VALIDATED；请使用 INCONCLUSIVE 或 REJECTED

## 证据产物

- aegis-report-3b149981-84e0-4a33-a96e-233167df8aa9.html；ID：d16570fb-8221-40a8-b8b3-7ff655917041；SHA-256：76125094fcd283717520438cd30339c5f100734acef2e2458767072f81fe5ddb
- aegis-report-3b149981-84e0-4a33-a96e-233167df8aa9.json；ID：6d7802f1-5a61-480a-9666-8797407106c5；SHA-256：eb1fcbd5faa7ccae321b6fb4d497e1698ad2e85621e649e6ee331c84398481cf
- agent-AUDITOR-4cfcb4f0-1e06-497d-8ef6-876fd76719d2.json；ID：9340d1c2-442f-4fd1-8ac8-2eb97878d72f；SHA-256：30c347ef70a148d173d1c609350398d92a39408d87060a1c7c965a78ec453149
- agent-PLANNER-4e635114-dafa-4606-b1cf-3e07e8fa8dfc.json；ID：885afe78-d76e-4b60-abca-c713afff7bce；SHA-256：d62bbc81b81cb8ff7ab8d5a6ea5821973bf73459c88e0870a5a56cec87c61b63
- analysis-result.json；ID：61cb4503-a23e-4e86-9926-087ae9d03513；SHA-256：fdfb88ddd80bac975fd7b53c4cb7ad93446c216a1eebb4c5a1f6e7306628c94d
- model-request-05351795-9ba9-4374-b965-476e98ecdce0.json；ID：d92ec4b7-2e03-4dfe-99be-d82e991d3994；SHA-256：9352d45fda8aa264d95e46c052f318b2996cb0efe72ed0730fcfb4f62eba6ba9
- model-request-19d691e6-a2a7-463c-ab15-40bd981bb57e.json；ID：86a925be-6907-4fd7-a3e8-00c5e1f50811；SHA-256：56be4a22ae0e606c1a5a2845d22b0b742065a86e5fe7d7a355f6ab1aba17c7ec
- model-request-28056fff-802b-4fff-82e5-700431322ff0.json；ID：5eb3b21a-1c0f-4ccc-825e-d591e790d69b；SHA-256：74dea5c3d7a8b23c32c8474380277af530d62c6db02193680ddc7e794692d66c
- model-request-292d5083-d63c-4884-980a-2e9284aede89.json；ID：108805e1-aaef-4c17-985e-ce86db3ca054；SHA-256：76b91b1230e9f388882d085359978990746be42b5877ceece934d95b32125bdb
- model-request-2e9c0ec0-d185-4d22-a295-ec376facdcfa.json；ID：e72adcf3-e943-404b-be57-38eedc6c7880；SHA-256：671b6d5f64931559c1d99e297dd240f422bf1f1704411cec83d8590e0f708e70
- model-request-2f2f2a0b-4dc2-4d32-a100-67d9464b402c.json；ID：d0a52b54-fa67-4570-aeea-289ab2242cc1；SHA-256：f1fde443295547fa1615cbaf79e040a900bd95c6099a18146d4631ec7dd59fd4
- model-request-308aa305-9ad8-4641-9754-62557dd270cc.json；ID：77462176-69c4-4ac5-afa8-38e9c3124bea；SHA-256：745c15d483827014765589ee05b2906c6b3d9f16098dc3cf6c28e6a70b5b6a92
- model-request-35b9e9d9-d353-4f45-ad3c-c83872551e23.json；ID：29d005f9-cfde-40d7-b4c0-1cf8acda6e4a；SHA-256：7c021e3aa54cd54427098aa27318e4b34c912e9701a702f614e94d970dd0d380
- model-request-4590edd8-3e39-4513-9589-bed780d5d21e.json；ID：39ba756b-4a32-420e-9c0c-3b08554c04b1；SHA-256：c93baa720817a296e8ce3bcb848a6ff8f9d0997a85cbe271b2231eb7c5cb3b15
- model-request-4836bdce-288f-4f6a-8d93-73fa4f016449.json；ID：bd7fdc75-9901-46c4-900a-9d8a9ce51bda；SHA-256：1585e06f1baf934bed3a7f5d608b613540e65f97416a65f332e6fd1e6421add2
- model-request-558d404b-93b2-47a8-bae4-3695f74e524a.json；ID：832b81c6-c6ed-4706-81ac-3f1b6e0b3563；SHA-256：32fd75d101a74dc3af088a5b5901d6368bfe0faf6e5bcd809e235e1b0ce4b270
- model-request-5af930eb-9dff-4855-b9f1-0b22286c7b0b.json；ID：b9a6729b-51c5-4edc-916a-20985d68b4f4；SHA-256：a0682d9adda539379e9988bd64e867c95b8143801b7abca5bab6b022642c606b
- model-request-5b9a4c77-07a4-4237-b053-7e6b455e7c65.json；ID：167f5f26-c2a2-4241-999f-a672e5e1db3a；SHA-256：1521bf69c3583b0e060eac90842b6ff5430b12aa994cf1a8ce31715835769966
- model-request-5e51a715-8e28-4642-8328-16bcc1e97a01.json；ID：0196ef35-734f-4ceb-a9c4-4000246dde95；SHA-256：25961b7b23fb02861fea0dae6e13d9fc762cd2790a936783e411b3067aa4fd94
- model-request-5e81a608-6ac6-421b-b35f-bb5e22d755d8.json；ID：e5b62eee-d18a-4a7e-b87b-86795960bf31；SHA-256：0649e763edf72393450a2ba026bee9aa4c847fca306f06433ece7f04872886c6
- model-request-7773feca-b9a5-44bc-b1fa-9b8cfa1b8887.json；ID：8738a137-1650-4e71-a0b7-72b3fe3d4825；SHA-256：b723ac35f18086916676121eb080bdbd30c7a29c7036035ef6512ccf40c063ba
- model-request-7b06ccf6-d0dd-4b14-9b8e-1e63c4ea2537.json；ID：6d87a7b7-1243-4ba7-ae7c-3659f977d1ec；SHA-256：87420a1e25c32359560462f71bb311a9e742dad5ab13bde3bc30f6ff2abbf627
- model-request-91b2604d-2d32-46c1-af95-61d2f6be22a4.json；ID：7ad56e9a-f7d7-4111-a035-9c05c03ee3c0；SHA-256：d20c93ab2276630c587b08fae16c2636fe458434346d214ed8aef22e9d6e9e72
- model-request-95c2406d-9383-4ab3-95cd-ab740ca603d8.json；ID：d77e63e6-7f97-42f6-a6d5-7437a839e604；SHA-256：10d441a71f0308f7d7cae136245b77dabd2e42a482facb8d7f0f3e473f8654a1
- model-request-ad34976c-d421-4637-b932-9a65593ac5c0.json；ID：4f7a5ed2-5feb-4af7-8d9a-d24e1a398545；SHA-256：f13eba7b3bf382c724451cda3f4ffbc421047cd4f4125bd784f55980c53954c3
- model-request-b05e6252-456b-40fd-a269-926f02301490.json；ID：7eabdc9a-6675-4879-ad9a-592516715ea9；SHA-256：d8e4eb5bf56054553824877e12d5d89bdcbf22cfcfa6f92cbc74e5aa9594524f
- model-request-c5295027-b41b-46fd-8b59-ac579da985c1.json；ID：e7a84cee-d92f-452f-a8cd-5801f2f0ac22；SHA-256：1f20c8137198d1db2e9071d4b4c947b1ec44ce1a8f64e0b55660b140ddfe8c21
- model-request-d905ad21-edcb-492e-a733-d8c324562dc5.json；ID：7235a33e-4d75-426c-943c-483cbd00e7b6；SHA-256：a9086dd28e3a3b97597686cc24ca499ba1fc4f193ac39209880ddc7b0f0caf1f
- model-request-f1af9e7b-5033-4fad-937d-c4bfdf650736.json；ID：f42651d6-65ae-4225-8237-d145fa2fb7d8；SHA-256：1481bb3df9977cd91c08fe219f3a2ff149ed3cdb6ccefa0b839049f28d715673
- model-request-ff09d398-f8c3-4bb2-9d6c-bde97cff6648.json；ID：ea11d506-da0a-41a4-ad6a-d70a27a81170；SHA-256：c48fea71835b05ed9762f08f6e785ec5bc9ab21cef30abb6a44a671fba71b51e
- model-response-192c1dbf-7fc6-43cc-a0bc-d4f341a0e00a.json；ID：80351aca-e1f5-4099-82ee-9ff9a1bcca81；SHA-256：f0864c3cdc1d68a29a7c49281d8339765a554d664d31ba09f7a59d1e1ec2669b
- model-response-1bad43a6-a394-4eba-bb06-b32239a571ee.json；ID：e942c39c-e54a-4db5-b054-96e7f433035c；SHA-256：99a2d468d3a8a1967d84638764739b119abf9b17472a0bac873ac79f8b7bf5df
- model-response-35222f0b-59f8-48d1-aa47-85af16eed711.json；ID：649fe693-293f-4a17-9beb-2ab9584fa3db；SHA-256：3fd8aae30b270819c1e340e4f0a69a98ff6ba35101c7411d51283f915749d092
- model-response-3cf678cc-41b5-4216-80fd-1f0dce9433dd.json；ID：94a02a6b-cb81-4b42-88c2-7089c776948f；SHA-256：39788fc668ff993f72ce0a5cd823a4b5aabfcb58c26241685ad9cce12b94bc27
- model-response-3eafb02c-98d4-4b3d-890d-aa92bbe6e955.json；ID：20a9d13e-4321-493b-962d-01a9018e9773；SHA-256：dd83c599eece16438366eb7d7865a0838060ca67a332879719e3f63ddad9da84
- model-response-4033b9d5-e10c-4311-86ba-fdc9cbca9cd4.json；ID：3773813e-85ef-4293-a8f9-1bbcc148c911；SHA-256：ddde05666f42550f03caa4035bdb12e4befee17a0b163a022718c83763843547
- model-response-5e3e4434-508b-4e6b-8b51-f8a444347805.json；ID：870ebe84-24d1-4559-9573-667f5c16f501；SHA-256：389e5e2e42e18733fa4520befc8df19762aaad0878164c429a62283a6df96e1a
- model-response-73048077-5a93-4aae-b1aa-bc4b9c98df7a.json；ID：bb959ef5-527b-4dbb-aba9-eafb35b7bdc4；SHA-256：e82d30691abb8b0268abe5e47bd2000a68a81e204615c6d1e0fa39e2d18f7763
- model-response-77f58dcd-0ab2-4548-a2ae-7b69afc4edcf.json；ID：9c12aaed-bc05-46de-b54e-e8ae7cf2142e；SHA-256：9bc75267d2ae97d6ad6f1ad95d03724b306959140792dedabed500f86fc252ed
- model-response-937cbed5-31f9-4384-b438-f32432d6355f.json；ID：a8ec068e-ec7c-46e7-b535-6a5086a8a9e6；SHA-256：b51bf8902d8def47e4ad4810769d56abffce0abd9f165134f1ccbadaf4df31ed
- model-response-94d09239-fd5d-4950-a6c0-36627865a919.json；ID：5957738f-f202-4966-802c-2d952ac39bf3；SHA-256：1b0bfcbacbaca111488ffc39dd574e8e2ef3763e87e61ea5de5074b5b6c8f4ef
- model-response-9936f2e7-b330-4d42-b6aa-8711cd759399.json；ID：139b25b2-3cd2-4ebf-b199-fac503e88aa4；SHA-256：6f6b20f9e00b6b4a49d99d33d29e5b136c975c3cb45a381f7f3c837bbc1178b8
- model-response-9f338369-0d39-4dc4-963b-cb5ce0f19712.json；ID：4c4240ea-d158-4e0f-8c3e-d931318c95ad；SHA-256：0c928aabfec125d3c3f177c0def11f56201348484edbc644e83b55e5a2e7e4db
- model-response-af11f3ed-e1ea-43de-ae1b-8aef00f60850.json；ID：ea5a8457-e936-4532-b815-7130d403137e；SHA-256：2ab95f72e779db91d0e3d756e72bdcb9eeb961c65c52a9f5d57af2fad9d5f761
- model-response-b6f6b26b-44cb-48de-9fe4-b2f6d38be5a0.json；ID：f99e8aff-88a6-4415-aa27-f0d0fb56402c；SHA-256：443a11f2a59a438e87fad04df628fab11da7e0a120cc9d34e406b38cd349e19a
- model-response-c0f83910-c351-4677-815d-397be14fb543.json；ID：a9a4e7e7-88fa-4d94-beaa-22db77793e8a；SHA-256：796fee691349f2d8baed90f6694dee501a9950fbd3adff84f91805abbb8d4aed
- model-response-ca248cc5-b298-4fd5-8cc2-34ff2db3aa23.json；ID：061b18d9-778a-4685-9f89-d3051a42e5bc；SHA-256：bdddb6d922f4582d43121056863bd1ea381a9aa0cfc6dea28d95e4c992d307a5
- model-response-cdd1c108-b482-42f9-995b-2c369557ed1f.json；ID：bd8e31bb-6b86-4ff6-b7ad-74a5ed53de24；SHA-256：a0a5f75c68b521ee7178bc16715a12ec0fed596b098594b400d6a83ead04f664
- model-response-ceffbdb6-e423-47af-9dd8-74886d1350b8.json；ID：f8e71d98-cec4-4219-8508-2004825a9969；SHA-256：6968ac735ed49370ed1b052e5a8fbff327c8587ee23aa23f705cced52cb8d3a0
- model-response-d477e6e0-f05b-4b69-8d5d-208ad9ea1383.json；ID：3622d8e6-2e7a-42b1-9a58-a281ac0cedcd；SHA-256：b2e9e9251113e1e5e42ac6d0ef100c68244c5662f36402ffb0584a027c45342f
- model-response-dec667fc-f3be-45c5-832c-7a9814752de9.json；ID：4e324324-422c-489c-a932-69b3ede42d73；SHA-256：dcea7797b74b8d554b2cdf835d2f43345d3b871eee9dd14c7ac40a61aab62aeb
- model-response-e613e53a-c445-4ec0-abab-17853a20ecd6.json；ID：957da0ad-179c-4e05-8397-b3057ed03b22；SHA-256：9338e54acc2025f9cdd59ac338303bf2ec97646eeaa56a95980ca1f30a037e09
- model-response-f0588ccf-3188-4ea0-ab68-880c85cd083c.json；ID：524fbb67-68b2-4926-abce-0c40abe0ada7；SHA-256：38adcb0fcddfb940fdc87b4aedabcd647cea2ed06a978aa0b0936f1b978ccc15
- model-response-fa3ae1ab-f2ee-48bb-a54b-a51273d694db.json；ID：ee5ba857-2a20-48af-a515-8cfb6f93c84b；SHA-256：ed63921f484a67c07d7e57e3eaa30546a41fefda68efaca1488a85fc1445908b
- model-response-fe2183a0-c4fb-445c-994c-1ca575a84b38.json；ID：a793caff-7905-4ea6-a861-0a1f4012152f；SHA-256：437e16bea1531467813e36fe4d7778d85f30f7e6f1409286626e896b480bbe3c
- p01-llama-jinja-fixed.zip；ID：ea2dde8f-a2ec-4e90-a180-80b7e5aad0b7；SHA-256：54095352552ce6196e40dc83ea84bdda288695a9eea3d41569581af49d138d58
- snapshot-manifest.json；ID：0597f03f-750e-4830-b019-0b8e9bc46d05；SHA-256：96fb2a37d2e3fc9644d292cf46c15020c1c72ff69205d78a0c52fceb722a4edc
- source-snapshot.zip；ID：dbac746e-4a6c-46d1-b696-c99170526871；SHA-256：b2b6a5bc5067d4bba323c7533ea38f132b5f2ee6529ebff458f8961e43b9f53e
