# AegisAudit 分析报告

项目：对照池评测 20260911-073500

任务：2d239400-1b70-4364-a76b-8bb86cd64e5f

状态：Partial

目标 SHA-256：f0e549546608e38a56149170307630323e16d26e48989301b0b4c75383222421

结果快照 · 数据截至 2026-09-11T07:35:38.459Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：NOT\_RUN；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

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

目标为单文件 Python（fastchat/serve/gradio\_patch.py，7 个单元，U0001 模块 + 6 个方法）。先只读取整个模块源码（U0001，1-167 行）确认数据流：Chatbot 组件重写了 postprocess 与 \_process\_chat\_messages，把消息内容拼接为 HTML 并用 markdown2 渲染。计划按“外部输入 → 输出 HTML 渲染”的信任边界排序：优先审计把消息文本直接拼进 HTML 的 postprocess（U0006）与做 Markdown/媒体处理的 \_process\_chat\_messages（U0005），其次审计构造处 \_\_init\_\_ 的 Markdown 解析器配置（U0002）、配置序列化（U0003/U0004）与样式入口 style（U0007），U0001 作为整体数据流/导入面（from gradio.components import \*）复核。注意这些方法是组件输出侧处理器，是否构成漏洞取决于上游调用方（控制器/前端是否转义）与部署形态，属于必须保持开放的缺口，不能仅凭拼接字符串或危险函数名定性。

1. u\_694d3cfd9b0ae4506dc3b9dc4f51b070：postprocess 把 message\_pair\[0\] 直接字符串拼接到 &#39;&lt;pre style=...&gt;&#39; 中输出为 HTML（143-151 行），并调用 \_process\_chat\_messages 处理消息对；这是本文件最直接的“外部内容 → HTML”信任边界，需核实消息来源（用户输入或模型输出）是否可包含 &lt;script&gt;/标签，以及该输出是否由前端 innerHTML 渲染。
2. u\_2513838d2381caa74eb5e434381bf6f1：\_process\_chat\_messages 对 str 消息调用 self.md.convert 生成 HTML（115-117 行），对 tuple/list 调用 processing\_utils.get\_mimetype\(chat\_message\[0\]\) 并把 chat\_message\[0\]、chat\_message\[1\] 作为 name/alt\_text 返回（102-110 行）。需检查 Markdown 渲染是否允许原始 HTML 与是否对 URL/文件名做校验（本地文件路径泄露/SSRF 类信任问题），同时注意 get\_mimetype 依赖未在本文件出现的实现（缺证据）。
3. u\_c57c65562f3d5228fb69d68cf4e97b99：\_\_init\_\_ 第 54 行用 Markdown\(extras=\[...\]\) 选择解析器能力（fenced-code-blocks/tables/break-on-newline），决定 U0005/U0006 链路的输出语义与是否放行原始 HTML；同时第 62-72 行把 \*\*kwargs/color\_map 传入 IOComponent，属于参数透传边界，需确认是否存在未过滤的样式/属性注入面。
4. u\_bdfa3dda0495b6afcca08be62b29592b：style 接受 height 与 \*\*kwargs 并写入 self.\_style、调用 Component.style（158-166 行）。需核实调用方是否传入用户可控键值，否则可能污染输出 HTML 样式/属性；若键值来自固定代码则风险低，需以实际调用点为准（当前为缺口）。
5. u\_5c31ba83c875852904f391061a07f784：get\_config 直接返回 self.value 与 IOComponent.get\_config\(self\)（74-79 行），value 若包含消息内容会被序列化进前端配置。需确认这是否成为 U0006 渲染之外的第二条内容输出通道，以及 value 是否可被外部影响。
6. u\_3a6a9c20762cdc313cdecc64f204f55f：update 把 value/label/show\_label/visible 打包为 \_\_type\_\_=update 的配置（82-95 行），是组件状态的输入侧。参数本身未被本文件校验，需结合调用方确认是否存在状态/样式注入或被用于覆盖前端行为。
7. u\_e3799138a1e3e6ca2a78971d1ee07fb6：模块级 from gradio.components import \*（第 7 行）使 Changeable/Selectable/IOComponent 等父类行为不在本文件中，postprocess/\_process\_chat\_messages 的最终渲染语义与转义责任落在未提供的依赖实现上。作为整体数据流与依赖面复核单元，用于确认跨界证据缺口。

规划限制：分析范围仅为 STRUCTURE\_ANALYSIS；call\_graph\_complete=false，且只能在 1 次工具预算内读取 U0001 全文，未逐个独立读取其余单元（其正文已包含在该 span 中），也无跨文件调用图。

规划限制：Semgrep 未执行（平台不支持，UNSUPPORTED），无规则线索；metadata.verification/vulnerability\_audit 均为 NOT\_RUN，未构建、未运行目标（target\_executed=false），无动态证据。

规划限制：未识别构建系统、入口与输入接口（metadata.run\_config.missing 列出），因此“消息内容来自用户还是模型、谁负责 HTML 转义、前端是否 innerHTML 渲染、是否对外暴露服务”均无法确认；XSS/注入类风险无法在此定级。

规划限制：markdown2 与 gradio 的版本、extras（如 fenced-code-blocks）是否允许原始 HTML、processing\_utils.get\_mimetype 的实现与返回值校验、IOComponent/Component.style/get\_config 的实现均为外部依赖，本目标未提供，属明确缺口。

规划限制：human\_annotations 为空，无参考数据可交叉验证；任何结论需在补齐依赖与调用点后独立复核，禁止仅凭字符串拼接或函数名判定漏洞。

规划限制：未记录任何解包/去混淆转换（recovery 为 null），不做此类声明。

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
  "audit_coverage_gap": "共 7 个可读单元，完成 0 个单元的语义审计；其余未审计",
  "audited_unit_count": 0,
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
  "finding_count": 0,
  "function_count": 6,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "NOT_RUN",
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
    "calls": 7,
    "cost_cny": null,
    "measured_tokens": 30894,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "3b7eb033-5dd7-4697-9869-bcb575372f59",
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
      "finished_at": "2026-09-11T07:35:03.121Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:35:03.119Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 7,
  "unresolved_calls": 19,
  "verification": "NOT_RUN",
  "vulnerability_audit": "PARTIAL",
  "warnings": []
}
```

任务错误：智能体响应再次未通过校验：证据的行范围或引用文本无效

## 证据产物

- aegis-report-2d239400-1b70-4364-a76b-8bb86cd64e5f.html；ID：3cc9674c-8509-4ec0-a748-43dc1c0dee03；SHA-256：471bb5aa7a8391449286410cef60b5a832f77ac8160f69ded9a80560f8d5d865
- aegis-report-2d239400-1b70-4364-a76b-8bb86cd64e5f.json；ID：706554d7-e87b-4e03-9ad5-b2465984541a；SHA-256：24285449ebe277abbc8cc3e3c4849aa7397d099966f40aeab66d650fabf4546c
- agent-PLANNER-60dc7cf4-10a8-459e-9453-254d021da964.json；ID：10395ed6-ffd3-45b7-a028-e98baea673e6；SHA-256：c1d836898507a3542100fa18966375c22151903695d6cb97524eb925a4f335ed
- analysis-result.json；ID：3b7eb033-5dd7-4697-9869-bcb575372f59；SHA-256：b32c6123c8e509cc124d00f112bfb7398f33f359667e2527b90f87a93dc3e154
- model-request-33b6329a-0adf-4a13-815c-47ed82c35c76.json；ID：8f6ac240-9876-4022-ad4d-da558d4da48d；SHA-256：e99d307cddab986a5d75ef9cb1d852c79fe20c62cb4f91c9cd0918715b101eec
- model-request-5e2d321e-e3e8-455b-a755-84b722f97a86.json；ID：a0795e2c-dc84-42d5-af32-ce33aa064885；SHA-256：ef6dd8df2bd44578afc49a5c738a2ecb30e2de55c88554c8d4638efa7d3ae4e0
- model-request-83b7180f-5d1e-44ac-a2d5-64707cfd6688.json；ID：6ee07b74-40c0-4720-a8a1-2972d84e3b2f；SHA-256：76e23f560a8d655af2b0218400803e2968e67fbdbded81840a3e1ea028e2d42a
- model-request-95c1a82c-63a9-433e-904b-23132d920217.json；ID：8b4d3cb9-aefa-428e-bafc-abe6e687bf48；SHA-256：509a93941b8a65150b9a0bca74ce466f03856ce1d952a7040f1cf2a0cda1b35d
- model-request-9cd07bf2-76fa-476b-b34a-a3e0fb2363e7.json；ID：86caac73-41cd-4d8a-87c2-85457c4d5de2；SHA-256：ccdaeea49ef429d60b47229f0db9cb53cda6f085793665fbfb0f05d4a52aae88
- model-request-d70b4757-1ae3-4b5d-8408-eba4af2c64a8.json；ID：b48bd4f5-8e67-4982-bc74-721e3afdf780；SHA-256：135c920ad1f47624e95ff0076630cb2039a8df69d90a95f25bc112e3d44d0fe3
- model-request-e151a8db-22d2-4d0a-a107-3366ffcfed83.json；ID：3f810f48-c996-4240-9906-52836193c9cf；SHA-256：017081e26e44002361015d37b5c569bc6ef2ff62c79fc90b26889c829e18c23a
- model-response-2075f8bd-b376-47ca-bf3d-7a88ac44acc5.json；ID：9f2f4276-7692-4ec1-be57-d23a4a93bcc1；SHA-256：edc9ae6589d0a1a54bf198274ee6ffd9650d04e514dd4e1f687d002a105cb0f6
- model-response-211ff1ba-9664-4ac1-b4c9-fd2104bba93a.json；ID：a38b9d2d-f2d8-4b23-8fe1-61914243715a；SHA-256：80f443f13b8d1a2915c8a972afa070e0740efa8f0404140407aaa1e6515f4bea
- model-response-810d73e8-4e61-4689-bab5-0be8427dcbef.json；ID：98a80b7c-9ee6-437a-8a0c-5e54632a6eba；SHA-256：98cf2bffd614e80867163c15399807c34c11ecca6564e46118e72cc109115b06
- model-response-8365e5df-7ef7-4ea1-a9bb-2445b8cfe7f6.json；ID：fb913a3f-3003-4eab-a609-8195e64b3378；SHA-256：58f00a9430001d79fed5401f3d271162c312516a1a5062693bb06321fad22e74
- model-response-9dbef207-9a92-4a61-aaba-25f8615f69f4.json；ID：2428ece5-b3d5-4999-baa5-64c8bb316151；SHA-256：97b92ae52bf3ee0b30980e2fc5e366ef3c14832f7068efda33724b60d2b63071
- model-response-dc88e485-ebaf-43de-846b-58de75589bda.json；ID：6e3a327e-a5cd-4902-be1b-ea9cd0cfe491；SHA-256：dcd8e3ac472bde0e994e6dba1da099e8f7938462bbe416bbd244ac9f1ad050c8
- model-response-efcf935a-70a0-4712-b1a0-5b127d00d4bd.json；ID：1c2ddcc9-94ca-45dd-af42-44185edda437；SHA-256：ffe78c6ffeadb217ca8286e7791921c24cf3fb907868553bb5d710f5c4409ee8
- p03-fastchat-xss-vuln.zip；ID：797296f7-144c-4e84-993b-3ce9b7128e15；SHA-256：2c0029bece926ac8d1e5388307a42c45d91b602cd8feaf914f8f94df794d8402
- snapshot-manifest.json；ID：0a0a6390-619d-43b6-9f8c-28255ad26fb2；SHA-256：de7abf27f4f52fea5634b584618114f55e67430e7347a8fdd5f57abaab37c0da
- source-snapshot.zip；ID：748eb6aa-451a-40fb-96fd-9a30d2791eb6；SHA-256：f0e549546608e38a56149170307630323e16d26e48989301b0b4c75383222421
