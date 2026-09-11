# AegisAudit 分析报告

项目：对照池评测 20260911-074524

任务：110e1ebd-574b-4534-a3ab-47c1ea16b7c5

状态：Partial

目标 SHA-256：1c49987949af5726ac1ddf397986b4dcee265eaed1db1082e4685377d660c923

结果快照 · 数据截至 2026-09-11T07:59:42.874Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：NOT\_RUN；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

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

仅完成一次受限读取（U0001 模块前 200 行）后预算用尽。从已获证据看，server/download.go 是分块下载器：以 HTTP HEAD/GET 的 Content-Length 与 Range 交互、把分片状态持久化到 &lt;Name&gt;-partial-N 文件并在重启时恢复，内部用 atomic/互斥与 sync.Map/errgroup 做并发与去重。计划按“外部输入→信任边界→文件与偏移算术→并发与错误处理”排序，优先审计解析远端头部/持久化 JSON、拼接文件路径、以及 offset/size/Completed 的算术与切片索引处，其余函数在预算内继续审计。

1. u\_ce2d4c95ec6b9620bb2b2f0e15709966：Prepare 是外部输入与文件系统交汇点：Content-Length 头部解析、b.Total 与 size 的分片切分、Glob 读取既有 partial 文件并累加 Total/Completed；offset+size 越界判断和解析失败分支（ParseInt 错误被忽略）会直接决定后续 Range 请求与文件写偏移，需核对边界与错误处理。
2. u\_b83cfe584e19b919f5d9a9f08aa5ff31：downloadChunk 是分片核心：构造/校验当前 part 的 StartsAt/StopsAt、按偏移读取已有数据、向响应体追加写入，涉及下标与偏移算术、字节计数及 HTTP 响应长度与实际写入不一致时的语义，是最可能的整数/边界与恢复正确性问题集中点。
3. u\_a0500f3bc6907ab42bbb225f98e67b5d：readPart 读取磁盘上的 partial 文件并解析为 part 元数据，属于持久化状态→内存对象的信任边界：文件来源、截断/篡改内容、反序列化得到的 Offset/Size/Completed 是否被校验，直接影响后续写入位置。
4. u\_2073e5bb5971c107989a5a481a06b6c8：downloadBlob 作为入口级函数，负责从外部传入的 Name/Digest 构造存储路径并驱动整个流程，是路径与来源信任边界的第一道关卡（名称是否可能含路径分隔符、是否复用 b.Name 作为 Glob 与文件名前缀）。
5. u\_b3f182d0a865641a7f8f6c73c7fff845：UnmarshalJSON 把外部/持久化 JSON 直接映射为 N/Offset/Size/Completed 且不做范围或一致性校验，负值或超大值会传播到偏移计算；需与使用点交叉验证。
6. u\_7fff43b3c5014d221d2d1d1f2d2bb886：writePart 将内存中的 part 状态序列化落盘，需核对写入原子性、临时文件/重命名、以及并发写同一路径的竞态与数据损坏风险。
7. u\_d1d0a4b1f737274a594020e4f9d84f42：newPart 分配 N/Offset/Size 并挂入 b.Parts，是分片编号与范围的单一构造点，需确认编号唯一性与 offset/size 的合法性校验。
8. u\_351f84967df763c0e1921308c23dbd9d：run 是调度与重试主循环：errgroup 并发、重试计数、errPartStalled/errMaxRetriesExceeded 的判定条件与取消传播，决定失败语义与是否出现无限重试或提前放弃，需核对状态机。
9. u\_e7ade2366c1a1023fa9f0ff303f8e193：Wait 读取 done 通道与 b.err，涉及跨 goroutine 结果可见性、重复 Wait、以及引用计数与取消的交互，是并发正确性关键点。
10. u\_3ba5539090beabd5d2d2d22d2a2931b7：acquire 增加引用计数并可能创建/复用全局 sync.Map 中的下载任务，是并发去重与生命周期绑定的信任/一致性决策点。
11. u\_ea5dabfaecc12105d75e8c576a46c727：release 递减引用并清理/取消任务，需确认计数下溢、过早删除（其他使用者仍在读）与关闭 done 通道的顺序问题。
12. u\_7bfd109db5c3d1e99ab6636b8652b15a：Write 作为 io.Writer 只累加 len\(b\) 而不做上限校验，可能使 Completed 超过 Size（与 StartsAt/StopsAt 交互导致重复或越界读取），需核对调用方是否保证不超写。
13. u\_ebb3fa9918b57b360cd9342269bb1cd2：StartsAt 用 Offset+Completed 决定续传起点，若 Completed 被外部 JSON 或超写弄脏会产生越界 Range 或覆盖已下载数据。
14. u\_4b44f9bd511b137ca5ad0b616a94f5d8：StopsAt 决定分片结束偏移与请求范围，需与 b.Total 及响应长度比较，核对是否存在超读/短读未检出的情况。
15. u\_b0dcc14c928d590ca6d18edc3a02752b：Name 用字符串拼接构造分片文件名（Name-partial-N），是路径构造点，需与调用方传入的 Name 组合评估路径穿越与文件覆盖。
16. u\_861fdd7aa890a6c89d73d537b84f86e8：Run 包装 run 并设置 b.err、关闭 done，是错误结果发布点，需确认 defer close 与写入 b.err 之间是否存在数据竞争或读取未完成的竞态。
17. u\_5b44bad7cc835889bcd2e56d8a22897b：newBackoff 的重试定时与 rand 抖动影响重试节奏与上限，需确认 maxBackoff 与取消交互，判断是否存在过久阻塞。
18. u\_a6be9d202ce13e390cd3490e5aed49ce：MarshalJSON 输出 part 状态用于持久化，需确认字段与 UnmarshalJSON 对称、Completed 读取是否原子一致，避免恢复时状态错位。
19. u\_c2a6263ff17f82964fa7abaf20e31c1d：模块级常量与全局变量（numDownloadParts、min/maxDownloadPartSize、blobDownloadManager、maxRetries）定义了所有边界阈值，仅读到前 200 行；需在后续预算中复核余下导入与全局状态使用范围以校准上述判断。

规划限制：仅执行 1 次读取，只覆盖 server/download.go 第 1–200 行；201–499 行（含 downloadChunk、readPart/writePart、downloadBlob、Wait 等）未取得原始文本，上述优先级依据目录信息（名称/行号/线索）推断，尚未逐行验证。

规划限制：调用图不完整（call\_graph\_complete=false），makeRequestWithRetry、registryOptions、blobDownloadManager 的实际使用与外部调用点未见；HTTP 响应处理、Part 读取的校验逻辑可能位于未读行或本文件之外。

规划限制：Semgrep 未运行（UNSUPPORTED），verification 与 vulnerability\_audit 均为 NOT\_RUN，无构建/运行证据；未识别构建系统与启动入口，部署形态未知。

规划限制：人类标注为空，无可参考线索；本计划不得被视为漏洞结论，路径穿越、整数越界、并发数据竞争与状态校验缺失均只是待验证假设。

规划限制：无法确认 Name/Digest 的外部来源（是否来自用户可控的模型名或注册表响应），因此路径与信任边界结论保持为未决。

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
  "audit_coverage_gap": "共 19 个可读单元，完成 0 个单元的语义审计；其余未审计",
  "audited_unit_count": 0,
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
  "finding_count": 0,
  "function_count": 18,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "NOT_RUN",
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
    "target_sha256": "1c49987949af5726ac1ddf397986b4dcee265eaed1db1082e4685377d660c923",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 8,
    "cost_cny": null,
    "measured_tokens": 53289,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "a9a4fbb8-03fb-4dc3-a1b2-4094ab0e23a0",
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
      "finished_at": "2026-09-11T07:58:43.094Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:58:43.081Z",
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

任务错误：智能体响应再次未通过校验：证据的行范围或引用文本无效

## 证据产物

- aegis-report-110e1ebd-574b-4534-a3ab-47c1ea16b7c5.html；ID：bc51f89e-9bb3-4e9e-a274-c63fba0e89ff；SHA-256：dc7e971fed932fd01561a2130ac2a0abfcd7f3fe3f77f0840192af3eb25c535c
- aegis-report-110e1ebd-574b-4534-a3ab-47c1ea16b7c5.json；ID：ef59b5cc-fdee-44a5-9a44-a185ba355840；SHA-256：b817593f648595eaa1ccb8c997bdd87b46e0fb3d9bc858d4d105ec63418fdf03
- agent-PLANNER-005e8630-0a32-4040-a513-8f95ca5e2c3b.json；ID：a34b34be-f2ff-4c25-aeb7-342caf876bf8；SHA-256：3fc837224f0ee928d621df57ec803cace701cca8fc70e8512450e57c6c76e80a
- analysis-result.json；ID：a9a4fbb8-03fb-4dc3-a1b2-4094ab0e23a0；SHA-256：0f68ee92b1c99c048fcfc68f2b9d549455dd4e22120f8b61acff289c57aa0cfa
- model-request-2540cc30-b2b5-4c03-a36e-2719f404c40e.json；ID：006d0064-cd06-4aba-a460-8f27a9cd2568；SHA-256：c5c160b976412aa6a12ea836e3f5bb7c2d282f4704235e5d56263fee40c9362b
- model-request-2b39ce3d-ee9e-4178-98dd-54abd58f481c.json；ID：fd31cf79-b05c-4128-904a-6b65c5985c76；SHA-256：28cd278d443ac0b2d710df04e1dd20d464e37a3dbe182ef8b21a328b4cf2290b
- model-request-4f81d16b-f9eb-4402-992d-5bd6162f7423.json；ID：05e3d3ed-7712-4a2b-8541-02d65bccd41b；SHA-256：093a55d6a8c0b44647a14b1f244029a4db9d277b3d2cc065377d2ce0795c0451
- model-request-836f783c-bf40-438a-a85d-d3b069500bc2.json；ID：c4021650-be75-4dee-b397-a5f332b3c59f；SHA-256：6483c6581b8f708d5cd7317b536c419e719942317a12170de8c0fa7fea51fdcb
- model-request-9dda75b8-079a-40d4-b64a-b1dfb37cc4fb.json；ID：a7a65205-8e09-438c-86db-97852ab92da0；SHA-256：a326e017923762c04d7af14f26b1091f5269b390116cea003602bb8e0061399c
- model-request-afb5ae3f-b330-4a9d-93ee-c728a2150173.json；ID：fe5c5947-75cc-4c0f-92be-ec6c1eb10cb4；SHA-256：ee536c5a0e20cb6bc1d24a2b4be9e1b963251a1455c583a296c6bb18a3bb37c9
- model-request-ce42e9a9-fd66-4813-97e5-e214f2f7220b.json；ID：1cc56ca7-0a20-468e-9419-ea6a5a4fcd36；SHA-256：7b846c02105b4a1b494faeb8cf20cdb056fdd06a0e5c24a7e389134ee1b387ee
- model-request-d1e407f7-2346-4316-89f5-aeb7534418ea.json；ID：e0f904f4-8015-4989-a855-d4cf56000425；SHA-256：dceb7900b22b2de2b28cd843f0c0332952fd4e9ecd24824d7a4118c4259903a7
- model-response-1ac8b707-29f8-49ba-b166-eea7f46fc909.json；ID：76bbf62a-4b13-4968-b8b9-f2e789d64303；SHA-256：e6135c7e71b99e9c965d482f56b2a5ecc0277c44d2da91ed96a8a88f45f2c4eb
- model-response-39e8bd8e-785a-4f31-9065-d8c59c94c69a.json；ID：365f33ff-086c-4cdf-87dd-0c1be33fcdf2；SHA-256：02b19e9f73015265761bb7ab0dafba063f79db2695e68e4ee99017453509104a
- model-response-3e9a765b-bc34-49d7-b6b0-0463f43e5085.json；ID：878c065d-6087-4f23-999c-29e71b5256d9；SHA-256：b1cbdc41947256c32502fd989d3cd30cf23487621b8466a38afb2b9506ecee55
- model-response-519764e1-0501-4bcc-ac50-01887d8c07dd.json；ID：558f1719-11cb-4e08-a280-04eb80afa9c3；SHA-256：d318ab28849418d913c481647aee667ec6eef0a5ed11b9635eb48c13ac28673f
- model-response-6001e8b0-c041-4217-a9b7-9ac993ab51d2.json；ID：a184c595-7add-485f-ba2d-6d1b0a84b268；SHA-256：4af80092fccb81cd93e7abe2a07603ce3a2a2322077c0b6bf630e96c78e7918d
- model-response-ad05e877-9b19-478f-a63b-03d68cdc7b6f.json；ID：43a1db4b-b966-4e8b-b09a-777ebb994aa7；SHA-256：89ed8eebeb265c77e43a30a53cd59fa44bf81ae2c30a86ff27bee6656b110331
- model-response-c1bf54c2-0a59-4549-9fbd-2dce1b172149.json；ID：48239139-c215-4b85-a298-c29145c2744b；SHA-256：ffa92d5df2f85336f1cc3f6d42010ebdf019537086b91913ebfe2d4130cdd565
- model-response-fbdb4d7c-c1e3-4e9c-a16d-aaa18a1f440d.json；ID：b37b268a-6809-42ad-8ec5-aec84a6372bd；SHA-256：ae65498b247d97dd6775cf0bc251d04f91d012aab7e72d1b76b8bb98a99c930c
- p06-ollama-parts-fixed.zip；ID：5c787dd3-2c74-4103-ad98-c5466b9c5b8e；SHA-256：61492df6a4fbb3cbe3aedb9c0f8e2b3f37bf6fd2e63354717c7d2a631daa5c98
- snapshot-manifest.json；ID：e3f0fb8c-f300-42ac-b9e1-965afa82fdd7；SHA-256：b2453badd166823c962c1cb415f41eaf0d9b7d00d37e5cd332c3a0402f29c6b9
- source-snapshot.zip；ID：749d0ebd-ca13-4792-a912-7d4ac92da6a1；SHA-256：1c49987949af5726ac1ddf397986b4dcee265eaed1db1082e4685377d660c923
