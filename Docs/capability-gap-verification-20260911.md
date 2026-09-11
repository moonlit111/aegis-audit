# 能力缺口核对与修复登记（2026-09-11）

基线：`fb409ad`。按用户提供的 26 项登记逐项核对，保留现有证据校验、幂等请求、乐观锁、取消及进程回收边界。模型验证使用本地测试提供方，不使用真实付费调用。

| 编号 | 核对结论 | 修复与验证状态 |
| --- | --- | --- |
| Q2.01 | 确认：缺少有序阶段契约 | 已补 RunPhase；从持久化任务重建，刷新/重启回归通过 |
| Q2.02 | 确认：事件流不能替代阶段 | 已补常驻阶段导航，事件保留为详细记录 |
| Q2.03 | 确认：没有当前阶段高亮 | 已补当前阶段、角色、单元定位及等待/取消状态；浏览器核对运行中第 3/5 阶段与刷新后高亮 |
| Q2.04 | 确认：预算/覆盖计数不等于步骤 | 显示第 N/M 阶段；覆盖按实际已审计单元计数 |
| Q2.05 | 确认：源码缺少步骤导航 | 源码、二进制与动态任务均有阶段定义；单测通过 |
| Q2.06 | 确认显示缺口；接口已有 end_line，精简 code 不影响行范围 | 已补列表完整范围（含窄屏），浏览器核对 L5–L6 通过 |
| Q2.07 | 确认显示缺口；图节点已有路径/行号/地址 | 节点显示位置，悬停/下拉按需预览原文；浏览器切换预览通过 |
| Q2.08 | 确认：事件缺阶段身份 | 新事件持久化阶段 id/序号/总数；生命周期与浏览器“阶段 3/5”回归通过 |
| Q3.01 | 确认：顶层策略未显示 | 常驻规划面板直接显示 approach；源码与二进制浏览器实际显示通过 |
| Q3.02 | 原因误判：计划已持久化于 AgentTask.result，并经 result_json 返回 | 已补明确契约及可达展示；原 JSON 保留 |
| Q3.03 | 确认：优先级理由未显示 | 显示有序优先列表、理由及代码定位；核对源码 L1–L2 与二进制 0x 地址 |
| Q3.04 | 确认：用户需下载 JSON 阅读 | 直接显示策略、理由和限制，仍可下载原始证据；浏览器确认无需下载即可阅读 |
| Q3.05 | 确认：缺 typed 计划契约 | AgentTask.plan/AuditPlan/AuditPriority；从既有保存结果转换，测试通过 |
| Q3.06 | 确认：源码没有规划展示入口 | 源码与二进制使用同一顶层规划面板；实际 Ghidra 恢复→规划→刷新通过 |
| Q1.01 | 确认：复核反证被写死、待补信息为空 | 已补独立输入框，浏览器填写/保存/刷新/报告原值核对通过；双窗口旧草稿提交被拒且保留草稿，轮询不绕过 revision |
| Q1.02 | 确认：只能修改模型标注 | 已补 CreateAnnotation/ListAnnotations、结构任务可达入口、原文校验、修订历史和重复保护；隔离浏览器新建/修订/刷新/导出通过 |
| Q1.03 | 确认：人工标注未进入后续模型上下文 | 后续子任务读取同快照且代码完全相同的人工参考，保留来源与版本；浏览器先标注再创建审计，下载实际 PLANNER 请求核对引用；异快照隔离/引文校验通过，不自动重跑已有任务 |
| Q1.04 | 确认：缺跨发现复核总览 | 已补跨发现总览、待人工复核计数、状态队列、分页、最新复核与待补信息；实际调用 ListFindings/GetFinding，浏览器待人工复核 1→0 与修订记录通过 |
| Q1.05 | 确认：缺 PDF | 已补本机 Edge/Chrome 隔离排版（A4、中文字体、页码），真实 PDF 下载通过；4 页样本逐页渲染检查通过 |
| Q1.06 | 确认：GetReport 无界面入口 | 已补 ListReports/历史分页，下载实际调用 GetReport；浏览器导出后刷新、历史再次下载通过 |
| Q1.07 | 确认界面限制；服务端已允许运行中导出 | 开放阶段报告；记录数据时间/状态/是否阶段快照，旧报告不可变、并发幂等/取消后历史保留通过；浏览器在完成审计及人工修订后再下载旧快照，与初次导出完全一致 |
| Q5.01 | 确认：网页不能输入密钥 | 已补密码输入框；浏览器从未配置状态完成保存、检测、刷新，重开编辑不回填密钥，localStorage 无密钥 |
| Q5.02 | 确认：无配置写接口 | 已补 SaveModelSettings，共用会话/CSRF 保护；DPAPI 密文与幂等记录同事务保存，版本冲突/活动审计与检测锁定测试通过 |
| Q5.03 | 确认：无环境变量回退 | 已补本地配置→匹配地址的 AEGIS_MODEL_API_KEY→官方 DEEPSEEK_API_KEY 回退；隔离进程与独立浏览器实例验证实际来源及保留行为 |
| Q5.04 | 确认：endpoint 固定 | 已补 OpenAI 兼容接口、基础地址校验、禁跟随重定向、回环绕过代理；实际本地兼容提供方运行完整审计，浏览器核对更换地址不会沿用环境密钥 |
| Q5.05 | 确认：连接面板只读 | 已补编辑/保存/检测；浏览器检测成功并保留真实调用记录，活动审计期间禁止保存；CLI/托盘更新同一份加密配置 |

阶段必须反映实际编排：审计与复核按单元交替进行；验证方案生成不表示动态执行完成。恢复已完成子任务不应清零已完成进度，取消在进程回收确认前仍须显示取消中。阶段性报告是不可变的导出时快照。

原工作树中的 `crates/server/src/runtime.rs` 格式化和 `frontend/vite.config.ts` 代理变更属于先前修改，不纳入本次提交。

## 验证记录与复跑入口

| 检查 | 实际结果 | 复跑入口 |
| --- | --- | --- |
| Rust 常规测试 | 93 通过（含 domain 16、server 单测 7、生命周期 16） | `python scripts/aegis.py cargo test --workspace --locked -j 1` |
| Windows 原生工具 | 8 通过；实际 UPX、FLOSS、Semgrep、Ghidra、Git 与 Python→Rust DPAPI 互操作 | `python scripts/aegis.py cargo test --workspace --locked -j 1 native_ -- --ignored --test-threads=1` |
| PDF | 两个显式 PDF 测试通过；最新 4 页样本逐页渲染检查通过 | application 的 `local_browser_produces_real_pdf_and_reaps_its_processes`；lifecycle 的 `pdf_export_does_not_block_cancellation_and_preserves_a_factual_snapshot`，均加 `--ignored` |
| Python | 38 通过，包含 CLI/托盘加密配置兼容、活动任务保护、跨控制台正常停止与进程身份保护 | `python -m unittest discover -s tests -p 'test_*.py'` |
| 前端与契约 | Svelte 0 错误/警告、Prettier 通过、生产构建通过、codegen 可重复、Rust fmt/Clippy 通过 | `python scripts/manage.py check`（复跑总检查）；内存紧张时将 Cargo 构建任务数设为 1 |
| 浏览器 | 9 条完整流程通过，无跳过；1440 桌面与 390 窄屏截图检查；最后的窄屏标签/提示尺寸调整后，源码完整链路再次通过 | `python scripts/e2e.py --no-build --runtime`；定向复跑可加 `--grep 'web model'` |

[capabilities.spec.ts](../frontend/tests/capabilities.spec.ts) 验证网页配置→标注→后续真实模型请求载入人工参考→源码阶段和规划→阶段导出→活动任务配置锁→复核总览→双窗口冲突→刷新与报告历史；另有真实 Ghidra 二进制规划与独立环境变量实例。该测试使用 [e2e_model.py](../scripts/e2e_model.py) 的固定本地提供方，只验证产品流程，不衡量真实模型的审计效果。

[workspace.spec.ts](../frontend/tests/workspace.spec.ts) 验证源码行范围/调用图预览、四种报告格式与历史下载、文件夹导入、真实 Ghidra 的断线重连与取消、Windows VERIFY 的对照与重复观察、非法导入和审计预算表单。

[progress.rs](../crates/domain/src/progress.rs)、[lifecycle.rs](../crates/server/tests/lifecycle.rs) 和 [audit_behaviors.rs](../crates/server/tests/support/audit_behaviors.rs) 覆盖阶段恢复、审计/复核交替、引文强校验、取消与进程回收、幂等请求、人工标注版本及同快照隔离、不可变阶段报告。配置边界另见 [model_settings.rs](../crates/server/src/model_settings.rs)、[model.rs](../crates/application/src/model.rs) 与 [test_windows_launcher.py](../tests/test_windows_launcher.py)。

完整九流程的结果与截图归档在 `.data/verification/browser-full-results.json` 和 `.data/verification/browser-full-pass.zip`。最后一次源码链路复跑在 `.data/verification/browser-results.json`、`.data/verification/browser-model.json` 与 `frontend/test-results/`。原生和 PDF 证据在 `.data/verification/native-sast/` 与 `.data/verification/capability-report.pdf`。这些测试数据、截图与临时模型配置未纳入 Git，也不会写入实际工作区数据库。

原始清单与本登记的编号再次逐项比对：Q2 8 项、Q1 7 项、Q3 6 项、Q5 5 项，共 26 项；无遗漏、额外编号或重复。机器核对结果保存在 `.data/verification/checklist-coverage.json`。

## 走查额外修复与边界

- 双窗口实际操作暴露了直接打开任务链接时的会话初始化竞态：子组件在取得 CSRF 前发送 RPC，偶发 403。现在 RPC/上传等待共用的会话初始化；浏览器故意延迟会话响应，确认不再出现未授权请求。
- CLI/托盘改为更新同一个 SQLite 配置后，测试发现连接上下文未关闭导致 Windows 文件占用；已显式关闭连接，并验证失败不会覆盖已有配置。
- 实际服务更新发现 CLI 从另一个终端停止服务会报 Windows 参数错误（87）。现通过独立隐藏助手附着目标控制台，发送指定进程组的正常停止事件；原生测试确认目标正常退出、同控制台的其他进程继续运行，且拒绝身份已变化的 PID。实际服务停止也已成功。
- 新规划、复核、标注、报告和配置面板统一白底、字体令牌与正文内边距；窄屏内容可换行，表格与代码在各自区域内滚动。
- PDF 排版释放数据库写锁后进行；测试确认取消请求在 1 秒内完成，文件保留取消前快照。每次使用独立浏览器资料，Windows Job 回收子进程，45 秒超时，最多两个并发排版，禁止脚本和外部资源。`AEGIS_PDF_BROWSER` 可指定本机浏览器。
- 旧版无阶段字段的事件保留原始记录，不伪造历史阶段；当前阶段可从既有持久化任务重建。未执行的动态验证仍显示“未执行”，生成验证方案不等于已验证漏洞。
- 本机 `doctor`：Semgrep 1.176.1、Ghidra 12.1.3、FLOSS 3.1.1、UPX 5.2.1、Python 与 Zig 可用；IDA/Hex-Rays/D-810 未配置。真实付费模型未调用，未替用户保存任何真实密钥。
- Vite 保留 Monaco 等大包提示；本次不改变编辑器加载机制。并行编译与前端构建曾遇到本机内存不足，使用 `-j 1` 串行编译后原生回归通过。

## 本地服务更新与浏览器现场复核

- Release 工作区构建通过，实际服务已切换到新编译的控制服务和执行器。更新前确认没有活动任务或模型请求，并通过 SQLite 备份保留升级前数据库；迁移版本由 5 升至 6。
- 正式入口 `http://127.0.0.1:7331/` 和开发入口 `http://127.0.0.1:5173/` 的页面、会话、能力查询、项目列表与任务列表均返回 200。RPC 检查携带对应入口的 Origin 与真实会话/CSRF，执行器心跳在 1 秒内。
- 浏览器实际打开两个入口；正式环境的配置面板可打开，切换 OpenAI 兼容接口后地址和模型标识可编辑，API Key 使用 password 控件。临时编辑已取消并刷新确认，实际数据库未保存任何测试模型配置或模型调用。
- 正式页显示 Semgrep 1.176.1 可用、Windows 宿主 Python/Zig 均可用，执行器共有 9 项可用能力；IDA/Hex-Rays/D-810 未配置。实际模型凭据仍未配置，首次使用可从网页进入配置表单。
- 实际开发服务曾保留旧编译失败的 HMR 遮罩，即使当前组件请求已返回 200，浏览器仍显示旧错误。核实进程属于本工作区后重启 Vite；再次打开页面和刷新，遮罩消失且控制台无错误。此项是运行服务的旧状态，没有通过屏蔽错误遮罩规避检查。
- 现场核对正文为 14px 的系统/中文字体，侧栏使用浅灰色背景并与白色工作区分隔；1440 视口没有文档级横向溢出。临时视口设置已恢复。

升级与连通性回执：`.data/verification/local-service-upgrade.json`。升级前备份：`.data/verification/before-capability-upgrade-20260911-080023.sqlite`。

分批版本：`e928209`（阶段/规划/定位）、`a699558`（人工复核/标注/引用）、`4f4f3b6`（阶段报告/历史/PDF）、`38ff4ee`（网页模型配置与兼容接口）、`6623530`（跨终端正常停止服务）。最终浏览器回归、会话竞态修复及视觉收尾与本登记一起提交。
