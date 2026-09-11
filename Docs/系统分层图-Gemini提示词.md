# AegisAudit 系统分层图 —— Gemini 生图提示词（简洁风格）

> 配合《作品技术原理介绍》3.1 节「系统分层」。**简洁优先**：每层只保留标题 + 3–4 个关键词，去掉长句。

---

## 中文提示词（直接复制）

生成一张**极简风格的四层系统架构图**，横向卡片自上而下堆叠，扁平化、大量留白、线条细、配色克制（深蓝主色 + 青绿、橙黄点缀），浅灰背景、白色圆角卡片、轻阴影。中文文字清晰、不糊、不重叠。

**第一层（浅蓝）**：Svelte 浏览器 · 工作台 UI
标签：项目 · 导入 · 任务 · 发现 · 报告

**第二层（深蓝）**：Rust 控制服务 · Axum / Tokio / SQLx
标签：状态机 · 多智能体编排 · 工作队列 · SQLite

**第三层（青绿）**：Windows 执行器（多实例）
标签：Tree-sitter · Ghidra · Semgrep · UPX · FLOSS

**第四层（橙黄）**：DeepSeek API · 模型审计

**箭头（居中、竖直、带小标签）**：
1→2：Connect RPC
2→3：领任务 / 回报证据
3→4：HTTPS

**风格**：极简工程示意，文字尽量少，关键词用圆角小标签（pill）呈现；不要人物、机器人、大脑、3D 渲染、水印或多余装饰。比例 4:3。右上角小字标题「AegisAudit 系统分层」。

---

## English prompt（推荐，Gemini 遵循更稳）

A **minimalist four-layer system architecture diagram**, wide horizontal cards stacked top-to-bottom, connected by short vertical arrows. Flat design, lots of white space, thin strokes, light gray background, white rounded cards with subtle shadow, restrained palette: deep blue primary with teal-green and warm orange accents. Aspect ratio 4:3. Small title at top-right: "AegisAudit 系统分层".

**Layer 1 (light blue)** — "Svelte 浏览器 · 工作台 UI": chips reading 项目 · 导入 · 任务 · 发现 · 报告.

**Layer 2 (deep blue)** — "Rust 控制服务 · Axum / Tokio / SQLx": chips reading 状态机 · 多智能体编排 · 工作队列 · SQLite.

**Layer 3 (teal-green)** — "Windows 执行器（多实例）": chips reading Tree-sitter · Ghidra · Semgrep · UPX · FLOSS.

**Layer 4 (orange)** — "DeepSeek API · 模型审计".

**Arrow labels**: 1→2 "Connect RPC" · 2→3 "领任务 / 回报证据" · 3→4 "HTTPS".

**Style**: ultra-clean technical schematic, minimal words, keywords as small rounded pill chips. No people, no robots, no brain art, no 3D, no watermark, no extra decoration. All Chinese text crisp and legible.

---

## 若中文乱码，用全英文版

Minimalist 4-layer architecture diagram, 4:3, light background, flat style.
Four wide rounded cards stacked vertically with short labeled arrows.

1. (light blue) "Svelte Browser · Workbench UI" — chips: Projects · Import · Tasks · Findings · Report
2. (deep blue) "Rust Control Service · Axum / Tokio / SQLx" — chips: State Machine · Multi-Agent Orchestration · Work Queue · SQLite
3. (teal-green) "Windows Executor (multi-instance)" — chips: Tree-sitter · Ghidra · Semgrep · UPX · FLOSS
4. (orange) "DeepSeek API · Model Audit"

Arrow labels: "Connect RPC" · "Claim / Report Evidence" · "HTTPS".
Ultra-clean, minimal text, keyword pill chips, no people/robots/3D/watermark. Title top-right: "AegisAudit System Layering".
