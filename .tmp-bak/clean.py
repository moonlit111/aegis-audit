import pathlib

FILES = [
    "Docs/作品技术原理介绍.md",
    "Docs/概要设计报告.md",
    "Docs/详细设计报告-文字版.md",
    "Docs/测试分析报告.md",
]

ROOT = pathlib.Path(__file__).resolve().parent.parent


def clean(rel: str):
    p = ROOT / rel
    text = p.read_text(encoding="utf-8")
    before_bold = text.count("**")
    before_hr = sum(1 for l in text.split("\n") if l.strip() == "---")

    lines = text.split("\n")
    out = []
    in_fence = False
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(ln)
            continue
        if in_fence:
            out.append(ln)
            continue

        # 独立分隔线：删除（表格分隔行形如 | --- | --- |，不受影响）
        if ln.strip() == "---":
            continue

        # 文档头部元信息：前 15 行内的引用块转为普通行
        if i < 15 and ln.lstrip().startswith(">"):
            body = ln.lstrip()[1:].strip()
            if body:
                out.append(body)
            continue

        parts = ln.split("`")
        for j in range(0, len(parts), 2):
            parts[j] = parts[j].replace("**", "")
        ln = "`".join(parts)
        out.append(ln)

    new = "\n".join(out)
    # 压掉连续空行
    while "\n\n\n" in new:
        new = new.replace("\n\n\n", "\n\n")
    p.write_text(new, encoding="utf-8")
    return before_bold, new.count("**"), before_hr, sum(1 for l in new.split("\n") if l.strip() == "---")


for rel in FILES:
    b, a, hb, ha = clean(rel)
    print(f"{rel:<34} 粗体 {b:>4} -> {a:<4}  分隔线 {hb:>3} -> {ha}")
