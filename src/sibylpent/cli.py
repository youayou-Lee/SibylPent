"""sibylctl —— SibylPent 知识底座 CLI（argparse，无额外依赖）。

子命令:
  parse-vul  解析 redteam_vul README，生成按类目分文件的 YAML 索引
             + _skipped.yaml + _report.md；数量守恒不等则 exit 1
  query      按 product/category/version 过滤查询索引
  validate   校验知识库 YAML（playbooks/tools 过模型 + expect_tags 过词表）
  compile    编译知识库为三运行时格式（hbg/cai/cc_skill），写入 --out（默认 gen/）
"""

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import TypeVar
from urllib.parse import quote

import yaml
from pydantic import BaseModel, TypeAdapter, ValidationError

from sibylpent.compilers import compile_cai, compile_cc_skill, compile_hbg
from sibylpent.models import (
    ParseResult,
    PlaybookEntry,
    Skipped,
    ToolEntry,
    VulnEntry,
    validate_tags,
)
from sibylpent.parsers.redteam_vul import count_entry_lines, parse_readme
from sibylpent.query import load_index, query

DEFAULT_INDEX_DIR = Path("knowledge/vuln_index")
DEFAULT_KNOWLEDGE_DIR = Path("knowledge")
DEFAULT_OUT_DIR = Path("gen")

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sibylctl", description="SibylPent 知识底座工具")
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser("parse-vul", help="解析 redteam_vul README 生成 vuln_index")
    p_parse.add_argument("--src", type=Path, required=True, help="README.md 路径")
    p_parse.add_argument(
        "--out", type=Path, default=DEFAULT_INDEX_DIR, help="输出目录（默认 %(default)s）"
    )

    p_query = sub.add_parser("query", help="查询 vuln_index")
    p_query.add_argument(
        "--index-dir", type=Path, default=DEFAULT_INDEX_DIR, help="索引目录（默认 %(default)s）"
    )
    p_query.add_argument("--product", help="产品名子串（大小写不敏感）")
    p_query.add_argument("--category", help="类目子串（大小写不敏感）")
    p_query.add_argument("--version", help="版本号 token（M0 启发式子串匹配）")

    p_validate = sub.add_parser("validate", help="校验知识库 YAML（模型 + 受控词表）")
    p_validate.add_argument(
        "--knowledge",
        type=Path,
        default=DEFAULT_KNOWLEDGE_DIR,
        help="知识库根目录（默认 %(default)s）",
    )

    p_compile = sub.add_parser(
        "compile", help="编译知识库为三运行时格式（hbg / cai / cc_skill）"
    )
    p_compile.add_argument(
        "--knowledge",
        type=Path,
        default=DEFAULT_KNOWLEDGE_DIR,
        help="知识库根目录（默认 %(default)s）",
    )
    p_compile.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help="编译输出根目录（默认 %(default)s）",
    )

    args = parser.parse_args(argv)
    if args.command == "parse-vul":
        return _cmd_parse_vul(args.src, args.out)
    if args.command == "validate":
        return _cmd_validate(args.knowledge)
    if args.command == "compile":
        return _cmd_compile(args.knowledge, args.out)
    return _cmd_query(args.index_dir, args.product, args.category, args.version)


def _cmd_parse_vul(src: Path, out: Path) -> int:
    try:
        text = src.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"错误: 无法读取 {src}: {exc}", file=sys.stderr)
        return 2

    result = parse_readme(text)
    entry_lines = count_entry_lines(text)
    conserved = len(result.entries) + len(result.skipped) == entry_lines

    out.mkdir(parents=True, exist_ok=True)
    for stale in out.glob("*.yaml"):  # 目录整体由本命令生成，清掉旧类目文件保证幂等
        stale.unlink()
    category_files = _write_category_files(result.entries, out)
    _write_skipped(result.skipped, out)
    (out / "_report.md").write_text(
        _render_report(src, result, entry_lines, conserved, category_files),
        encoding="utf-8",
    )

    verdict = "PASS" if conserved else "FAIL"
    print(
        f"解析 {src}: {len(result.entries)} typed / {len(result.skipped)} skipped"
        f" / {entry_lines} entry lines；守恒断言 {verdict}；索引写入 {out}"
    )
    return 0 if conserved else 1


def _cmd_validate(knowledge: Path) -> int:
    """加载 playbooks/tools YAML，逐文件过模型与受控词表；任一错误 exit 1。"""
    specs = (
        (knowledge / "playbooks", PlaybookEntry, "playbook"),
        (knowledge / "tools", ToolEntry, "tool"),
    )
    ok = True
    file_count = 0
    entry_count = 0
    for directory, model, kind in specs:
        files = sorted(directory.glob("*.yaml"))
        if not files:
            print(f"错误: {directory} 下无 YAML 文件", file=sys.stderr)
            ok = False
            continue
        for path in files:
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                entries = TypeAdapter(list[model]).validate_python(raw)
                for entry in entries:  # 模型 validator 已强制；此处为词表规则的显式执行点
                    if isinstance(entry, PlaybookEntry):
                        validate_tags(entry.expect_tags)
            except (OSError, yaml.YAMLError, ValueError) as exc:
                print(f"错误: {path}: {exc}", file=sys.stderr)
                ok = False
                continue
            print(f"{path}: {len(entries)} 条 {kind} 条目")
            file_count += 1
            entry_count += len(entries)
    verdict = "PASS" if ok else "FAIL"
    print(f"知识库校验 {verdict}: {file_count} 个文件 / {entry_count} 条条目（{knowledge}）")
    return 0 if ok else 1


def _load_model_dir(directory: Path, model: type[_ModelT]) -> list[_ModelT]:
    """加载 directory/*.yaml → list[model]（pydantic 校验；文件名排序确定顺序）。

    目录缺失或无 YAML 文件时抛 FileNotFoundError，数据不符模型时抛
    ValidationError（ValueError 子类）——均由 _cmd_compile 统一转 exit 1。
    """
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise FileNotFoundError(f"{directory} 下无 YAML 文件")
    adapter = TypeAdapter(list[model])
    entries: list[_ModelT] = []
    for path in files:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries.extend(adapter.validate_python(raw))
    return entries


def _cmd_compile(knowledge: Path, out: Path) -> int:
    """加载三份知识源（pydantic 校验）→ 编译三格式 → 写 {out}/{hbg,cai,cc_skill}/。

    任一源加载/校验失败 exit 1；成功时逐文件打印写入路径与条目数。
    """
    try:
        playbook_entries = _load_model_dir(knowledge / "playbooks", PlaybookEntry)
        tools = _load_model_dir(knowledge / "tools", ToolEntry)
        vulns = load_index(knowledge / "vuln_index")
    except (OSError, yaml.YAMLError, ValueError) as exc:
        print(f"错误: 知识库加载/校验失败: {exc}", file=sys.stderr)
        return 1

    outputs: dict[str, str] = {}
    for compiled in (
        compile_hbg(playbook_entries, tools),
        compile_cai(playbook_entries, tools, vulns),
        compile_cc_skill(playbook_entries, tools, vulns),
    ):
        outputs.update(compiled)

    full_counts = (
        f"{len(playbook_entries)} playbook / {len(tools)} tools / {len(vulns)} vulns"
    )
    counts = {
        "hbg/playbook.py": f"{len(playbook_entries)} playbook",
        "hbg/system_prompt.md": f"{len(playbook_entries)} playbook",
        "cai/instructions.md": full_counts,
        "cc_skill/SKILL.md": full_counts,
    }
    for rel_path in sorted(outputs):
        target = out / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(outputs[rel_path], encoding="utf-8")
        print(f"写入 {target}（{counts[rel_path]}）")
    print(f"编译完成: {len(outputs)} 个文件 ← {full_counts}（{knowledge}）")
    return 0


def _cmd_query(
    index_dir: Path, product: str | None, category: str | None, version: str | None
) -> int:
    try:
        entries = load_index(index_dir)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        print(f"错误: 无法加载索引 {index_dir}: {exc}", file=sys.stderr)
        return 2
    hits = query(entries, product=product, category=category, version=version)
    for e in hits:
        print(f"[{e.entry_type}] {e.category} / {e.product}: {e.name}")
        if e.url:
            print(f"    {e.url}")
        if e.affected_versions:
            print(f"    affected: {e.affected_versions}")
    print(f"共 {len(hits)} 条命中（索引 {len(entries)} 条）")
    return 0


def _write_category_files(
    entries: list[VulnEntry], out: Path
) -> list[tuple[str, str, int]]:
    """按 category 分文件写 YAML，返回 (文件名, 类目, 条目数) 供报告引用。"""
    grouped: dict[str, list[VulnEntry]] = {}
    for e in entries:
        grouped.setdefault(e.category, []).append(e)
    summary: list[tuple[str, str, int]] = []
    for category, cat_entries in grouped.items():
        filename = (quote(category, safe="") or "uncategorized") + ".yaml"
        header = f"# 类目: {category}\n# 条目数: {len(cat_entries)}\n"
        body = yaml.safe_dump(
            [e.model_dump() for e in cat_entries],
            allow_unicode=True,
            sort_keys=False,
            width=10_000,
        )
        (out / filename).write_text(header + body, encoding="utf-8")
        summary.append((filename, category, len(cat_entries)))
    return summary


def _write_skipped(skipped: list[Skipped], out: Path) -> None:
    header = f"# 未识别条目行（含理由），共 {len(skipped)} 条\n"
    body = yaml.safe_dump(
        [s.model_dump() for s in skipped], allow_unicode=True, sort_keys=False
    )
    (out / "_skipped.yaml").write_text(header + body, encoding="utf-8")


def _render_report(
    src: Path,
    result: ParseResult,
    entry_lines: int,
    conserved: bool,
    category_files: list[tuple[str, str, int]],
) -> str:
    by_type = Counter(e.entry_type for e in result.entries)
    verdict = "PASS" if conserved else "FAIL"
    lines = [
        "# vuln_index 生成报告",
        "",
        f"- 源文件: `{src}`",
        f"- 条目行总数（count_entry_lines）: {entry_lines}",
        f"- typed 条目: {len(result.entries)}",
    ]
    for t in ("vuln", "tool", "collection", "placeholder"):
        lines.append(f"  - {t}: {by_type.get(t, 0)}")
    lines += [
        f"- skipped: {len(result.skipped)}",
        f"- 数量守恒断言: entries({len(result.entries)})"
        f" + skipped({len(result.skipped)})"
        f" == entry_lines({entry_lines}) → **{verdict}**",
        "",
        "## 按类目分布",
        "",
        "| 文件 | 类目 | 条目数 |",
        "| --- | --- | --- |",
    ]
    lines += [f"| `{fname}` | {cat} | {n} |" for fname, cat, n in category_files]
    lines.append(f"| `_skipped.yaml` | （未识别） | {len(result.skipped)} |")
    lines.append("")
    return "\n".join(lines)
