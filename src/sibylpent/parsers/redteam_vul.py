"""redteam_vul README 解析器。

README 为三层 markdown：`## 类目` → `> 产品` → `* 条目`。
产出 typed 的 ``VulnEntry`` 列表与未识别条目行的 ``Skipped`` 列表，
数量守恒：len(entries) + len(skipped) == count_entry_lines(text)。
"""

import re

from sibylpent.models import ParseResult, Skipped, VulnEntry

# 条目行：* [2021.01.07] - <rest>
_ENTRY_RE = re.compile(r"^\* \[(\d{4}\.\d{2}\.\d{2})\] - (.+)$")
# 类目行：## 一、OA系统 → 剥掉 CJK 序号前缀（一、二、…）
_CATEGORY_RE = re.compile(r"^##(?!#)\s*(?:[一二三四五六七八九十]+\s*、\s*)?(.+?)\s*$")
# 产品行：> 泛微(Weaver-Ecology-OA)
_PRODUCT_RE = re.compile(r"^>\s*(.+?)\s*$")
# 条目内链接：[name](url)
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
# 链接文本中的 CNVD-/CVE- 编号
_ID_RE = re.compile(r"CNVD-\d+-\d+|CVE-\d+-\d+")
# 影响版本后缀：影响 / 影响版本 <版本范围>
_AFFECTED_RE = re.compile(r"^影响(?:版本)?\s*(.+)$")

# ⚒️ 工具图标（U+2692，可带 U+FE0F 变体选择符）
_TOOL_ICON = "⚒"


def parse_readme(text: str) -> ParseResult:
    """三层结构：## 类目 → > 产品 → * 条目。
    条目行五种变体（fixture 全覆盖）：
      1. 普通: * [date] - [name](url)
      2. 带版本: ... - 影响版本7.0/8.0
      3. 带备注: ... - Thanks:@user
      占位: * [date] - 暂无(...)
      工具: * [date] - ⚒️[name](url) 或 name 含 '合集' 的聚合页
    类目行 '## 一、OA系统' → category='OA系统'（剥掉序号前缀）。
    """
    entries: list[VulnEntry] = []
    skipped: list[Skipped] = []
    category = ""
    product = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _CATEGORY_RE.match(line)
        if m:
            category = m.group(1)
            product = ""
            continue
        m = _PRODUCT_RE.match(line)
        if m:
            product = m.group(1)
            continue
        if line.startswith("* "):
            em = _ENTRY_RE.match(line)
            if em is None:
                skipped.append(
                    Skipped(
                        raw_line=raw_line,
                        reason="条目行不匹配 '* [YYYY.MM.DD] - ...' 格式",
                    )
                )
                continue
            entries.append(_build_entry(em.group(1), em.group(2), category, product))
    return ParseResult(entries=entries, skipped=skipped)


def count_entry_lines(text: str) -> int:
    """README 中以 '* ' 开头的条目行数（数量守恒校验用）。"""
    return sum(1 for line in text.splitlines() if line.startswith("* "))


def _build_entry(date: str, rest: str, category: str, product: str) -> VulnEntry:
    link = _LINK_RE.search(rest)
    if link:
        name, url = link.group(1), link.group(2)
        remainder = (rest[: link.start()] + " " + rest[link.end() :]).strip()
        remainder = remainder.lstrip("-").strip()  # 去掉首个 ' - ' 分隔符残留
        affected_versions, notes = _parse_suffixes(remainder)
    else:  # 占位等无链接条目
        name, url = rest.strip(), None
        affected_versions, notes = None, None
    id_match = _ID_RE.search(name)
    return VulnEntry(
        category=category,
        product=product,
        name=name,
        url=url,
        date=date,
        cnvd_or_cve=id_match.group(0) if id_match else None,
        affected_versions=affected_versions,
        entry_type=_detect_type(rest, name, url),
        notes=notes,
    )


def _detect_type(rest: str, name: str, url: str | None) -> str:
    if _TOOL_ICON in rest:  # ⚒️ 出现即工具
        return "tool"
    if "暂无" in rest:
        return "placeholder"
    if "合集" in name or "sploitus" in (url or "").lower():
        return "collection"
    return "vuln"


def _parse_suffixes(remainder: str) -> tuple[str | None, str | None]:
    """链接之后以 ' - ' 分隔的后缀：影响(版本)?X → affected_versions，其余 → notes。"""
    affected: str | None = None
    notes: list[str] = []
    for part in remainder.split(" - "):
        part = part.strip()
        if not part or part in (_TOOL_ICON, _TOOL_ICON + "\ufe0f"):
            continue  # 纯工具图标是类型标记，不算备注
        m = _AFFECTED_RE.match(part)
        if m:
            affected = m.group(1).strip()
        else:
            notes.append(part)
    return affected, " - ".join(notes) if notes else None
