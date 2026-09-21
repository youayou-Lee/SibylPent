"""Claude Code 运行时格式编译：gen/cc_skill/SKILL.md。"""

from sibylpent.compilers._shared import (
    GENERATED_MARKDOWN,
    checklist_sections,
    tool_table,
    vuln_summary_lines,
)
from sibylpent.models import PlaybookEntry, ToolEntry, VulnEntry

CC_SKILL = "cc_skill/SKILL.md"


def compile_cc_skill(
    entries: list[PlaybookEntry], tools: list[ToolEntry], vulns: list[VulnEntry]
) -> dict[str, str]:
    """→ {cc_skill/SKILL.md}：YAML frontmatter + Playbook/Tools/Known vulns 三节。

    内容源与 cai/instructions.md 相同（检查清单 / 工具表 / 漏洞摘要），
    按 Claude Code skill 的 markdown 习惯排版。frontmatter 必须是文件首行
    （Claude Code 只在 ``---`` 位于第一行时才解析 name/description），故本文件
    豁免首行生成标记：标记放在 frontmatter 结束的 ``---`` 之后（控制器裁定）。
    """
    lines = [
        "---",
        "name: sibylpent-generic",
        'description: "SibylPent generic Web 渗透：检查清单、工具档位与已知漏洞索引摘要"',
        "---",
        GENERATED_MARKDOWN,
        "",
        "# SibylPent Generic Web Pentest",
        "",
        "对目标执行证据优先的 Web 渗透检查；以下三节编译自 knowledge/ 知识库。",
        "",
        "## Playbook Checklist",
        "",
    ]
    lines += checklist_sections(entries)
    lines += ["## Tools", ""]
    lines += tool_table(tools)
    lines += ["", "## Known Vulns", ""]
    lines += vuln_summary_lines(vulns)
    lines.append("")
    return {CC_SKILL: "\n".join(lines)}
