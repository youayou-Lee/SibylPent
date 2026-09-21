"""CAI 运行时格式编译：gen/cai/instructions.md 领域 agent 提示词。"""

from sibylpent.compilers._shared import (
    GENERATED_MARKDOWN,
    checklist_sections,
    tool_table,
    vuln_summary_lines,
)
from sibylpent.models import PlaybookEntry, ToolEntry, VulnEntry

CAI_INSTRUCTIONS = "cai/instructions.md"


def compile_cai(
    entries: list[PlaybookEntry], tools: list[ToolEntry], vulns: list[VulnEntry]
) -> dict[str, str]:
    """→ {cai/instructions.md}：类目清单 + 工具档位表 + 已知漏洞索引摘要。"""
    lines = [
        GENERATED_MARKDOWN,
        "# SibylPent 领域 Agent 指令（generic Web 渗透）",
        "",
        "你是 SibylPent 的 Web 渗透测试领域 agent。以下三节内容编译自本地知识库",
        "（knowledge/）：执行检查时逐条引用条目 id，工具只在目标权限档位允许的",
        "范围内调用，命中已知漏洞条目时先查证影响版本再立假设。",
        "",
        "## 检查清单",
        "",
    ]
    lines += checklist_sections(entries)
    lines += [
        "## 工具目录（权限档位 recon < scan < exploit < destructive）",
        "",
    ]
    lines += tool_table(tools)
    lines += ["", "## 已知漏洞索引摘要", ""]
    lines += vuln_summary_lines(vulns)
    lines.append("")
    return {CAI_INSTRUCTIONS: "\n".join(lines)}
