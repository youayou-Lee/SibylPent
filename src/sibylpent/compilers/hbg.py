"""HackingBuddyGPT 运行时格式编译。

- hbg/playbook.py：``PLAYBOOK: dict[str, dict]``（id → entry.model_dump()），
  repr 输出可被 ast.literal_eval 回读——编译与校验两侧的硬约定；
- hbg/system_prompt.md：按类目分组的检查清单（LLM system prompt 片段，
  标题不深于 ``##``）。
"""

from sibylpent.compilers._shared import (
    GENERATED_MARKDOWN,
    GENERATED_PYTHON,
    checklist_sections,
)
from sibylpent.models import PlaybookEntry, ToolEntry

HBG_PLAYBOOK = "hbg/playbook.py"
HBG_SYSTEM_PROMPT = "hbg/system_prompt.md"


def compile_hbg(entries: list[PlaybookEntry], tools: list[ToolEntry]) -> dict[str, str]:
    """→ {hbg/playbook.py, hbg/system_prompt.md}（键为相对 --out 的路径）。

    tools 为接口预留参数：M0 的 HBG 产物暂不渲染工具信息（capability
    包装清单由 HBG 集成侧生成），当前不影响输出。
    """
    playbook = {entry.id: entry.model_dump() for entry in entries}
    playbook_py = "\n".join(
        [
            GENERATED_PYTHON,
            '"""HackingBuddyGPT playbook dict（编译自 knowledge/playbooks/*.yaml）。"""',
            "",
            f"PLAYBOOK = {playbook!r}",
            "",
        ]
    )
    prompt = [
        GENERATED_MARKDOWN,
        "# SibylPent Web 渗透检查清单（generic）",
        "",
        "以下每行是一个可独立执行的检查项；执行后按 expect_tags 归档现象证据，",
        "成立/否证判定依据见 playbook.py 中对应条目的 success/refute_criteria。",
        "",
    ]
    prompt += checklist_sections(entries, heading="##")
    return {HBG_PLAYBOOK: playbook_py, HBG_SYSTEM_PROMPT: "\n".join(prompt)}
