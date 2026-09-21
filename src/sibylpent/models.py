"""SibylPent 知识底座核心数据模型。

后续所有任务（README 解析、Playbook、工具清单）都依赖这里的模型，
字段名与类型以 M0 计划 Interfaces 为准，逐字一致。
"""

from typing import Literal

from pydantic import BaseModel, Field


class VulnEntry(BaseModel):
    category: str            # 类目，如 "OA系统"
    product: str             # 产品，如 "通达OA(TongDa OA)"
    name: str                # 漏洞/条目名（README 里的链接文本）
    url: str | None = None          # 复现链接；占位条目为 None
    date: str | None = None         # "2021.01.07"
    cnvd_or_cve: str | None = None  # 从 name 中提取的 CNVD-/CVE- 编号
    affected_versions: str | None = None  # "影响版本X" 后缀文本
    entry_type: Literal["vuln", "tool", "collection", "placeholder"]
    notes: str | None = None        # 其余后缀（Thanks 等）
    verified: bool = False


class Skipped(BaseModel):
    raw_line: str
    reason: str


class ParseResult(BaseModel):
    entries: list[VulnEntry]
    skipped: list[Skipped]


class PlaybookEntry(BaseModel):
    id: str                  # 如 "EC-014" / "GEN-003"
    domain: str              # generic | ecommerce | finance
    category: str            # 如 "recon" / "authz" / "payment"
    check: str               # 检查项描述
    how: str                 # 怎么测
    expect_tags: list[str] = Field(min_length=1)  # 现象词表 tag（PLAN §3.2 词表）
    success_criteria: str
    refute_criteria: str     # ≥N 条不同 verify 路径的描述（PLAN §5）


class ToolEntry(BaseModel):
    name: str
    url: str
    phase: str               # recon | scan | exploit | post
    category: str
    permission_tier: str     # recon | scan | exploit | destructive
    wrap_as: str             # capability | mcp | cli
