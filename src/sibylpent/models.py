"""SibylPent 知识底座核心数据模型。

后续所有任务（README 解析、Playbook、工具清单）都依赖这里的模型，
字段名与类型以 M0 计划 Interfaces 为准，逐字一致。
"""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

# ---- 现象受控词表（PLAN §3.2；Task 4 起为 expect_tags 的硬约束）----

#: M0 核心 tag 集：13 个现象 tag + body_reflect/body_diff，共 15 个。
#: surface:* 前缀 tag 由领域包在 M2 注册（M0 不入表，generic.yaml 不使用）。
CORE_TAGS: frozenset[str] = frozenset({
    "http_2xx", "http_401", "http_403", "http_404", "http_429", "http_5xx",
    "timeout", "dns_fail", "tls_error", "waf_block_page", "redirect_external",
    "set_cookie", "rate_limited", "body_reflect", "body_diff",
})

#: 依赖基线机制的 tag（M1 网关检查其前置，如 404 基线是否已采样）。
REQUIRES_BASELINE: frozenset[str] = frozenset({"body_reflect", "body_diff"})


def validate_tags(tags: list[str]) -> None:
    """expect_tags 中出现 CORE_TAGS 之外的 tag 时抛 ValueError（domain-pack 可扩展注册）。"""
    unknown = sorted(t for t in tags if t not in CORE_TAGS)
    if unknown:
        raise ValueError(f"tag 不在受控词表 CORE_TAGS: {', '.join(unknown)}")


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

    @field_validator("expect_tags")
    @classmethod
    def _expect_tags_in_core_vocab(cls, tags: list[str]) -> list[str]:
        validate_tags(tags)
        return tags


class ToolEntry(BaseModel):
    name: str
    url: str
    phase: str               # recon | scan | exploit | post
    category: str
    permission_tier: str     # recon | scan | exploit | destructive
    wrap_as: str             # capability | mcp | cli
