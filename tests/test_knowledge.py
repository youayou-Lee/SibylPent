"""Task 4：受控词表校验 + 知识库 YAML（generic playbook / 工具目录）加载。

Step 4 的验收（`sibylctl validate --knowledge knowledge/` 全绿）在此固化为测试：
两份 hand-authored YAML 必须能过 pydantic 模型与 validate_tags。
"""

from pathlib import Path

import pytest
import yaml
from pydantic import TypeAdapter, ValidationError

from sibylpent.cli import main
from sibylpent.models import (
    CORE_TAGS,
    REQUIRES_BASELINE,
    PlaybookEntry,
    ToolEntry,
    validate_tags,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = REPO_ROOT / "knowledge"

#: brief 的 13 个现象 tag（ruling 1：CORE_TAGS = 这 13 个 + body_reflect/body_diff）
BRIEF_13_TAGS = {
    "http_2xx", "http_401", "http_403", "http_404", "http_429", "http_5xx",
    "timeout", "dns_fail", "tls_error", "waf_block_page", "redirect_external",
    "set_cookie", "rate_limited",
}

TOOL_NAMES = {
    "nuclei", "httpx", "subfinder", "gobuster", "feroxbuster",
    "gowitness", "dismap", "nmap", "sqlmap", "mitmproxy",
}


def test_core_tags_is_expected_15():
    assert CORE_TAGS == BRIEF_13_TAGS | {"body_reflect", "body_diff"}
    assert len(CORE_TAGS) == 15


def test_validate_tags_accepts_all_core_tags():
    validate_tags(sorted(CORE_TAGS))  # 不抛异常即通过


def test_validate_tags_rejects_unknown_tag_naming_all_offenders():
    with pytest.raises(ValueError) as excinfo:
        validate_tags(["http_2xx", "surface:admin", "nope_tag"])
    msg = str(excinfo.value)
    assert "surface:admin" in msg
    assert "nope_tag" in msg


def test_requires_baseline_exactly_two_members():
    assert REQUIRES_BASELINE == {"body_reflect", "body_diff"}


def test_playbook_entry_rejects_tag_outside_vocab():
    with pytest.raises(ValidationError):
        PlaybookEntry(
            id="GEN-X", domain="generic", category="recon",
            check="c", how="h", expect_tags=["nonexistent_tag"],
            success_criteria="s", refute_criteria="r",
        )


def test_playbook_entry_accepts_requires_baseline_tags():
    entry = PlaybookEntry(
        id="GEN-006", domain="generic", category="recon",
        check="404 基线", how="h", expect_tags=["http_404", "body_diff"],
        success_criteria="s", refute_criteria="r",
    )
    assert entry.expect_tags == ["http_404", "body_diff"]


def test_generic_playbooks_load_and_pass_vocab():
    data = yaml.safe_load((KNOWLEDGE / "playbooks" / "generic.yaml").read_text("utf-8"))
    entries = TypeAdapter(list[PlaybookEntry]).validate_python(data)
    assert [e.id for e in entries] == [f"GEN-00{i}" for i in range(1, 7)]
    for e in entries:
        assert e.domain == "generic"
        validate_tags(e.expect_tags)


def test_tool_catalog_loads_with_ruled_tiers():
    data = yaml.safe_load((KNOWLEDGE / "tools" / "catalog.yaml").read_text("utf-8"))
    tools = TypeAdapter(list[ToolEntry]).validate_python(data)
    by_name = {t.name: t for t in tools}
    assert set(by_name) == TOOL_NAMES
    assert by_name["nmap"].wrap_as == "mcp"
    assert by_name["mitmproxy"].wrap_as == "cli"
    assert by_name["sqlmap"].permission_tier == "exploit"
    for t in tools:  # 档位与阶段取值受控（recon/scan/exploit）
        assert t.permission_tier in {"recon", "scan", "exploit", "destructive"}
        assert t.phase in {"recon", "scan", "exploit", "post"}


def test_cli_validate_passes_on_knowledge_dir():
    assert main(["validate", "--knowledge", str(KNOWLEDGE)]) == 0


def test_cli_validate_fails_on_unknown_tag(tmp_path):
    playbooks, tools = tmp_path / "playbooks", tmp_path / "tools"
    playbooks.mkdir()
    tools.mkdir()
    bad = {
        "id": "GEN-X", "domain": "generic", "category": "recon", "check": "c",
        "how": "h", "expect_tags": ["bogus_tag"],
        "success_criteria": "s", "refute_criteria": "r",
    }
    (playbooks / "bad.yaml").write_text(yaml.safe_dump([bad]), encoding="utf-8")
    (tools / "ok.yaml").write_text(
        yaml.safe_dump([{
            "name": "t", "url": "https://example.com", "phase": "recon",
            "category": "c", "permission_tier": "recon", "wrap_as": "capability",
        }]),
        encoding="utf-8",
    )
    assert main(["validate", "--knowledge", str(tmp_path)]) == 1
