from pathlib import Path

import pytest
from pydantic import ValidationError

from sibylpent.models import VulnEntry
from sibylpent.parsers.redteam_vul import count_entry_lines, parse_readme

FIXTURE = (
    Path(__file__).parent / "fixtures" / "redteam_vul_sample.md"
).read_text(encoding="utf-8")

# 真实 README 的字节级摘录：条目分隔符是非断行空格（'] \xa0- \xa0['）
REAL_EXCERPT = (
    Path(__file__).parent / "fixtures" / "redteam_vul_real_excerpt.md"
).read_text(encoding="utf-8")


def test_count_conservation():
    assert count_entry_lines(FIXTURE) == 6


def test_parses_vuln_with_cnvd_and_versions():
    e = parse_readme(FIXTURE).entries[0]
    assert e.entry_type == "vuln"
    assert e.cnvd_or_cve == "CNVD-2019-32204"
    assert e.affected_versions == "7.0/8.0/8.1/9.0"


def test_entry_type_mix():
    types = sorted(e.entry_type for e in parse_readme(FIXTURE).entries)
    assert types == ["collection", "placeholder", "tool"] + ["vuln"] * 3


def test_product_and_category_flow_into_entries():
    es = parse_readme(FIXTURE).entries
    assert es[0].product == "泛微(Weaver-Ecology-OA)" and es[0].category == "OA系统"
    assert es[-1].product == "Weblogic"


def test_entries_plus_skipped_equals_entry_lines():
    result = parse_readme(FIXTURE)
    assert result.skipped == []
    assert len(result.entries) + len(result.skipped) == count_entry_lines(FIXTURE)


def test_placeholder_entry_has_no_url():
    e = parse_readme(FIXTURE).entries[3]
    assert e.entry_type == "placeholder"
    assert e.url is None
    assert e.date == "2021.01.07"
    assert "暂无" in e.name
    assert e.product == "蓝凌OA"
    assert e.category == "OA系统"


def test_collection_via_sploitus_and_heji():
    e = parse_readme(FIXTURE).entries[4]
    assert e.entry_type == "collection"
    assert e.name == "Weblogic历史漏洞合集"
    assert e.url == "https://sploitus.com/"
    assert e.category == "Web中间件"


def test_notes_from_thanks_suffix():
    e = parse_readme(FIXTURE).entries[5]
    assert e.entry_type == "vuln"
    assert e.notes == "Thanks:@LandGrey"
    assert e.affected_versions is None
    assert e.cnvd_or_cve is None
    assert e.date == "2021.01.08"


def test_affected_versions_without_version_word():
    e = parse_readme(FIXTURE).entries[1]
    assert e.affected_versions == "2018-2019 多个版本"


def test_tool_entry_icon_suffix_not_a_note():
    e = parse_readme(FIXTURE).entries[2]
    assert e.entry_type == "tool"
    assert e.notes is None


def test_vuln_entry_type_literal_enforced():
    with pytest.raises(ValidationError):
        VulnEntry(category="x", product="y", name="z", entry_type="exploit")


def test_real_excerpt_keeps_nbsp_bytes():
    # fixture 是真实文件的字节级拷贝，未把 NBSP 静默归一化成普通空格
    assert REAL_EXCERPT.count("\xa0") == 8


def test_real_excerpt_nbsp_entries_parse_as_vuln():
    result = parse_readme(REAL_EXCERPT)
    assert len(result.entries) + len(result.skipped) == count_entry_lines(REAL_EXCERPT)
    assert len(result.entries) == 4
    assert result.skipped == []
    first = result.entries[0]
    assert first.entry_type == "vuln"
    assert first.name == "泛微OA E-cology RCE(CNVD-2019-32204)"
    assert first.cnvd_or_cve == "CNVD-2019-32204"
    assert first.affected_versions == "7.0/8.0/8.1/9.0"
    assert first.category == "OA系统"
    assert first.product == "泛微(Weaver-Ecology-OA)"
    assert result.entries[3].affected_versions == "2018-2019 多个版本"


def test_indented_bullet_conservation():
    text = (
        "## 一、OA系统\n"
        "\n"
        "> 泛微\n"
        "\n"
        "  * [2021.01.07] - [缩进条目RCE](https://example.com/x)\n"
    )
    assert count_entry_lines(text) == 1
    result = parse_readme(text)
    assert len(result.entries) == 1
    assert len(result.entries) + len(result.skipped) == count_entry_lines(text)
    assert result.entries[0].name == "缩进条目RCE"
