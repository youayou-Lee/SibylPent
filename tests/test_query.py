"""query 过滤逻辑（内存对象，不依赖文件）+ load_index YAML 回环 + CLI 守恒行为。"""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from sibylpent.cli import main
from sibylpent.models import ParseResult, VulnEntry
from sibylpent.parsers.redteam_vul import parse_readme
from sibylpent.query import load_index, query

MINI_FIXTURE = (
    Path(__file__).parent / "fixtures" / "redteam_vul_mini.md"
).read_text(encoding="utf-8")


def _entry(
    product: str,
    *,
    category: str = "OA系统",
    name: str = "某产品RCE",
    affected: str | None = None,
    entry_type: str = "vuln",
) -> VulnEntry:
    return VulnEntry(
        category=category,
        product=product,
        name=name,
        entry_type=entry_type,
        affected_versions=affected,
    )


def _sample_entries() -> list[VulnEntry]:
    # 第一条镜像真实 README：版本 token 只出现在 name（affected_versions=None）
    return [
        _entry("通达OA(TongDa OA)", name="通达OA <11.5版本 任意用户登录"),
        _entry("泛微(Weaver-Ecology-OA)", name="泛微OA E-cology RCE", affected="7.0/8.0/8.1/9.0"),
        _entry("致远(Seeyon)", category="E-mail", name="致远OA A8 getshell"),
    ]


# ---------- query()：内存过滤 ----------


def test_query_no_filter_returns_all():
    assert query(_sample_entries()) == _sample_entries()


def test_query_product_case_insensitive_substring():
    entries = _sample_entries()
    assert [e.name for e in query(entries, product="通达")] == ["通达OA <11.5版本 任意用户登录"]
    assert [e.name for e in query(entries, product="TONGDA")] == ["通达OA <11.5版本 任意用户登录"]


def test_query_product_substring_matches_partial():
    # 'OA' 是子串：命中 通达OA(...) 与 泛微(...OA)，不命中 致远(Seeyon)
    hits = query(_sample_entries(), product="oa")
    assert [e.product for e in hits] == ["通达OA(TongDa OA)", "泛微(Weaver-Ecology-OA)"]


def test_query_version_token_in_affected_versions():
    hits = query(_sample_entries(), version="8.0")
    assert [e.name for e in hits] == ["泛微OA E-cology RCE"]


def test_query_version_token_in_name_when_affected_missing():
    # 真实 README 形态：'11.5' 只在 name，不在 affected_versions
    hits = query(_sample_entries(), version="11.5")
    assert [e.name for e in hits] == ["通达OA <11.5版本 任意用户登录"]


def test_query_version_no_match_returns_empty():
    assert query(_sample_entries(), version="99.9") == []


def test_query_category_case_insensitive_substring():
    assert [e.category for e in query(_sample_entries(), category="E-mail")] == ["E-mail"]
    assert [e.category for e in query(_sample_entries(), category="e-mail")] == ["E-mail"]
    assert len(query(_sample_entries(), category="OA")) == 2  # 'OA系统' 子串


def test_query_filters_combine_with_and():
    entries = _sample_entries()
    assert len(query(entries, product="泛微", version="8.0")) == 1
    assert query(entries, product="通达", version="8.0") == []


# ---------- load_index()：YAML → pydantic 校验 ----------


def test_load_index_missing_dir_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_index(tmp_path / "nope")


def test_load_index_ignores_skipped_and_non_yaml(tmp_path):
    # 只有 _skipped.yaml（Skipped 结构，非 VulnEntry）时应安全返回空
    (tmp_path / "_skipped.yaml").write_text(
        yaml.safe_dump([{"raw_line": "* bad", "reason": "格式不符"}]), encoding="utf-8"
    )
    assert load_index(tmp_path) == []


def test_load_index_rejects_invalid_entry_type(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        yaml.safe_dump(
            [{"category": "x", "product": "y", "name": "z", "entry_type": "exploit"}]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_index(tmp_path)


# ---------- CLI：parse-vul 生成 + 数量守恒 ----------


def test_cli_parse_vul_generates_index_and_conserves(tmp_path):
    rc = main(["parse-vul", "--src", str(_fixture_path()), "--out", str(tmp_path)])
    assert rc == 0

    yamls = sorted(p.name for p in tmp_path.glob("*.yaml"))
    assert yamls == [
        "E-mail.yaml",
        "OA%E7%B3%BB%E7%BB%9F.yaml",  # 'OA系统' percent-encode 后的安全文件名
        "_skipped.yaml",  # ASCII 排序：'_' 大于大写字母
    ]
    assert (tmp_path / "_report.md").read_text(encoding="utf-8").count("PASS") >= 1

    # 回环：load_index 经 pydantic 校验后还原出与解析器相同的条目
    parsed = sorted(parse_readme(MINI_FIXTURE).entries, key=lambda e: e.name)
    loaded = sorted(load_index(tmp_path), key=lambda e: e.name)
    assert [e.model_dump() for e in loaded] == [e.model_dump() for e in parsed]


def test_cli_parse_vul_report_has_type_breakdown(tmp_path):
    rc = main(["parse-vul", "--src", str(_fixture_path()), "--out", str(tmp_path)])
    assert rc == 0
    report = (tmp_path / "_report.md").read_text(encoding="utf-8")
    assert "条目行总数（count_entry_lines）: 3" in report
    assert "- vuln: 2" in report
    assert "- tool: 1" in report
    assert "- skipped: 0" in report


def test_cli_parse_vul_conservation_mismatch_exits_1(tmp_path, monkeypatch):
    # 守恒断言是安全网：解析器若与 count_entry_lines 脱钩必须 exit 1。
    # 真实数据下两者按构造恒等，故用 monkeypatch 注入不守恒的结果。
    monkeypatch.setattr(
        "sibylpent.cli.parse_readme", lambda text: ParseResult(entries=[], skipped=[])
    )
    rc = main(["parse-vul", "--src", str(_fixture_path()), "--out", str(tmp_path)])
    assert rc == 1
    assert "FAIL" in (tmp_path / "_report.md").read_text(encoding="utf-8")


def test_cli_query_reads_generated_index(tmp_path, capsys):
    assert main(["parse-vul", "--src", str(_fixture_path()), "--out", str(tmp_path)]) == 0
    rc = main(["query", "--index-dir", str(tmp_path), "--product", "通达", "--version", "11.5"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "通达OA <11.5版本 任意用户登录" in out
    assert "共 1 条命中" in out


def _fixture_path() -> Path:
    return Path(__file__).parent / "fixtures" / "redteam_vul_mini.md"
