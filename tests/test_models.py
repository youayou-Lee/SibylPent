import pytest
from sibylpent.models import VulnEntry, PlaybookEntry, ToolEntry

def test_vuln_entry_minimal():
    e = VulnEntry(category="OA系统", product="泛微", name="RCE", entry_type="vuln")
    assert e.verified is False

def test_vuln_entry_type_rejects_unknown():
    with pytest.raises(Exception):
        VulnEntry(category="x", product="y", name="z", entry_type="exploit")

def test_playbook_entry_requires_tags():
    with pytest.raises(Exception):
        PlaybookEntry(id="GEN-001", domain="generic", category="authz",
                      check="c", how="h", expect_tags=[],
                      success_criteria="s", refute_criteria="r")
