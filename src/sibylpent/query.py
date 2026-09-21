"""vuln_index 查询：YAML 索引加载（pydantic 校验）与内存过滤。"""

from pathlib import Path

import yaml

from sibylpent.models import VulnEntry

# 目录内审计工件（Skipped 结构，非 VulnEntry），加载时跳过
_SKIPPED_FILENAME = "_skipped.yaml"


def load_index(dirpath: Path) -> list[VulnEntry]:
    """读 knowledge/vuln_index/*.yaml，按 pydantic 校验后返回。

    文件名排序保证加载顺序确定；数据不符 VulnEntry 模型时抛 ValidationError。
    """
    dirpath = Path(dirpath)
    if not dirpath.is_dir():
        raise FileNotFoundError(f"索引目录不存在: {dirpath}")
    entries: list[VulnEntry] = []
    for path in sorted(dirpath.glob("*.yaml")):
        if path.name == _SKIPPED_FILENAME:
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries.extend(VulnEntry.model_validate(item) for item in data or [])
    return entries


def query(
    entries: list[VulnEntry],
    product: str | None = None,
    category: str | None = None,
    version: str | None = None,
) -> list[VulnEntry]:
    """product 大小写不敏感子串匹配；version 为启发式 token 匹配
    （affected_versions 或 name 中含该 token——真实 README 的版本号大多写在
    条目名里，如 '11.5' 命中 name='通达OA <11.5版本 任意用户登录'）。
    version 语义是 M0 启发式，语义化版本区间解析挂 M1。"""
    hits = entries
    if product:
        p = product.lower()
        hits = [e for e in hits if p in e.product.lower()]
    if category:
        c = category.lower()
        hits = [e for e in hits if c in e.category.lower()]
    if version:
        hits = [
            e for e in hits
            if version in (e.affected_versions or "") or version in e.name
        ]
    return hits
