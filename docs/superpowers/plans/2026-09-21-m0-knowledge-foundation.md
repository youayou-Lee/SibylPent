# M0 知识底座 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 SibylPent 知识底座——redteam_vul 解析器（typed vuln_index）、generic playbook 种子、工具目录、`sibylctl compile` 三格式编译流水线（HBG / CAI / Claude Code skill）与查询命令。

**Architecture:** 单一事实源 = `knowledge/` 下受 pydantic schema 约束的 YAML；解析器/编译器是纯函数式转换（README → YAML → 三格式产物）；CLI（argparse）串起 parse / query / compile / validate 四个子命令。`knowledge/` 入库，`gen/`（编译产物）gitignore。

**Tech Stack:** Python ≥3.12、uv、pydantic v2、PyYAML、pytest；不引入其他运行时依赖。

**Spec:** docs/PLAN.md（M0 行，§7 路线图）、docs/INTEGRATION.md（§2 解析器、§4 编译流水线、§5 决策点）。

## Global Constraints

- 包管理只用 uv（`uv add`、`uv run`）；requires-python = ">=3.12"
- 运行时依赖仅 `pydantic>=2` 与 `pyyaml`；CLI 用标准库 argparse
- 代码标识符用英文，注释/文档中文；commit 尾行 `Co-Authored-By: Claude Code <noreply@anthropic.com>`
- vuln_index 验收口径：**全部条目解析为 typed 记录或带理由显式跳过**，不做静默丢弃（数量守恒：解析数 + 跳过数 == README 中 `* ` 条目行数）
- 编译产物写 `gen/`（已 gitignore）；`knowledge/` 入库
- entry_type 四值：`vuln | tool | collection | placeholder`

## File Structure

```
SibylPent/
├── pyproject.toml                 # uv + hatchling；[project.scripts] sibylctl
├── src/sibylpent/
│   ├── __init__.py
│   ├── models.py                  # VulnEntry/PlaybookEntry/ToolEntry + ParseResult
│   ├── cli.py                     # argparse: parse-vul/query/compile/validate
│   ├── query.py                   # 产品/类目/版本过滤
│   ├── parsers/
│   │   ├── __init__.py
│   │   └── redteam_vul.py         # README → VulnEntry 列表 + skip 清单
│   └── compilers/
│       ├── __init__.py
│       ├── hbg.py                 # → gen/hbg/playbook.py + system_prompt.md
│       ├── cai.py                 # → gen/cai/instructions.md
│       └── cc_skill.py            # → gen/cc_skill/SKILL.md
├── tests/
│   ├── fixtures/redteam_vul_sample.md
│   ├── test_models.py
│   ├── test_parser_redteam_vul.py
│   ├── test_query.py
│   └── test_compile.py
└── knowledge/
    ├── vuln_index/*.yaml          # 解析产物（入库）
    ├── playbooks/generic.yaml     # 种子条目
    └── tools/catalog.yaml
```

---

### Task 1: 项目脚手架 + pydantic 数据模型

**Files:**
- Create: `pyproject.toml`
- Create: `src/sibylpent/__init__.py`、`src/sibylpent/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces（后续所有任务依赖这三个模型，字段名必须逐字一致）:

```python
# models.py
class VulnEntry(BaseModel):
    category: str            # 类目，如 "OA系统"
    product: str             # 产品，如 "通达OA(TongDa OA)"
    name: str                # 漏洞/条目名（README 里的链接文本）
    url: str | None          # 复现链接；占位条目为 None
    date: str | None         # "2021.01.07"
    cnvd_or_cve: str | None  # 从 name 中提取的 CNVD-/CVE- 编号
    affected_versions: str | None  # "影响版本X" 后缀文本
    entry_type: Literal["vuln", "tool", "collection", "placeholder"]
    notes: str | None        # 其余后缀（Thanks 等）
    verified: bool = False

class ParseResult(BaseModel):
    entries: list[VulnEntry]
    skipped: list[Skipped]   # Skipped: {raw_line: str, reason: str}

class PlaybookEntry(BaseModel):
    id: str                  # 如 "EC-014" / "GEN-003"
    domain: str              # generic | ecommerce | finance
    category: str            # 如 "recon" / "authz" / "payment"
    check: str               # 检查项描述
    how: str                 # 怎么测
    expect_tags: list[str]   # 现象词表 tag（PLAN §3.2 词表）
    success_criteria: str
    refute_criteria: str     # ≥N 条不同 verify 路径的描述（PLAN §5）

class ToolEntry(BaseModel):
    name: str
    url: str
    phase: str               # recon | scan | exploit | post
    category: str
    permission_tier: str     # recon | scan | exploit | destructive
    wrap_as: str             # capability | mcp | cli
```

- [ ] **Step 1:** `git init` 已有；创建 `pyproject.toml`：

```toml
[project]
name = "sibylpent"
version = "0.1.0"
description = "Evidence-first AI web pentest framework - knowledge foundation"
requires-python = ">=3.12"
dependencies = ["pydantic>=2", "pyyaml"]

[project.scripts]
sibylctl = "sibylpent.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/sibylpent"]

[tool.pytest.ini_options]
pythonpath = ["src"]
```

- [ ] **Step 2:** `uv sync`（生成 .venv 与 uv.lock）；`uv add pydantic pyyaml` 已含于 dependencies
- [ ] **Step 3:** 写 `tests/test_models.py`：

```python
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

```

注：`expect_tags: list[str] = Field(min_length=1)`，故空列表抛异常。

- [ ] **Step 4:** 运行 `uv run pytest tests/test_models.py -v`，Expected: FAIL（模块不存在）
- [ ] **Step 5:** 写 `src/sibylpent/models.py`（按上面 Interfaces 逐字段实现；`expect_tags` 用 `Field(min_length=1)`；`VulnEntry.url/date/cnvd_or_cve/affected_versions/notes` 均 `= None`；`Literal` 从 typing 导入）
- [ ] **Step 6:** 运行 `uv run pytest tests/test_models.py -v`，Expected: 3 PASS
- [ ] **Step 7:** Commit：`feat(m0): pydantic 数据模型与项目脚手架`

---

### Task 2: redteam_vul README 解析器

**Files:**
- Create: `src/sibylpent/parsers/__init__.py`（空文件）
- Create: `src/sibylpent/parsers/redteam_vul.py`
- Test: `tests/fixtures/redteam_vul_sample.md` + `tests/test_parser_redteam_vul.py`

**Interfaces:**
- Consumes: `models.VulnEntry`、`models.ParseResult`
- Produces:

```python
# parsers/redteam_vul.py
def parse_readme(text: str) -> ParseResult:
    """三层结构：## 类目 → > 产品 → * 条目。
    条目行五种变体（fixture 全覆盖）：
      1. 普通: * [date] - [name](url)
      2. 带版本: ... - 影响版本7.0/8.0
      3. 带备注: ... - Thanks:@user
      占位: * [date] - 暂无(...)
      工具: * [date] - ⚒️[name](url) 或 name 含 '合集' 的聚合页
    类目行 '## 一、OA系统' → category='OA系统'（剥掉序号前缀）。
    """

def count_entry_lines(text: str) -> int:
    """README 中以 '* ' 开头的条目行数（数量守恒校验用）。"""
```

- [ ] **Step 1:** 写 fixture `tests/fixtures/redteam_vul_sample.md`（真实 README 的浓缩样本，覆盖全部变体）：

```markdown
# 红队中易被攻击的一些重点系统漏洞整理

以下时间为更新时间，不代表漏洞发现时间.带 ⚒️图标的为工具URL.

## 一、OA系统

> 泛微(Weaver-Ecology-OA)

* [2021.01.07] - [泛微OA E-cology RCE(CNVD-2019-32204)](https://xz.aliyun.com/t/6560) - 影响版本7.0/8.0/8.1/9.0
* [2021.01.07] - [泛微OA云桥任意文件读取](https://www.cnblogs.com/yuzly/p/13677238.html) - 影响2018-2019 多个版本
* [2021.01.07] - [泛微OA工具⚒️](https://example.com/tool) ⚒️

> 蓝凌OA

* [2021.01.07] - 暂无(希望大佬能提供)

## 二、Web中间件

> Weblogic

* [2021.01.07] - [Weblogic历史漏洞合集](https://sploitus.com/) 
* [2021.01.08] - [Weblogic反序列化RCE](https://example.com/rce) - Thanks:@LandGrey
```

- [6 条目行 → 3 vuln + 1 placeholder + 1 tool + 1 collection；0 skipped]
- [ ] **Step 2:** 写 `tests/test_parser_redteam_vul.py`：

```python
from pathlib import Path
from sibylpent.parsers.redteam_vul import parse_readme, count_entry_lines

FIXTURE = Path("tests/fixtures/redteam_vul_sample.md").read_text()

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
```

- [ ] **Step 3:** 运行 `uv run pytest tests/test_parser_redteam_vul.py -v`，Expected: FAIL
- [ ] Step 4-6: 按测试实现 `parse_readme`/`count_entry_lines`（正则：条目行 `^\* \[(\d{4}\.\d{2}\.\d{2})\] - (.+)$`；链接 `\[([^\]]+)\]\(([^)]+)\)`；⚒️ → `tool`；`暂无` → `placeholder`；`合集`/sploitus → `collection`；`CNVD-\d+-\d+|CVE-\d+-\d+` 提取编号；后缀解析 `- 影响(版本)?([\d./<> ]+)$`）
- [ ] **Step 7:** Commit：`feat(m0): redteam_vul README 解析器（数量守恒 + typed 条目）`

---

### Task 3: 生成真实 vuln_index + 数量守恒验证 + query 命令

**Files:**
- Create: `src/sibylpent/query.py`
- Modify: `src/sibylpent/cli.py`（新增 `parse-vul` 与 `query` 子命令）
- Create: `knowledge/vuln_index/`（生成产物，入库）
- Test: `tests/test_query.py`

**Interfaces:**
- Consumes: Task 1 模型、Task 2 解析器
- Produces:

```python
# query.py
def load_index(dirpath: Path) -> list[VulnEntry]:
    """读 knowledge/vuln_index/*.yaml，按 pydantic 校验后返回。"""

def query(entries, product: str | None = None, category: str | None = None,
          version: str | None = None) -> list[VulnEntry]:
    """product 大小写不敏感子串匹配；version 为启发式 token 匹配
    （affected_versions 字符串中含该 token，如 '11.5' 命中 '<11.5版本 任意用户登录'）。
    version 语义是 M0 启发式，语义化版本区间解析挂 M1。"""
```

- [ ] **Step 1:** 写 `tests/test_query.py`（构造 3 条 VulnEntry 内存对象断言过滤逻辑；不依赖文件）：
- [ ] **Step 2:** 运行 Expected: FAIL → **Step 3:** 实现 `query.py` → **Step 4:** PASS
- [ ] **Step 5:** CLI 子命令 `parse-vul --src <README路径> --out knowledge/vuln_index`：解析真实 README（`/home/you/workspace/Penetration/redteam_vul/README.md`），写出按类目分文件 YAML + `_skipped.yaml`（带理由）+ `_report.md`（总数/typed 数/skip 数/**数量守恒断言：entries+skipped == count_entry_lines(README)**，不等则 exit 1）
- [ ] **Step 6:** 运行解析真实 README，核对 `_report.md`：117 条目行 → 全部 typed 或显式 skip，守恒断言通过
- [ ] **Step 7:** `uv run sibylctl query --product 通达 --version 11.5` 返回命中（通达OA 条目）
- [ ] **Step 8:** Commit：`feat(m0): vuln_index 生成 + 数量守恒校验 + query 子命令`

---
---

### Task 4: playbook 种子条目 + 工具目录

**Files:**
- Create: `knowledge/playbooks/generic.yaml`（6 条种子，源自 redteam-skill web-recon/web-attack）
- Create: `knowledge/tools/catalog.yaml`（Web 子集，源自 RedTeam-Tools）
- Modify: `src/sibylpent/models.py`（`expect_tags` 元素须在受控词表：加 validator）

**Interfaces:**
- Consumes: `models.PlaybookEntry`/`models.ToolEntry`
- Produces: 知识库 YAML（compile 的输入）；词表校验规则：

```python
CORE_TAGS = {"http_2xx","http_401","http_403","http_404","http_429","http_5xx",
             "timeout","dns_fail","tls_error","waf_block_page","redirect_external",
             "set_cookie","rate_limited"}
# body_diff/body_reflect ∈ CORE_TAGS 但记入 REQUIRES_BASELINE 集合（依赖基线机制，M1 网关检查）
# surface 前缀 tag 由领域包注册（generic.yaml 不用 surface:*，M2 电商包再加）

def validate_tags(tags) -> None:
    """expect_tags 中出现 CORE_TAGS 之外的 tag 时抛 ValueError（domain-pack 可扩展注册）。"""
```

- [ ] **Step 1:** 写 `knowledge/playbooks/generic.yaml`——6 条种子，每条含 `PlaybookEntry` 全字段，tags ∈ CORE_TAGS。内容规格（YAML 语法由执行者按 models.PlaybookEntry 写出）：

| id | category | check | expect_tags | success_criteria 要点 | refute_criteria 要点 |
|---|---|---|---|---|---|
| GEN-001 | recon | 识别 Web 服务器指纹（Server 头/X-Powered-By/favicon hash） | [http_2xx, http_404] | 唯一软件+版本假设，记 ASSET meta | ≥2 条路径（响应头+favicon hash）均无指纹特征 |
| GEN-002 | recon | 发现 API 端点（OpenAPI spec/sitemap/JS 提取路径） | [http_2xx] | 端点清单入 ASSET | spec+JS 提取两源独立均零端点 |
| GEN-003 | authz | 未授权访问敏感路径（裸访问 /admin、/api/*） | [http_401, http_403, http_2xx] | 无凭据可访问即成立 | 带凭据/无凭据/错误凭据三路径均有鉴权现象 |
| GEN-004 | injection | 反射探测：参数值回显到响应 | [body_reflect] | 反射点清单入 ASSET | 原样/URL 编码/HTML 实体三类全不反射 |
| GEN-005 | injection | 错误回显：触发异常页/堆栈 | [http_5xx, body_reflect] | 堆栈/框架信息入 ASSET meta | 常规+边界输入均无异常页 |
| GEN-006 | recon | 404 基线：先取不存在路径基准响应再判差异 | [http_404, body_diff] | 404 基线存 evidence/raw | 两次基线采样 SHA256 相同 |

- [ ] **Step 1 注:** body_reflect/body_diff 记入 REQUIRES_BASELINE 标记集（依赖基线机制，M1 网关检查其前置）；GEN-006 的 404 基线是 REQUIRES_BASELINE 首个消费者
- [ ] **Step 2:** 写 `knowledge/tools/catalog.yaml`——10 条真实工具（字段 name/url/phase/category/permission_tier/wrap_as）：nuclei、httpx、subfinder、gobuster、feroxbuster、gowitness、dismap、nmap(wrap_as=mcp)、SQLMap(permission_tier=exploit)、mitmproxy；URL 用官方仓库地址；档位按 INTEGRATION §3.2 映射
- [ ] **Step 3:** models.py 加受控词表 validator（expect_tags ⊆ CORE_TAGS；body_diff/body_reflect 记入 REQUIRES_BASELINE 集）
- [ ] **Step 4:** `uv run sibylctl validate --knowledge knowledge/` 全绿；`uv run pytest -v` 全绿
- [ ] **Step 5:** Commit：`feat(m0): generic playbook 种子与工具目录（词表校验）`

---

### Task 5: sibylctl compile 三格式编译

**Files:**
- Create: `src/sibylpent/compilers/__init__.py`、`hbg.py`、`cai.py`、`cc_skill.py`
- Test: `tests/test_compile.py`

**Interfaces:**
- Consumes: `models.PlaybookEntry`/`ToolEntry`/`VulnEntry`；`query.load_index`
- Produces:

```python
# compilers/hbg.py
def compile_hbg(entries: list[PlaybookEntry], tools: list[ToolEntry]) -> dict[str, str]:
    """返回 {filename: content}：
    gen/hbg/playbook.py  → PLAYBOOK: dict[str, dict]（id → entry 字段 dict，repr 输出可 import）
    gen/hbg/system_prompt.md → 按类目分组的检查清单（LLM system prompt 片段）"""

# compilers/cai.py
def compile_cai(entries, tools, vulns: list[VulnEntry]) -> dict[str, str]:
    """gen/cai/instructions.md：领域 agent 提示词（类目清单 + 工具档位 + 已知漏洞索引摘要）"""

# compilers/cc_skill.py
def compile_cc_skill(entries, tools, vulns) -> dict[str, str]:
    """gen/cc_skill/SKILL.md：YAML frontmatter（name/description）+ 分节清单"""
```

- [ ] **Step 1:** 写 `tests/test_compile.py`：构造 1 条 PlaybookEntry + 1 条 ToolEntry + 1 条 VulnEntry（内存对象），对三个 compiler 各断言：输出 dict 含正确文件名；内容含 id/名称字符串；playbook.py 输出能被 `ast.literal_eval` 解析（取 PLAYBOOK= 后的 dict 字面量）
- [ ] **Step 2:** FAIL → **Step 3:** 实现三个 compiler（模板字符串拼接，无第三方模板引擎）
- [ ] **Step 4:** `uv run pytest tests/test_compile.py -v` PASS
- [ ] **Step 5:** CLI `compile --knowledge knowledge/ --out gen/`：加载 YAML（pydantic 校验）→ 调三个 compiler → 写 `gen/{hbg,cai,cc_skill}/`；运行一次并抽查产物
- [ ] **Step 6:** Commit：`feat(m0): sibylctl compile 三格式编译流水线`

---

### Task 6: 收尾——验收 + 文档状态更新

**Files:**
- Modify: `README.md`（§6 状态：M0 完成 + 交付物清单）
- Test: 全量测试 + 验收清单

**Interfaces:**
- Produces: M0 验收证据清单（写入本 plan 的复选框）

- [ ] **Step 1:** 全量验证：`uv run pytest -v`（全部 PASS）
- [ ] **Step 2:** M0 验收对照（PLAN §7 M0 行）：
  - [x] `sibylctl compile` 跑通三格式产物（gen/hbg、gen/cai、gen/cc_skill 各有产出）
  - [x] vuln_index 全部条目 typed 或带理由显式跳过（_report.md 数量守恒断言通过）
  - [x] `sibylctl query --product 通达 --version 11.5` 命中通达OA条目
- [ ] **Step 3:** README §6 状态更新（M0 完成 + 指向 knowledge/ 与 sibylctl）+ INTEGRATION §5 决策点 5 处置注记（gen/ 已 gitignore 默认忽略）
- [ ] **Step 4:** Commit：`chore(m0): M0 验收通过，文档状态更新`
- [ ] **Step 5:** push 全部提交