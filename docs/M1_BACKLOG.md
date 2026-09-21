# M0 遗留 → M1 待办清单

> 来源：M0 全分支终审（opus）+ PR #2 正式评审。本文件是 M1 计划的强制输入：M1 实现计划必须逐项给出处置（修入 / 显式再挂起并说明理由），不允许静默消失。
> 台账版本存于 SDD 工作区（已删），本文件为唯一权威记录。

## 承载性（必须 M1 处置）

| # | 项 | 位置 | 说明 |
|---|---|---|---|
| F2 | **注入通道** | `src/sibylpent/compilers/_shared.py:52,66,84-86` | 上游可控文本（漏洞条目名等）未转义内插进 LLM 消费的 SKILL.md/instructions.md；parse-vul 自动摄入第三方 README，M1 加入 LLM 消费者后即成指令注入入口。处置：knowledge 文本当数据——转义 / 截断 / 隔离引用 |
| B1 | playbook id 唯一性 | `cli.py` validate / `_load_model_dir` | 跨文件重复 id 在 PLAYBOOK 中静默折叠（后写胜出）；须在 M2 领域包之前加查重 |
| B2 | M1 网关豁免类与退出码约定 | `src/sibylpent/cli.py` | 同类失败退出码不一致：query 载入失败=2（cli.py:216）vs compile=1（cli.py:181）；M1 定一套约定全 CLI 统一 |

## 一致性 / 健壮性（M1 顺手修）

| # | 项 | 位置 | 说明 |
|---|---|---|---|
| C1 | query version 语义收窄 | `src/sibylpent/query.py:36-51` | 现为 affected_versions OR name 的 token 子串启发式（M0 裁定）；M1 收窄为语义化版本区间或文档化边界 |
| C2 | 词表未在模型层强制 | `src/sibylpent/models.py:57,74-78` | ToolEntry.phase/permission_tier/wrap_as、PlaybookEntry.domain 为裸 str，typo 可过 validate；照 entry_type 的 Literal 先例补齐 |
| C3 | `load_index` 标量崩溃 | `src/sibylpent/query.py:26` | 真值非迭代标量（如 `42`）→ TypeError 逃过捕获表裸 traceback；加 isinstance(data, list) |
| C4 | `_report.md` 绝对路径 | `knowledge/vuln_index/_report.md:4` | 嵌机器路径 → 跨 checkout 再生产生伪 diff；改 repo-relative |
| C5 | validate 覆盖面 | `cli.py:123-126` | 未覆盖 knowledge/vuln_index/；validate 加载之或注释说明分工 |
| C6 | `*.yml` 静默忽略 | `cli.py:104,107` | validate 与 parse-vul 清理均只认 `*.yaml` |
| C7 | counts 字典硬编码 | `cli.py:196-201` | compiler 键集变更 → KeyError 中途崩溃；从返回 dict 派生 |
| C8 | parse-vul --out 清理语义 | `cli.py:104` | 清空 --out 下所有 `*.yaml`——`--out knowledge/tools` 会误删 catalog.yaml；加守卫或 --help 声明 |

## 内容质量（挂 M1/M2 内容工作）

| # | 项 | 位置 | 说明 |
|---|---|---|---|
| D1 | 解析器畸形容忍 | `redteam_vul.py:19,126,50-51` | 含括号 URL 截断 / 空格连字符版本区间误拆 / 孤儿条目 category=""product=""——当前语料零命中（已扫描证实），语料演化时注意 |
| D2 | markdown bullet 拆裂 | `_shared.py:52` | 字面块标量（\|）换行字段会拆破清单行；真实语料用折叠标量不触发 |
| D3 | 工具表 `\|` 未转义 | `_shared.py:66` | 畸形数据仅破坏生成表格美观 |
| D4 | INTEGRATION §4 措辞过时 | `docs/INTEGRATION.md:94` | compile 已实现仍写"规划中"；M1 文档刷新 |

## 流程（不阻塞，择机）

- [ ] CI：`.github/workflows/` 缺失——uv sync + pytest 最小工作流，让 49 测试与守恒门持续强制
- [ ] 计划文件复选框：Task 6 Steps 1/3/4/5 已执行未勾选（计划行 364, 369-371）
- [ ] 测试覆盖重复：VulnEntry Literal 拒绝用例两处（tests/test_models.py:8 宽 / test_parser_redteam_vul.py:85 严）——统一为 ValidationError
