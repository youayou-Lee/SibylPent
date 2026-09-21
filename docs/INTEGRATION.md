# SibylPent 知识库集成设计（INTEGRATION）

> 三个上游知识库如何汇入 SibylPent。技术方案本体见 [PLAN.md](PLAN.md)。

## 0. 单一事实源，多运行时编译

三个上游仓库格式各异（SKILL.md 散文 / README 链接列表 / 工具目录），直接塞给 LLM 是 token 灾难，且无法参与覆盖统计。因此：

```
上游知识库                  单一事实源（canonical YAML）        运行时消费
────────────             ──────────────────────────       ─────────────────────
redteam-skill  ──转译──→  knowledge/playbooks/*.yaml   ──编译──→ ① HBG capability + system prompt
redteam_vul    ──解析──→  knowledge/vuln_index/*.yaml  ──编译──→ ② CAI personal agent prompt
RedTeam-Tools  ──抽取──→  knowledge/tools/catalog.yaml ──编译──→ ③ Claude Code skill（SKILL.md）
```

- **单一事实源**：知识以受 schema 约束的 YAML 维护，人工可读可改、可 diff、可审计。
- **多运行时编译**：同一份 YAML 编译出三个运行时格式。知识只写一遍，三个运行时受益。
- **按需注入**：不全量塞 prompt，由指纹路由 + LLM 主动查询分阶段注入。

## 1. redteam-skill → 方法论 + 纪律条款库

**上游形态**：Claude Code skill 格式（`skills/*/SKILL.md` + `references/*.md`），覆盖完整红队链路（recon → web-recon → web-attack → privesc → post）。

### 1.1 纪律条款转译表

redteam-skill 的 SKILL.md 已有一套操作纪律，逐条映射到 SibylPent 强制机制：

| redteam-skill 条款 | SibylPent 落点 | 强制层次 |
|---|---|---|
| 开局第一件事：Read `./notes.md` | 账本人类可读视图（`ledger view` 渲染 OBS/INF 时间线） | 运行时 |
| 不算：sqlmap 报 injection、`alert(1)`、Nuclei MATCH | **覆盖引擎 refute 规则**：扫描器 MATCH ≠ 漏洞成立，账本内可重放证据才算 covered | 代码强制 |
| 收尾：追加 notes.md → default_next | 覆盖引擎终止判定：矩阵全 covered/refuted 才放行 submit_final | 代码强制 |
| 监听/sudo/输密码：立刻停，等操作者 | 工具网关权限四档：exploit/destructive 档强制人工确认 | 代码强制 |
| 走到哪条链，才 Read 一份 reference | playbook 分段注入：指纹路由后只载入对应链的条目 | prompt 契约 |
| 禁止凭记忆写 payload | 账本溯源：INF 必须引用 OBS id；报告只能引用账本 ID | 代码强制 |
| 模块 handoff（web-recon→web-attack→privesc） | 面间交接协议：交接必须引用双方账本 ID | prompt 契约 + DEC 记录 |

### 1.2 知识转译

- `skills/web-recon/references/`（api-discovery、cms-cheatsheet、http-topology、frontend-recon、vulnerability-intelligence）+ `skills/web-attack/`（注入/上传/LFI/SSRF/XXE/SSTI/反序列化/JWT/SAML/API 逻辑/desync）→ `knowledge/playbooks/generic/*.yaml`。
- 转译规则：散文知识 → 结构化条目，字段 `{id, domain, category, check, how, expect_tags, success_criteria}`，每条目即覆盖引擎的一个覆盖 key。
- 分段注入策略继承 redteam-skill 的 reference 按需加载设计。

### 1.3 双格式输出：Claude Code skill

redteam-skill 本身就是 Claude Code skill 格式。转译器（M0 交付物）必须支持编译出 `SKILL.md`（含 `name/description` frontmatter），使知识库可直接作为 Claude Code skill 安装使用。

## 2. redteam_vul → 边界打点已知漏洞索引

**上游形态**：单 README（213 行），按产品组织，八大类（OA / 邮件 / Web 中间件 / 源码管理 / 项目管理 / 数据库 / 运维监控 / 堡垒机），每条含 CVE/CNVD 编号、影响版本、复现文章链接。

### 2.1 解析器设计

**解析器（M0 交付物）**：`scripts/parse_redteam_vul.py`——README 三层结构化解析：

```
## 一、OA系统     → category
> 泛微(Weaver)    → product
* [日期] - [漏洞名(CNVD-xxxx)](url) - 影响版本... → entry
```

输出 `vuln_index/<category>.yaml`，字段 `{product, vuln_name, cnvd_or_cve, affected_versions, ref_url, date, entry_type, verified: false}`。`entry_type ∈ {vuln, tool, collection, placeholder}`——上游含 ⚒️ 工具条目、"XX历史漏洞合集"聚合链接、无编号占位条目，均按类型保留而非丢弃；无法归类者进显式 skip 清单（带理由）。M0 验收口径：**全部条目解析为 typed 记录或带理由显式跳过**，不做静默丢弃。构建"产品 → 已知漏洞 + 版本约束 + 复现链接"索引。

### 2.2 指纹层反哺

产品清单 = 指纹目标清单。泛微/致远/通达 OA、中间件、堡垒机等产品 → 指纹库种子（favicon hash / 特征路径 / header / body 特征）。清单提取在 M0，指纹特征规则库 M2 交付。

### 2.3 打点层 × 业务层

redteam_vul = 打点层，领域 playbook = 业务层。金融/电商企业渗透的现实路径：外网打点（OA/VPN/堡垒机/中间件）→ 业务面测试。两层互补：

- 打点层命中 → 走红队链（web-attack → shell），交接以 DEC 记录联动
- 业务层命中 → 走验证 → 报告链
- 覆盖矩阵同时统计两层

## 3. RedTeam-Tools → 工具网关的选型菜单

**上游形态**：README 工具目录（150+ 工具，按 MITRE ATT&CK 战术名分章：Red Team Tips / Reconnaissance / Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Discovery / Lateral Movement / Exfiltration / Impact，偏 Windows/AD/钓鱼）。

**抽取规则**：Web 相关子集 → `knowledge/tools/catalog.yaml`，字段 `{name, url, phase, category, permission_tier, wrap_as}`。`wrap_as` 决定网关封装形式：capability（HBG 能力）/ mcp（MCP server）/ cli（run_command 透传）。

**权限档映射初值**（完整定义见 PLAN.md §6）：

| 工具性质 | 权限档 | 执行策略 |
|---|---|---|
| 被动收集（子域/指纹/被动 API） | recon | 自动放行 |
| 主动扫描（nmap/nuclei/httpx） | scan | 开关位开启 |
| exploit 类（SQLMap/PoC 重放） | exploit | 人工确认 |
| 删改类（删数据/DoS） | destructive | 默认禁止 |

## 4. 编译流水线（M0 交付物）

`sibylctl compile`（规划中）：YAML schema 校验 → 生成三格式产物：

1. HBG：`capabilities/domain_playbook.py` 消费的 PLAYBOOK dict + system prompt 片段
2. CAI：`src/cai/agents/personal/` 的 agent instructions 片段
3. Claude Code skill：`SKILL.md` + references/

知识更新单点化：上游仓库更新 → 重跑解析器/转译器 → 三格式产物再生成。

## 5. 决策点状态（v2 更新）

**v1 遗留 → v2 处置**：

1. §1.1 条款映射表——评审已核实 7 行忠实于原文；"是否有遗漏"仍开放
2. vuln_index 字段——已加 `entry_type`；去重键、人工复核流程仍开放
3. 权限档边界——自主模式 exploit 档三选一降级语义已定义（PLAN §6），默认"拒绝改道"
4. canonical YAML schema 细节——`entry_type` 已定；字段命名/必填可选/多语言仍开放
5. 编译产物放 `gen/` 并 gitignore，还是提交进仓库——**仍开放**

**v2 新增决策点**（评审提出、方向已定，细节 M1 定稿）：

6. branches 机器可求值谓词化的引入时机（当前不计分，仅解释性）
7. Brier 记分公式细节与"对冲降分"阈值
8. SubAgent 账本 namespace 的合并时机与冲突规则（独立 namespace 已定）
