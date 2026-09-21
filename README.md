# SibylPent

> **先写预言，再落动作；一切观察，皆有出处。**

**English**: SibylPent is an evidence-first, prediction-locked AI web-penetration-testing framework. Every tool action must be preceded by a written prediction; every observation must carry provenance (source, category tags, causal links). It packages domain-specific attack playbooks (e-commerce / fintech) with a coverage engine that owns the right to decide when testing is done — not the LLM.

[![status](https://img.shields.io/badge/status-设计阶段_PLAN_ONLY-blue)]() [![base](https://img.shields.io/badge/base-HackingBuddyGPT-informational)]() [![donor](https://img.shields.io/badge/donor_mechanisms-CAI-red)]()

---

## 1. 这是什么

SibylPent 是一个 **证据优先、预测锁定的 AI Web 渗透测试框架**，针对当前 LLM 渗透 Agent 的四个顽疾：

| # | 顽疾 | SibylPent 对策 |
|---|------|----------------|
| 1 | 领域泛泛尝试：打电商站还是通用扫描器思路 | **领域打法包**：电商/金融 playbook + 指纹→已知漏洞索引 |
| 2 | 推理污染事实：看到 404 就断言"目标不通"（如同 x²>9 只写 x>3，漏掉 x<-3） | **证据账本**：现象/推理解耦；推理必须枚举 ≥2 个候选原因（含叠加原因） |
| 3 | 收工权在 LLM："试了三下没打通，换个目标吧" | **覆盖引擎 + 终止权上收**：playbook 条目 × 目标面矩阵，代码判定能否收工 |
| 4 | 工具各自为政：nmap/Burp 无统一接入与管控 | **工具网关**：预测校验硬闸 + 权限四档 + 全流量过代理 |

## 2. 三支柱

1. **证据账本（Evidence Ledger）**：append-only JSONL，五类记录（PRD 预测 / ACT 动作 / OBS 现象 / INF 推理 / DEC 决策）。现象与推理解耦——OBS 的 tag 只能取自现象级受控词表、禁止携带因果解释；INF 必须枚举候选原因（含叠加原因）+ 各自的 verify 动作。
2. **动作前强制预测（Prediction Lock）**：`PRD → ACT → OBS → COMPARE` 时序状态机由工具网关硬强制：无未消费 PRD 则拒绝执行工具。猜错不惩罚，**mismatched（猜错）是黄金信号**——预期与现象不一致即认知盲区，自动生成调查任务。
3. **覆盖引擎（Coverage Engine）**：playbook 条目 × 目标面矩阵，由编排器代码统计账本覆盖率、判定终止。"打不通"不是合法收工理由，"矩阵全 covered/refuted"才是。

## 3. 架构总览

```
                ┌─────────────────────────────────────┐
                │       Orchestrator（纯代码）          │
                │   覆盖统计 · 预算 · 终止判定 · 对账     │
                └──────┬──────────────┬───────────────┘
                       │              │
          ┌────────────▼───┐   ┌──────▼─────────────────┐
          │  Agent（LLM）   │   │  Evidence Ledger        │
          │ 领域playbook注入 │   │  append-only JSONL      │
          └──────┬─────────┘   │  PRD/OBS/INF/ACT/DEC    │
                 │             └──────▲─────────────────┘
                 │                    │ 强制写入
       ┌─────────▼─────────┐          │
       │ Tool Gateway       │──────────┘
       │ 预测校验硬闸·权限四档│
       └─────────┬─────────┘
                 │ 全部 HTTP 流量过代理
       ┌─────────▼─────────┐
       │ mitmproxy / Burp   │──→ raw evidence 落盘 + sha256
       └───────────────────┘
```

## 4. 知识库集成（三个上游知识源）

SibylPent 不从零写知识：三个已验证的红队知识库经**转译流水线**（`knowledge/` 单一事实源 YAML → 多运行时格式编译）汇入。设计详见 [docs/INTEGRATION.md](docs/INTEGRATION.md)：

| 上游仓库 | 在 SibylPent 中的角色 | 集成方式 |
|---|---|---|
| [pale-knight/redteam-skill](https://github.com/pale-knight/redteam-skill) | 方法论 + 纪律条款库 | SKILL.md 纪律条款 → 覆盖引擎成功判定规则；web-recon / web-attack references → 通用 playbook 条目 |
| [r0eXpeR/redteam_vul](https://github.com/r0eXpeR/redteam_vul) | 边界打点已知漏洞索引 | README 解析 → `vuln_index/*.yaml`（产品/漏洞/CNVD/影响版本/复现链接）；产品清单反哺指纹库 |
| [A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) | 工具网关的选型菜单 | 抽取 Web 子集 → `tools/catalog.yaml`（工具/阶段/权限档/封装形式） |

## 5. 技术方案

完整技术方案（证据账本 schema、强制机制插桩点、覆盖引擎、双基座选型论证、关键源码插点 file:line 速查）见 **[docs/PLAN.md](docs/PLAN.md)**。

**基座选型结论**：[HackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) 为主开发基座（活跃维护、扩展零侵入、`capability.py:344` 单一执行咽喉点），[CAI](https://github.com/aliasrobotics/cai) 为机制移植来源（执行层统一拦截 `capture_notice`、记忆压缩 `auto_compactor`、提示词证据契约条款）。

## 6. 当前状态

> 📝 **PLAN-ONLY 阶段**：本仓库当前只含设计文档，未开始任何实现。方案正等待 review（人类 + AI 交叉评审）后，按 [docs/PLAN.md](docs/PLAN.md) 第 7 节路线图推进。

欢迎 review 意见：对账本 schema、强制层次（prompt/schema/gateway/执行层）、领域 playbook 条目设计、双基座选型、路线图合理性提出批评与建议——请开 Issue。

## 7. 相关项目

- 基座：[ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) · 机制来源：[aliasrobotics/cai](https://github.com/aliasrobotics/cai)（已归档）
- 同类项目：[usestrix/strix](https://github.com/usestrix/strix) · [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) · [knownsec/aipyapp](https://github.com/knownsec/aipyapp) · [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT)
- 知识源：[pale-knight/redteam-skill](https://github.com/pale-knight/redteam-skill) · [r0eXpeR/redteam_vul](https://github.com/r0eXpeR/redteam_vul) · [A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools)
- 评估参考：腾讯 Tsecbench（智能攻防 AI 跑分基准）
