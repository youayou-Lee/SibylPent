# SibylPent 技术方案（PLAN）

> 基座：HackingBuddyGPT（主开发）+ CAI（模式库与机制移植对象）
> 目标：领域化打法（电商/金融）+ 强制证据账本（现象/推理解耦 + 动作前预测）+ 覆盖驱动的终止判定
> 知识库（redteam-skill / redteam_vul / RedTeam-Tools）如何汇入本框架，见 [INTEGRATION.md](INTEGRATION.md)。

---

## 0. 结论先行：选型与分工

| | HackingBuddyGPT (v0.5.0) | CAI (v1.1.5, 已归档) |
|---|---|---|
| 角色 | **主开发基座** | **机制移植来源 + agent 模式参考** |
| 理由 | 活跃维护；扩展零侵入（3-4 个新文件即可加领域 skill）；`capability.py:344` 是全部工具执行的单一咽喉点，强制机制一处插桩全局生效 | 代码即文档：`capture_notice` 的执行层统一拦截、`auto_compactor` 的记忆压缩、baseline 的证据契约条款，三套机制直接抄 |
| 二开位置 | `src/hackingBuddyGPT/usecases/web/` 下新增领域 use case | `src/cai/agents/personal/`（官方预留的自定义 agent 目录，自动发现，核心零改动） |

两者都**没有** RAG/向量库——领域案例库需要自建（见 §2.4）。

---

## 1. 总体架构

```
                    ┌─────────────────────────────────────┐
                    │        Orchestrator (纯代码)         │
                    │  覆盖引擎 · 预算 · 终止判定 · 对账     │
                    └──────┬──────────────┬───────────────┘
                           │              │
              ┌────────────▼───┐   ┌──────▼────────────────┐
              │  Agent (LLM)   │   │   Evidence Ledger      │
              │ 领域playbook注入 │   │  append-only JSONL     │
              └──────┬─────────┘   │  PRD/OBS/INF/ACT/DEC   │
                     │             └──────▲────────────────┘
              ┌──────▼──────────┐         │ 强制写入
              │ Tool Gateway     │────────┘
              │ 预测校验(硬)·权限档 │
              └──────┬──────────┘
                     │  全部 HTTP 流量过代理（一石三鸟：证据/覆盖/可重放）
              ┌──────▼──────────┐
              │ mitmproxy/Burp   │──→ raw evidence 落盘 + sha256
              └─────────────────┘
```

原则：**流程、证据、终止权全部在代码层强制；LLM 只负责生成假设和判断。**

---

## 2. 领域打法注入（Domain Pack）

### 2.1 HBG 上的落地（4 个新文件 + 1 行 import，核心零改动）

1. **`src/hackingBuddyGPT/utils/domain_playbook.py`** — PLAYBOOK 字典，照抄 `utils/pentest_playbook.py:14` 的结构。每个条目 = 一项覆盖检查（`id / domain / category / check / how / expect_tags`）。
2. **`src/hackingBuddyGPT/capabilities/domain_playbook.py`** — LLM 可调用的查询工具，照抄 `capabilities/pentest_playbook.py:9` 三段式（describe + __call__ + 参数即 schema）。
3. **`src/hackingBuddyGPT/usecases/web/ecommerce.py`** — `class EcommerceWebTesting(WebTestingAgent)`：
   - 覆写 `system_message`（模板见 `usecases/web/_base.py:29`、碎片注入参考 `:50` 的 hints 参数和 `web/advanced.py:14-26` 的完整覆写先例）
   - `_add_task_capabilities` 挂 HTTPRequest + DomainPlaybook + RecordPrediction（见 §4）
   - 尾部 `@use_case(...)` 注册（`usecases/usecase.py:158`）
4. **`usecases/web/__init__.py`** 加一行 import。

### 2.2 Playbook 内容（领域打法本体）

**电商（每条含：触发条件 / 测试步骤 / 预期现象 tag / 覆盖 key）**：

| 类别 | 检查项示例 |
|---|---|
| 越权 | 订单/收货地址/发票 IDOR；A 的 token 查 B 的订单；订单 id 遍历（自增/可枚举） |
| 支付 | 金额篡改（负数/0/0.000001/超大/浮点精度）；支付回调重放；回调签名不校验；回调金额与订单不比对；0 元购；回调并发竞态 |
| 优惠券 | 负数面额；并发核销竞态；循环领取；过期券改时间/状态；跨店铺通用 |
| 营销 | 秒杀库存超卖（并发下单）；砍价逻辑（自砍/负数助力）；满减叠加嵌套 |
| 资金 | 提现金额/次数/手续费参数篡改；退款金额 > 支付金额；部分退款重复申请 |
| 账号 | 批量注册/短信轰炸；恶意占库存；弱找回逻辑（验证码回显/爆破） |

**金融**：转账额度绕过、利息试算与实际放款不一致、KYC 环节跳过（直接调后续接口）、实名信息篡改、借款合同 IDOR、风控参数篡改、赎回/提现 T+0 绕过。

### 2.3 指纹路由（先分类再选剧本）

领域 skill 的 system_message 第一步强制：调用 `domain_playbook` 的 `fingerprint` 分支识别业务类型（商城 CMS 特征路径、支付网关回调端点、业务模块 URL 模式），据此只加载对应领域的 playbook 子集进上下文——避免通用泛泛尝试。

### 2.4 案例库（M4，可选增强）

电商类 SRC 报告/CNVD 案例结构化入库（sqlite + FTS5 全文检索即可起步，不必上向量库），`domain_playbook` 工具加 `similar_cases` 查询分支，按指纹命中返回历史打法 few-shot。

---

## 3. 证据账本（核心设计：现象/推理解耦 + 动作前预测）

### 3.1 记录类型与 Schema

Append-only JSONL（`evidence/ledger.jsonl` + `evidence/raw/` 原始文件）。每行一条，五种记录：

```jsonc
// PRD — 动作前预测（先写，后动作）
{"id":"PRD-0009","type":"prediction","ts":"...",
 "action":"GET /api/order?id=10086",
 "expect_tags_any":["http_403","waf_block"],
 "branches":[
   {"if":"403+WAF特征","then":"有WAF≠接口不存在，需评估绕过"},
   {"if":"404","then":"路径可能不存在，也可能鉴权前置——需对照基线路径再判"},
   {"if":"200","then":"接口裸奔，直接进参数测试"}]}

// ACT — 动作（必须引用一个未消费的 PRD，否则网关拒绝）
{"id":"ACT-0017","type":"action","prediction_ref":"PRD-0009",
 "tool":"http_request","args":{...},"ts":"..."}

// OBS — 现象（只描述观察，禁止携带因果解释）
{"id":"OBS-0042","type":"observation","action_ref":"ACT-0017",
 "tags":["http_200","body_diff"],              // 受控词表，见 §3.2
 "source":{"tool":"http_request",
           "raw":"evidence/raw/OBS-0042.txt",
           "sha256":"ab12..."},                // 溯源三件套之一
 "excerpt":"{\"code\":0,\"data\":{\"order_id\":10086,\"user_id\":777,...}}"}

// INF — 推理（必须引用现象，必须枚举候选原因）
{"id":"INF-0012","type":"inference","parents":["OBS-0042","OBS-0043"],
 "alternatives":[
   {"cause":"水平越权：order id 未校验归属","confidence":"high","verify":"用 A 的 token 查 B 订单复现"},
   {"cause":"接口本来就是公开查询","confidence":"low","verify":"未登录裸查"}],
 "chosen":"alternatives[0] 待验证"}

// DEC — 决策（改方向/收工申请，引用 INF）
{"id":"DEC-0006","type":"decision","parents":["INF-0012"],
 "content":"确认 IDOR，进入批量验证；放弃该路径的 SQLi 分支，理由：..."}
```

### 3.2 硬规则一：现象 ≠ 结论（tag 必须是现象）

- `OBS` 的 `tags` 只能取自**现象级受控词表**：`http_2xx / http_401 / http_403 / http_404 / http_429 / http_5xx / timeout / dns_fail / tls_error / waf_block / redirect_external / body_reflect / body_diff / set_cookie / rate_limited ...` + 业务面维度 `surface: auth|order|payment|coupon|user|admin`。
- **禁止** `目标不通 / 不存在漏洞 / 有WAF` 这类结论性 tag——它们属于 `INF`。
- 404 这类现象可能是**多个底层原因叠加**（路径不存在 + WAF 静默拦截 + 需要前置 cookie），所以 `INF` 强制 `alternatives` 字段：至少 2 个候选原因，或显式声明"唯一解释+依据"；每个候选带可执行的 `verify` 动作。这直接把"x²>9 只写 x>3"式的漏解变成账本里的必填枚举分支。

### 3.3 硬规则二：动作前强制预测

- 时序状态机：`PRD → ACT → OBS → COMPARE`，由网关强制，不靠 prompt 自觉。
- **猜错不惩罚，不写不放行**：`COMPARE` 结果三种——`matched`（符合预期）/ `mismatched`（猜错）/ `partial`。
- **`mismatched` 是黄金信号**：预测与现象不一致 = 认知外的东西 = 自动生成一条 investigation 任务（"PRD-0009 预期 403，实测 200+他人数据，为什么？"），优先级高于原计划。惊喜驱动深挖，替代"没结果就换目标"。

### 3.4 溯源三件套（对幻觉与记忆丢失）

1. **来源**：`source.tool` + 原始请求/响应全量落盘 `evidence/raw/` + `sha256`（防篡改、可重放）。
2. **类别**：`type` 五分类 + 受控 tag 词表（写入时校验，非法 tag 拒收）。
3. **因果链**：`parents / prediction_ref / action_ref` 把所有记录连成 DAG——任何结论都能一键回溯到原始字节。

### 3.5 记忆丢失对策

- 账本在文件里，不在模型脑子里。上下文丢了/切换 agent，按 id 重载摘要即可无损续跑。
- 上下文压缩（移植 CAI `auto_compactor` 思路，`src/cai/sdk/agents/models/chatcompletions/auto_compactor.py:659`，Phase1 截旧工具输出 + Phase2 LLM 摘要）：**压缩摘要必须逐条带引用 ID，禁止无出处的概括**，摘要是账本的视图而不是替代品。
- 报告生成规则：报告只能引用账本 ID（OBS/INF），出现无引用断言即报告无效。

---

## 4. 强制机制的三层实现（插点已探明）

| 层 | 机制 | HBG 插点 | 强度 |
|---|---|---|---|
| Prompt 层 | 证据契约条款（先预测、结果必须入账、报告只引用账本） | 领域 skill 的 `system_message` 覆写 | 软，会被遗忘 |
| Schema 层 | **参数即接口**：给 HTTPRequest（或子类 EcommerceHTTPRequest）的 `__call__` 加必填参数 `prediction: str` + `tags: list[str]`，`to_model()`（`capability.py:60`）自动进 JSON schema，缺失即校验失败，异常在 `capability.py:363` 天然转为 LLM 可读错误 | 零核心改动 | 中，覆盖挂了参数的能力 |
| Gateway 层 | **单一漏斗插桩**：`capability.py:344` `run_capability_json` 的 `:362` 执行前，校验 ACT 引用的 PRD 存在且未消费，否则 raise；文本策略路径在 `strategies.py:111` 同款 | 1 处核心改动 | **硬，全局生效** |
| 执行层兜底（CAI 移植） | CAI 在 `executor.py:1430-1433` 对每条本地命令无差别调 `apply_packet_capture_notice`——照此在账本侧做"无论 agent 配合与否，动作+结果必入账"的旁路记录 | 抄 `src/cai/tools/evidence/capture_notice.py` 模式 | 硬，防 agent 绕过 |

配套能力：仿 `capabilities/record_note.py` 写 `RecordPrediction` capability（LLM 主动登记 PRD/INF/DEC），网关对账"每个 ACT 有 PRD"。

**CAI 侧同步验证线**（可选，用于对照实验）：`src/cai/agents/personal/fintech_pentester_agent.py` 新建领域 agent（自动发现，`factory.py:207-228`），`CAI_SINGLE_SHOT_CLI=1 cai --prompt "..."` headless 跑分，对比 HBG 基座效果。

---

## 5. 覆盖引擎与终止权（解决"试两下就说打完了"）

- **覆盖矩阵 = playbook 条目 × 目标面**。每个 playbook 条目即覆盖 key；账本里出现对应 `surface + check` 的 OBS/INF 才算 covered/refuted。
- 终止权在 Orchestrator：agent 只能 `submit_final`（申请收工），代码查账本——playbook 全部 covered/refuted、或预算（`utils/limits.py:29` 四合一限额）烧完，才放行；否则打回并附未测清单。
- 独立预算：每个测试面单独限额，一个面打不通不连坐其他面。
- 参照框架内先例：`minimal_linux_privesc_tool_calling.py:126-175` 的"声明验证后才接受"（ground-truth 校验 `task_solved`）。

---

## 6. 工具与流量架构

- 全部 HTTP 走代理：HBG 的 HTTPRequest 原生支持 `CLIENT_HTTP(S)_PROXY` 环境变量（`capabilities/http_request.py:17-32`），直接指向 mitmproxy/Burp——落盘证据、覆盖统计（实测端点数）、可重放报告一站解决。
- 权限档：recon 自动 / scan 开关 / exploit 人工确认 / destructive 默认禁止——网关层按 capability 分档执行。
- CAI 侧工具封装范例 27 行：`src/cai/tools/reconnaissance/nmap.py`（`@function_tool` + `run_command` + `TOOL_REGISTRY.register`），需要时照抄。

---

## 7. 路线图

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| **M0 知识底座**（1 周） | redteam_vul README 解析器 → `vuln_index/*.yaml`；redteam-skill 条款核对 + 条目转译器；`sibylctl compile` 流水线（YAML → HBG/CAI/CC-skill 三格式）；`tools/catalog.yaml` Web 子集抽取 | `sibylctl compile` 跑通三格式产物；vuln_index 覆盖上游 README 全部条目且可按产品+版本过滤查询 |
| **M1 账本+预测**（1-2 周） | `evidence_ledger.py`（schema+词表校验+落盘）、RecordPrediction、Schema 层必填参数、Gateway 层 PRD 校验 | 无 PRD 的工具调用被拒；OBS 全部带 source+哈希；非法 tag 拒收 |
| **M2 电商领域包**（1-2 周） | domain_playbook（30+ 条目）、指纹路由、ecommerce use case、system_message 注入 | 对测试靶场（自建含价格/订单/优惠券接口的 mock 商城）产出领域化测试序列 |
| **M3 覆盖引擎**（1 周） | 覆盖矩阵统计、终止判定、mismatch→investigation 任务、报告只引用账本 ID | 故意让 agent 提前收工 → 被打回并给出未测清单 |
| **M4 增强**（持续） | 金融领域包、案例库（FTS5）、CAI 三机制移植（统一拦截/auto-compact/契约条款）、对照实验（CAI personal agent） | 同一靶场两基座跑分对比：覆盖率、mismatch 抓取数、幻觉率（无引用断言数） |

---

## 8. 风险与成本

- **Token 开销**：每次动作多一段 prediction+branches（约 150-300 token/次）。对策：branches 只在首次遇到某类检查时强制，同类重复动作允许引用上次 PRD 模板。
- **Schema 层只覆盖挂了参数的能力**：新能力忘记加 `prediction` 参数就绕过了中强度层——所以 Gateway 层兜底是必须项，不是可选项。
- **CAI 已归档**：只抄代码不做基座；license 校验用 `CAI_LICENSE_OFF=1` + `CAI_SKIP_UPDATE_CHECK=1` 绕过。
- **账本膨胀**：长任务 OBS 上千条。对策：按 `surface` 分文件 + 索引文件（id→offset），检索走 FTS5。

---

## 附录：关键文件速查（两框架，file:line 均已实地核对）

**HackingBuddyGPT**（`/home/you/workspace/Penetration/hackingBuddyGPT/`）
- 能力基类/注册/漏斗：`src/hackingBuddyGPT/capability.py:26 / :322 / :344-369`；schema 自动生成 `:60`、`:302-319`
- Web 基座：`usecases/web/_base.py:13-65`（prompt 碎片+system_message+hints）；`web/advanced.py:14-26`（完整覆写先例）
- HTTP 能力：`capabilities/http_request.py:12`（`:17-32` 代理支持，`:70-93` 响应处理）
- web_api 包装：`usecases/web_api/proposed_http_request.py:25,43,70,109`
- UseCase 注册：`usecases/usecase.py:12,57,69-105,108,158`
- 断言先例：`usecases/minimal_linux_privesc/minimal_linux_privesc_tool_calling.py:126-175`
- playbook 模板：`utils/pentest_playbook.py:14`；记账模板：`capabilities/record_note.py`
- 限额/日志/LLM：`utils/limits.py:29`；`utils/logging.py:91,327`；`utils/llm.py:16,32`
- 入口：`cli/wintermute.py:8`（CLI > --config > .env > env，`utils/configurable.py:682`）

**CAI**（`/home/you/workspace/Penetration/cai/`）
- 自定义 agent 目录（官方预留）：`src/cai/agents/personal/`（发现逻辑 `src/cai/agents/factory.py:140-230`，个人目录扫描 `:207-228`）
- Agent 定义范例：`src/cai/agents/red_teamer.py:67-82`；web agent：`src/cai/agents/web_pentester.py:44-60`
- 提示词三层：`src/cai/util/prompts.py:14-46`（baseline 含证据契约 17-19 条）、`:55-83`（micro-profile 注册表）、`:220-248`、`:251-338`、`:350-384`（append_instructions）
- 工具模板：`src/cai/tools/reconnaissance/nmap.py`；执行路由 `src/cai/tools/executor.py:1289,1450`
- 执行层拦截先例：`src/cai/tools/evidence/capture_notice.py` + 调用点 `executor.py:1430-1433`
- 证据核查工具先例：`src/cai/tools/evidence/inventory_check.py:63`
- 记忆压缩：`src/cai/sdk/agents/models/chatcompletions/auto_compactor.py:427,571,659`；压缩块注入 `util/prompts.py:387-426`
- 持久化/恢复：`src/cai/sdk/agents/run_to_jsonl.py:64,581`（~/.cai/logs/*.jsonl）
- headless：`CAI_SINGLE_SHOT_CLI=1 cai --prompt "..."`（`src/cai/cli_headless.py:593,766,1315-1334`）
- handoff 路由表：`src/cai/agents/operational_handoffs.py:17-124`
- 配置/license：`src/cai/config.py:63,194-276`；`src/cai/util/llm_api_base.py:68-108`（`OPENAI_API_BASE` 通配自定义端点）
