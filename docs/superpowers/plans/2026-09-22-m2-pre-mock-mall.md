# M2-pre Mock 商城靶场 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付可一键部署、行为确定的 mock 电商靶场（商品/订单/优惠券接口），内置 9 条已知漏洞作为 ground truth（订单竞态超卖、金额篡改三连、订单水平越权、垂直提权、优惠券三连），`SAFE_MODE=1` 一键关闭全部漏洞行为形成 M4 A/B 对照的固定基线。对应 PLAN §7 M2-pre 行验收：靶场可部署、ground truth 清单完备，作为 M2-M4 统一评测基准。

**Architecture:** `targets/mock-mall/` 独立 uv 子项目（不依赖 sibylpent 主包）。FastAPI 应用工厂 `create_app(Settings)`，SQLite 单连接（`check_same_thread=False`）+ `threading.RLock` 串行化全部 DB 访问；竞态漏洞由**锁外 sleep 竞态窗**（`race_window_ms`，默认 50ms）注入，同步 `def` 端点跑在线程池使并发真实可复现。每个漏洞 = 订单/优惠券/用户处理器里一个显式分支：非 SAFE 走漏洞路径（代码注释 `# VULN(MALL-xxx)`），SAFE 走修复路径（`# SAFE(MALL-xxx)`）。种子数据全固定（含 token 派生），`MALL_SEED=1` 启动重播种 → 每次 `docker compose up` 状态完全一致。ground truth 单一事实源 = `ground_truth.yaml`（机读，M3/M4 评分用），`GROUND_TRUTH.md` 人工表与之同步（测试强制）。

**Tech Stack:** Python ≥3.12、uv、FastAPI、uvicorn、标准库 sqlite3；dev 组 pytest + httpx（TestClient）。部署：`python:3.12-slim` + uv 官方镜像拷贝 + docker compose。不引入其他依赖。

**Spec:** docs/PLAN.md（§7 M2-pre 行验收标准、§2.2 电商打法表、§3.2 现象受控词表）、Issue #4 指派约束（SAFE_MODE 基线 / 回环绑定 / 合成数据 / ground truth 四字段）。

## Global Constraints

- 子项目位于 `targets/mock-mall/`，独立 `pyproject.toml` + `uv.lock`；主包 `src/sibylpent/` **零改动**。根 `pyproject.toml` 加 `testpaths = ["tests"]` 防根目录 pytest 误收集子项目测试
- 包管理只用 uv（`uv add`、`uv run`）；requires-python = ">=3.12"
- **默认只绑回环**：`MALL_HOST` 默认 `127.0.0.1`；绑定非回环地址必须显式 `MALL_ALLOW_REMOTE=1`，否则启动即 `RuntimeError` 拒绝。docker compose 内监听 `0.0.0.0`（容器网络隔离）但端口发布写死 `127.0.0.1:8400:8400`——宿主机侧唯一入口是本机回环
- **无真实支付**：金额只到订单 `total` 为止，无支付网关、无回调；**合成数据 only**（人名/商品/券码全部虚构）
- `targets/mock-mall/README.md` 首行声明：这是**故意脆弱、仅限本机 localhost** 的渗透测试靶场（Juice-Shop 式），禁止暴露公网
- **确定性**：种子固定、token 派生固定（`MALL_SECRET` 默认常量）、订单号从 1001 自增、竞态窗为固定常量、无时间依赖行为（无券过期/无时间戳字段）
- `SAFE_MODE=1` 时全部 9 条漏洞行为关闭且语义确定（原子扣减/服务端价格/分运算/归属校验/角色不可自改/限领/忽略客户端面额/原子核销）——每条漏洞至少配 1 条 vuln 测试 + 1 条 safe 对照测试（meta 测试强制配对）
- 测试全部 in-process（TestClient/ASGITransport），不发起真实网络；漏洞代码行注释 `# VULN(MALL-xxx)`、修复分支注释 `# SAFE(MALL-xxx)`，与 ground truth id 一一对应
- 代码标识符英文，注释/文档中文；commit 尾行 `Co-Authored-By: Claude Code <noreply@anthropic.com>`
- **非目标**（防范围蔓延，挂后续里程碑）：支付回调重放、短信轰炸、砍价/满减、券有效期、验证码、WAF、限流

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `SAFE_MODE` | `0` | `1` = 关闭全部漏洞行为（M4 A/B 固定基线） |
| `MALL_HOST` | `127.0.0.1` | 监听地址；非回环需 `MALL_ALLOW_REMOTE=1` |
| `MALL_PORT` | `8400` | 监听端口 |
| `MALL_DB` | `data/mock-mall.db` | SQLite 文件路径（测试传 tmp 路径） |
| `MALL_SECRET` | `sibyl-mock-mall-dev-secret` | token 派生密钥（固定默认 = 跨重启 token 确定） |
| `MALL_RACE_WINDOW_MS` | `50` | 竞态窗时长（毫秒） |
| `MALL_ALLOW_REMOTE` | `0` | 非回环绑定显式豁免 |
| `MALL_SEED` | `1` | 启动时重播种（确定性重置） |

## 接口契约（Endpoint Contract）

响应信封统一：成功 `{"code":0,"message":"ok","data":...}`（HTTP 200）；失败 `{"code":<业务码>,"message":"<中文>","data":null}`。业务码表：40001 参数非法（SAFE 模式校验）/ 40002 库存不足 / 40003 优惠券不可用或已领过 / 40101 未登录或 token 无效 / 40301 越权（SAFE 模式）/ 40401 资源不存在。畸形 JSON 走 FastAPI 默认 422（不定制）。

| Method / Path | 鉴权 | 说明 | 漏洞 |
|---|---|---|---|
| `GET /api/health` | 无 | `{"status":"ok","safe_mode":<bool>}` | — |
| `POST /api/auth/login` | 无 | `{"username","password"}` → `{"token","user_id","role"}` | — |
| `GET /api/users/me` | Bearer | 当前用户 profile | — |
| `PUT /api/users/me` | Bearer | 更新 nickname；VULN 分支接受 `role` | MALL-006 |
| `GET /api/products` | 无 | 商品列表（含 stock，超卖验证面） | — |
| `GET /api/products/{id}` | 无 | 商品详情 / 404 | — |
| `POST /api/orders` | Bearer | 下单：`{"items":[{"product_id","quantity","unit_price"?}],"coupon_code"?}` | MALL-001..004, 009 |
| `GET /api/orders` | Bearer | **本人**订单列表（两种模式都正确过滤） | — |
| `GET /api/orders/{id}` | Bearer | 订单详情 | MALL-005 |
| `POST /api/coupons/claim` | Bearer | 领券：`{"code"[,"amount"?]}` | MALL-007, 008 |
| `GET /api/admin/users` | Bearer+admin | 全部用户（提权后可达的现象面） | MALL-006 现象 |

请求模型（pydantic，漏洞字段即声明处）：

```python
class OrderItemIn(BaseModel):
    product_id: int
    quantity: int
    unit_price: float | None = None   # VULN(MALL-002/003)：非 SAFE 模式直接采信

class OrderIn(BaseModel):
    items: list[OrderItemIn]          # 非空，min_length=1
    coupon_code: str | None = None

class ClaimIn(BaseModel):
    code: str
    amount: float | None = None       # VULN(MALL-008)：非 SAFE 模式覆写实例面额

class ProfileUpdateIn(BaseModel):
    nickname: str | None = None
    role: str | None = None           # VULN(MALL-006)：非 SAFE 模式允许自改角色
```

种子数据（全固定）：

- users：`alice/Passw0rd!`（role=user）、`bob/Passw0rd!`（role=user）、`admin/Admin123!`（role=admin）；token = `sha256(f"{username}:{password}:{MALL_SECRET}").hexdigest()[:32]` 播种时算好入库
- products：

| id | name | price | stock | category | 用途 |
|---|---|---|---|---|---|
| 1 | 机械键盘 KB-100 | 99.0 | 10 | 数码 | 常规 |
| 2 | 显示器 M27 | 1299.0 | 5 | 数码 | 常规 |
| 3 | USB-C 线 0.1m | 0.1 | 100 | 配件 | MALL-004 精度诱饵 |
| 4 | 转接头 0.2m | 0.2 | 100 | 配件 | MALL-004 精度诱饵 |
| 5 | 限量手办 SP-01 | 499.0 | 1 | 收藏 | MALL-001 超卖诱饵 |

- coupons：`SAVE10`（amount=10.0）、`BIGSAVE`（amount=100.0）；订单号从 **1001** 起（`sqlite_sequence` 初始化为 1000，自增可枚举是 MALL-005 的一部分）

## Ground Truth 总表（9 条，单一事实源 = ground_truth.yaml）

| id | title | 类别 | endpoint | 触发（trigger） | 预期现象（SAFE_MODE=0） | SAFE_MODE=1 行为 |
|---|---|---|---|---|---|---|
| MALL-001 | 订单竞态超卖 | race | `POST /api/orders` | 商品 5（stock=1）；alice、bob 并发各提交 `{"items":[{"product_id":5,"quantity":1}]}`（50ms 竞态窗内同时过库存检查） | 两请求均 HTTP 200、两订单均创建；`GET /api/products/5` 返回 `stock=-1` | 原子条件扣减（`UPDATE ... WHERE stock>=qty`），仅 1 笔 200，另一笔 400/40002，stock=0 |
| MALL-002 | 客户端价格篡改 | amount | `POST /api/orders` | alice 提交 `{"items":[{"product_id":1,"quantity":1,"unit_price":0.01}]}`（DB 价 99.0） | HTTP 200，订单 `total=0.01`；`unit_price=0` 时 `total=0.0`（0 元购） | 忽略非负 `unit_price`，`total=99.0` |
| MALL-003 | 负数金额/数量 | amount | `POST /api/orders` | 提交 `{"product_id":1,"quantity":1,"unit_price":-50}`；或 `{"product_id":1,"quantity":-1}` | HTTP 200；前者 `total=-50.0`，后者订单创建且库存 10→11（负数量反向扣减） | 400/40001 拒绝（quantity<1 或 unit_price<0，两者都拒） |
| MALL-004 | 浮点精度滥用 | amount | `POST /api/orders` | 提交商品 3（0.1）+ 商品 4（0.2）各 1 件（价格即 float 存储） | HTTP 200，`total=0.30000000000000004`（IEEE754 直算 ≠ 0.3） | 分（cent）整数运算，`total=0.3` |
| MALL-005 | 订单水平越权（IDOR） | authz | `GET /api/orders/{id}` | bob 携自身 token 请求 alice 的订单 1001；继续遍历 1001..100N | HTTP 200 返回 alice 订单（含 `user_id=1`）；订单号自增可枚举 | 403/40301；本人订单仍 200；不存在 404 |
| MALL-006 | 垂直越权提权 | authz | `PUT /api/users/me` → `GET /api/admin/users` | alice 提交 `{"role":"admin"}` 后携原 token 调 admin 接口 | PUT 200 且返回 `role="admin"`；`GET /api/admin/users` 200 返回全部用户 | `role` 字段忽略（仍 user）；admin 接口 403/40301 |
| MALL-007 | 优惠券循环领取 | coupon | `POST /api/coupons/claim` | alice 对 SAVE10 连续领取 2 次，两实例分别核销于 2 笔订单 | 每次领取 200 生成新实例；两笔订单均享 10 元折扣（循环领取重复受益） | 每用户每码限 1 张，第 2 次 400/40003 |
| MALL-008 | 优惠券面额篡改 | coupon | `POST /api/coupons/claim` | alice 提交 `{"code":"SAVE10","amount":10000}`（或 `-50`）后下单核销 | 领取 200 且实例 `amount=10000`；订单 `total=499-10000=-9501.0`（负总额）；`amount=-50` 时 total 反增 | 忽略客户端 `amount`，实例面额=模板 10.0 |
| MALL-009 | 优惠券并发核销 | race | `POST /api/orders`（带 coupon_code） | alice 领 1 张 SAVE10 后并发提交 2 笔使用该券的订单（竞态窗内 status 检查与回写分离） | 两订单均 200 且均减 10 元（一券两用） | 原子条件核销，仅 1 笔 200（89.0），另一笔 400/40003 整单拒绝（不落无券订单，见 Task 7 事务顺序） |

detection_tags（每条 yaml 附，供 M2 playbook/M3 覆盖引擎对齐；取值 ⊆ PLAN §3.2 受控词表，surface ⊆ PLAN §3.2 业务面枚举）：

| id | detection_tags | surface |
|---|---|---|
| MALL-001 | [http_2xx] | order |
| MALL-002 | [http_2xx, body_reflect] | payment |
| MALL-003 | [http_2xx, body_reflect] | payment |
| MALL-004 | [http_2xx, body_diff] | payment |
| MALL-005 | [http_2xx, body_diff] | order |
| MALL-006 | [http_2xx] | admin |
| MALL-007 | [http_2xx] | coupon |
| MALL-008 | [http_2xx, body_reflect] | coupon |
| MALL-009 | [http_2xx] | coupon |

## File Structure

```
targets/mock-mall/
├── pyproject.toml              # 独立 uv 项目；fastapi+uvicorn，dev: pytest+httpx
├── uv.lock
├── Dockerfile                  # python:3.12-slim + uv；CMD python -m app（守卫生效路径）
├── docker-compose.yml          # 端口发布 127.0.0.1:8400:8400（宿主机侧仅回环）
├── .dockerignore
├── README.md                   # 故意脆弱·仅限本机·测试靶场声明 + 一键部署
├── GROUND_TRUTH.md             # 人工可读 ground truth 表（与 yaml 同步，测试强制）
├── ground_truth.yaml           # 机读 ground truth（单一事实源，M3/M4 评分输入）
├── app/
│   ├── __init__.py
│   ├── main.py                 # create_app 工厂 + /api/health + 模块级 app（uvicorn 入口）
│   ├── __main__.py             # python -m app：Settings.from_env()（含绑定守卫）→ uvicorn.run
│   ├── config.py               # Settings + from_env + validate_bind 回环守卫
│   ├── db.py                   # sqlite3 单连接 + RLock；schema DDL；执行助手
│   ├── seed.py                 # 固定种子（users/products/coupons + token 派生 + 订单号基座 1000）
│   ├── auth.py                 # POST /api/auth/login；get_current_user 依赖
│   └── routers/
│       ├── __init__.py
│       ├── users.py            # GET/PUT /api/users/me（MALL-006）
│       ├── products.py         # GET /api/products[/{id}]
│       ├── orders.py           # POST/GET /api/orders、GET /api/orders/{id}（MALL-001..005, 009）
│       ├── coupons.py          # POST /api/coupons/claim（MALL-007/008）
│       └── admin.py            # GET /api/admin/users（MALL-006 现象面）
└── tests/
    ├── __init__.py             # 空文件；使 `from tests.conftest import ...` 可导入（pythonpath=["."]）
    ├── conftest.py             # client_vuln / client_safe 双夹具（各自全新 tmp 库）+ login/auth 助手
    ├── test_config.py
    ├── test_health.py
    ├── test_db_seed.py
    ├── test_auth.py
    ├── test_products.py
    ├── test_orders.py
    ├── test_vuln_amount.py     # MALL-002/003/004
    ├── test_vuln_oversell.py   # MALL-001
    ├── test_vuln_idor.py       # MALL-005
    ├── test_vuln_privesc.py    # MALL-006
    ├── test_vuln_coupon.py     # MALL-007/008/009
    └── test_ground_truth.py
```

---

### Task 1: 子项目脚手架 + 配置与部署安全门（回环绑定 + SAFE_MODE）

**Files:**
- Create: `targets/mock-mall/pyproject.toml`、`app/__init__.py`、`app/config.py`、`app/main.py`
- Modify: 根 `pyproject.toml`（`[tool.pytest.ini_options]` 加 `testpaths = ["tests"]`）、根 `.gitignore`（加 `targets/mock-mall/data/`）
- Test: `tests/test_config.py`、`tests/test_health.py`

**Interfaces:**
- Produces（后续所有任务的运行时基石）:

```python
# app/config.py
class Settings(BaseModel):
    safe_mode: bool = False
    host: str = "127.0.0.1"
    port: int = 8400
    db_path: Path = Path("data/mock-mall.db")
    secret: str = "sibyl-mock-mall-dev-secret"
    race_window_ms: int = 50
    allow_remote: bool = False
    seed_on_start: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        """读上表环境变量（SAFE_MODE/MALL_HOST/MALL_PORT/MALL_DB/MALL_SECRET/
        MALL_RACE_WINDOW_MS/MALL_ALLOW_REMOTE/MALL_SEED），构造后立即 validate_bind()。"""

    def validate_bind(self) -> None:
        """host 不在 {127.0.0.1, ::1, localhost} 且 allow_remote=False
        → RuntimeError('refusing non-loopback bind; set MALL_ALLOW_REMOTE=1 to override')。"""

# app/main.py
def create_app(settings: Settings) -> FastAPI:
    """应用工厂：初始化 DB（settings.seed_on_start 时重播种），
    挂 /api/health 与全部 routers（后续任务逐个挂载）。"""

app = create_app(Settings.from_env())  # 模块级实例，供 uvicorn app.main:app

# GET /api/health → 200 {"code":0,"message":"ok","data":{"status":"ok","safe_mode":<bool>}}
```

- [ ] **Step 1:** 写 `targets/mock-mall/pyproject.toml`：

```toml
[project]
name = "mock-mall"
version = "0.1.0"
description = "Deliberately vulnerable localhost-only mock e-commerce target for SibylPent evaluation"
requires-python = ">=3.12"
dependencies = ["fastapi>=0.115", "uvicorn>=0.30"]

[dependency-groups]
dev = ["pytest>=8", "httpx>=0.27"]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

- [ ] **Step 2:** 根 `pyproject.toml` 的 `[tool.pytest.ini_options]` 加 `testpaths = ["tests"]`；根 `.gitignore` 加 `targets/mock-mall/data/`；`cd targets/mock-mall && uv sync`（生成 .venv 与 uv.lock）
- [ ] **Step 3:** 写 `tests/test_config.py`（测试名固定）：

```python
import pytest
from app.config import Settings

def test_settings_defaults_loopback_and_safe_mode_off():
    s = Settings()
    assert s.host == "127.0.0.1" and s.safe_mode is False and s.port == 8400

def test_settings_refuses_non_loopback_bind_without_opt_in():
    with pytest.raises(RuntimeError):
        Settings(host="0.0.0.0").validate_bind()

def test_settings_allows_non_loopback_bind_with_explicit_opt_in():
    Settings(host="0.0.0.0", allow_remote=True).validate_bind()  # 不抛即过
```

- [ ] **Step 4:** 写 `tests/test_health.py`：

```python
from app.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

def test_health_reports_safe_mode_false(tmp_path):
    c = TestClient(create_app(Settings(db_path=tmp_path / "v.db")))
    assert c.get("/api/health").json()["data"] == {"status": "ok", "safe_mode": False}

def test_health_reports_safe_mode_true(tmp_path):
    c = TestClient(create_app(Settings(db_path=tmp_path / "s.db", safe_mode=True)))
    assert c.get("/api/health").json()["data"]["safe_mode"] is True
```

- [ ] **Step 5:** 运行 `uv run pytest tests/test_config.py tests/test_health.py -v`，Expected: FAIL（模块不存在）
- [ ] **Step 6:** 实现 `app/config.py`（pydantic BaseModel，`from_env` 用 `os.environ.get` 逐字段读默认值；`"1"/"true"` 解析为 bool）与 `app/main.py`（工厂内 `settings.validate_bind()` 不需要——from_env 已做；工厂暂只挂 health 路由）
- [ ] **Step 7:** 运行同两条测试，Expected: 5 PASS
- [ ] **Step 8:** 回根目录 `uv run pytest -q` 确认主包 49 测试仍全绿且未收集 targets/（testpaths 生效）
- [ ] **Step 9:** Commit：`feat(m2-pre): 靶场脚手架与部署安全门（回环绑定+SAFE_MODE）`

---

### Task 2: SQLite schema + 确定性种子 + 认证

**Files:**
- Create: `app/db.py`、`app/seed.py`、`app/auth.py`、`app/routers/__init__.py`、`app/routers/users.py`（本任务只做 GET /api/users/me）
- Test: `tests/__init__.py`（空）、`tests/conftest.py`、`tests/test_db_seed.py`、`tests/test_auth.py`

**Interfaces:**
- Consumes: `config.Settings`、`main.create_app`
- Produces:

```python
# app/db.py
def connect(db_path: Path) -> sqlite3.Connection:
    """sqlite3.connect(db_path, check_same_thread=False)；PRAGMA foreign_keys=ON。"""

def init_schema(conn) -> None:   # DDL 见下，DROP IF EXISTS 后 CREATE（重播种=重建）
def make_lock() -> threading.RLock:

# app/seed.py
def seed(conn, secret: str) -> None:
    """init_schema 后写入固定种子：3 用户（token=sha256(f'{u}:{p}:{secret}').hexdigest()[:32]
    预算好入库）、5 商品、2 券模板；INSERT INTO sqlite_sequence VALUES('orders',1000)
    使订单号从 1001 起。幂等：重复调用结果完全一致。"""

# app/auth.py
def login(request: LoginIn) -> Response    # POST /api/auth/login
def get_current_user(...) -> UserRow       # FastAPI 依赖：Authorization: Bearer <token>
                                           # 查 users.token；缺失/未知 → 401/40101
# app/routers/users.py
# GET /api/users/me → {"user_id","username","nickname","role"}
```

Schema DDL（逐字实现）：

```sql
CREATE TABLE users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL, nickname TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user', token TEXT NOT NULL UNIQUE);
CREATE TABLE products(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  price REAL NOT NULL, stock INTEGER NOT NULL, category TEXT NOT NULL DEFAULT '');
CREATE TABLE coupons(
  id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL UNIQUE, amount REAL NOT NULL);
CREATE TABLE user_coupons(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
  coupon_id INTEGER NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'unused');
CREATE TABLE orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
  total REAL NOT NULL, coupon_id INTEGER, status TEXT NOT NULL DEFAULT 'paid');
CREATE TABLE order_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL, quantity INTEGER NOT NULL, unit_price REAL NOT NULL);
```

- [ ] **Step 1:** 写 `tests/conftest.py`（全项目共用的双模式夹具）：

```python
import pytest
from app.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

def make_client(tmp_path, safe_mode: bool) -> TestClient:
    return TestClient(create_app(Settings(db_path=tmp_path / f"mall-{'safe' if safe_mode else 'vuln'}.db",
                                          safe_mode=safe_mode)))

@pytest.fixture()
def client_vuln(tmp_path):
    return make_client(tmp_path, safe_mode=False)   # SAFE_MODE=0：漏洞全开

@pytest.fixture()
def client_safe(tmp_path):
    return make_client(tmp_path, safe_mode=True)    # SAFE_MODE=1：固定基线

def login(client, username="alice", password="Passw0rd!") -> str:
    return client.post("/api/auth/login",
                       json={"username": username, "password": password}).json()["data"]["token"]

def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
```

- [ ] **Step 2:** 写 `tests/test_db_seed.py`（固定测试名）：
  - `test_seed_deterministic_two_fresh_dbs_identical` — 两个全新 tmp 库各 seed 后，users/products/coupons 全表逐行断言相等（含 token）
  - `test_seed_expected_users_products_coupons` — 3 用户（alice/bob/admin，角色 user/user/admin）、5 商品（id/价格/库存按种子表）、2 券（SAVE10=10.0，BIGSAVE=100.0）
- [ ] **Step 3:** 写 `tests/test_auth.py`：
  - `test_login_returns_stable_token` — alice 登录 200，token 32 位 hex；两次登录 token 相同
  - `test_login_rejects_wrong_password_401`、`test_login_rejects_unknown_user_401`
  - `test_users_me_requires_token_401`（无 header / 伪 token 均 401/40101）
  - `test_users_me_returns_profile`（alice → user_id=1, role="user"）
- [ ] **Step 4:** 运行 `uv run pytest tests/test_db_seed.py tests/test_auth.py -v`，Expected: FAIL
- [ ] **Step 5:** 实现 `db.py`/`seed.py`/`auth.py`/`routers/users.py`；`create_app` 挂 login 与 users 路由（密码明文比对——mock 靶场，README 注明）
- [ ] **Step 6:** 运行同两条测试，Expected: 7 PASS
- [ ] **Step 7:** Commit：`feat(m2-pre): 确定性种子数据与认证`

---

### Task 3: 商品接口 + 订单基线（naive 核心）

**Files:**
- Create: `app/routers/products.py`、`app/routers/orders.py`（本任务：POST /api/orders + GET /api/orders）
- Test: `tests/test_products.py`、`tests/test_orders.py`

**Interfaces:**
- Consumes: Task 2 的 db/auth/seed
- Produces:

```python
# GET /api/products → {"code":0,"data":{"items":[{id,name,price,stock,category},...]}}（公开）
# GET /api/products/{id} → 单条 / 404/40401（公开）

# POST /api/orders（Bearer）请求/响应：
#   req  {"items":[{"product_id":1,"quantity":2,"unit_price":99.0?}],"coupon_code":null?}
#   200  {"code":0,"data":{"order_id":1001,"user_id":1,"total":198.0,
#         "items":[{"product_id":1,"quantity":2,"unit_price":99.0}],
#         "coupon":null}}
# 本任务核心语义（= SAFE 形状的骨架，漏洞分支 Task 4/5/7 打开）：
#   - unit_price 一律忽略，取 DB price（Task 4 在非 SAFE 分支改为采信）
#   - quantity<1 → 400/40001（Task 4 在非 SAFE 分支放行）
#   - 单请求库存检查：quantity>stock → 400/40002
#   - total = float 直算 sum(unit*qty)（MALL-004 现象源头；SAFE 分运算 Task 4 补）
#   - 扣减：SELECT 检查 → UPDATE 扣减（无竞态窗；Task 5 加窗）
# GET /api/orders（Bearer）→ {"orders":[...]} 仅本人订单（两种模式都正确过滤）
```

- [ ] **Step 1:** 写 `tests/test_products.py`：
  - `test_products_list_public_no_auth`（无 token 200，5 条，含 stock 字段）
  - `test_product_detail_public`（商品 5 → price=499.0, stock=1）
  - `test_product_detail_unknown_404`
- [ ] **Step 2:** 写 `tests/test_orders.py`：
  - `test_create_order_baseline_db_price_and_stock_decrement` — alice 买商品 1 ×2 → total=198.0，商品 1 stock 10→8
  - `test_create_order_requires_auth_401`
  - `test_create_order_unknown_product_404`
  - `test_create_order_quantity_exceeds_stock_400`（商品 2 ×6 > 5 → 400/40002，两种模式一致）
  - `test_list_orders_returns_only_own_orders`（alice/bob 各下一单，各自列表只见自己的）
  - `test_order_ids_start_from_1001`（连续两单 → 1001、1002）
- [ ] **Step 3:** 运行 `uv run pytest tests/test_products.py tests/test_orders.py -v`，Expected: FAIL
- [ ] **Step 4:** 实现两个 router（orders 用同步 `def` 端点——线程池并发是 Task 5 竞态的前提；DB 访问一律过 db.py 的锁）
- [ ] **Step 5:** 运行同两条测试，Expected: 9 PASS
- [ ] **Step 6:** Commit：`feat(m2-pre): 商品与订单基线接口`

---

### Task 4: 金额篡改漏洞族（MALL-002 客户端价格 / MALL-003 负数 / MALL-004 浮点精度）

**Files:**
- Modify: `app/routers/orders.py`（create 的 vuln/safe 分支）
- Test: `tests/test_vuln_amount.py`

**Interfaces:**
- Consumes: Task 3 订单核心
- Produces（orders.py 内的分支结构，注释规范即文档）:

```python
# 单价取值：
if not settings.safe_mode and it.unit_price is not None:
    unit = it.unit_price        # VULN(MALL-002/MALL-003): 信任客户端单价（0/负数照收）
else:
    if settings.safe_mode and it.unit_price is not None and it.unit_price < 0:
        return err(400, 40001, "unit_price must be >= 0")   # SAFE(MALL-003): 负单价直接拒绝
    unit = product.price        # SAFE(MALL-002): 服务端价格为准（其余客户端单价一律忽略，含 0）
# 数量校验：
if settings.safe_mode and it.quantity < 1:
    return err(400, 40001, "quantity must be >= 1")   # SAFE(MALL-003)
# 非 SAFE 分支两者皆不校验 → 负单价采信、负数量放行（扣减 stock-qty 反向增库存）  # VULN(MALL-003)
# 金额：
total = math.fsum(u * q for ...)            # VULN(MALL-004): float 直算（0.1+0.2 ≠ 0.3）
total_cents = sum(round(u*100) * q ...)     # SAFE(MALL-004): 分整数运算后 /100
```

- [ ] **Step 1:** 写 `tests/test_vuln_amount.py`（用 conftest 的 `client_vuln`/`client_safe`，测试名固定——meta 测试按前缀配对检查）：

```python
from tests.conftest import login, auth

def test_vuln_mall002_client_price_tampering_001(client_vuln):
    t = login(client_vuln)
    r = client_vuln.post("/api/orders", headers=auth(t),
                         json={"items": [{"product_id": 1, "quantity": 1, "unit_price": 0.01}]})
    assert r.status_code == 200 and r.json()["data"]["total"] == 0.01   # DB 价 99 被无视

def test_vuln_mall002_client_price_zero_purchase(client_vuln):
    t = login(client_vuln)
    r = client_vuln.post("/api/orders", headers=auth(t),
                         json={"items": [{"product_id": 1, "quantity": 1, "unit_price": 0}]})
    assert r.status_code == 200 and r.json()["data"]["total"] == 0.0

def test_safe_mall002_server_price_enforced(client_safe):
    t = login(client_safe)
    r = client_safe.post("/api/orders", headers=auth(t),
                         json={"items": [{"product_id": 1, "quantity": 1, "unit_price": 0.01}]})
    assert r.status_code == 200 and r.json()["data"]["total"] == 99.0

def test_vuln_mall003_negative_unit_price_negative_total(client_vuln):
    t = login(client_vuln)
    r = client_vuln.post("/api/orders", headers=auth(t),
                         json={"items": [{"product_id": 1, "quantity": 1, "unit_price": -50}]})
    assert r.status_code == 200 and r.json()["data"]["total"] == -50.0

def test_vuln_mall003_negative_quantity_increases_stock(client_vuln):
    t = login(client_vuln)
    r = client_vuln.post("/api/orders", headers=auth(t),
                         json={"items": [{"product_id": 1, "quantity": -1}]})
    assert r.status_code == 200
    assert client_vuln.get("/api/products/1").json()["data"]["stock"] == 11  # 10→11

def test_safe_mall003_negative_amounts_rejected_400(client_safe):
    t = login(client_safe)
    r1 = client_safe.post("/api/orders", headers=auth(t),
                          json={"items": [{"product_id": 1, "quantity": 1, "unit_price": -50}]})
    r2 = client_safe.post("/api/orders", headers=auth(t),
                          json={"items": [{"product_id": 1, "quantity": -1}]})
    assert r1.status_code == 400 and r2.status_code == 400
    assert r1.json()["code"] == 40001 and r2.json()["code"] == 40001

def test_vuln_mall004_float_precision_total_artifact(client_vuln):
    # 注：该现象在 Task 3 naive 核心即存在（float 直算），本测试固化漏洞侧事实
    t = login(client_vuln)
    r = client_vuln.post("/api/orders", headers=auth(t),
                         json={"items": [{"product_id": 3, "quantity": 1},
                                         {"product_id": 4, "quantity": 1}]})
    assert r.status_code == 200
    assert r.json()["data"]["total"] == 0.30000000000000004   # 精确双精度比较，≠ 0.3

def test_safe_mall004_cent_math_total_exact(client_safe):
    t = login(client_safe)
    r = client_safe.post("/api/orders", headers=auth(t),
                         json={"items": [{"product_id": 3, "quantity": 1},
                                         {"product_id": 4, "quantity": 1}]})
    assert r.status_code == 200
    assert r.json()["data"]["total"] == 0.3   # 分运算；与 0.3 字面量同一双精度值
```

- [ ] **Step 2:** 运行 `uv run pytest tests/test_vuln_amount.py -v`，Expected: `mall002`/`mall003` 全部 vuln 测试与 `test_safe_mall003` FAIL（Task 3 核心对 unit_price 只忽略不拒绝：负单价 leg 得 200 而非 400），`test_safe_mall004` FAIL（float 直算）；`test_safe_mall002` 与 `test_vuln_mall004` 此时已 PASS（忽略行为与 float 现象在 naive 核心已存在）
- [ ] **Step 3:** 在 orders.py 按 Interfaces 分支结构实现（vuln/safe 注释成对），`math.fsum` 或裸 sum 均可——以 `0.1+0.2` 双精度结果为准确认
- [ ] **Step 4:** 运行同测试，Expected: 8 PASS
- [ ] **Step 5:** Commit：`feat(m2-pre): 金额篡改漏洞族（客户端价格/负数/精度）`

---

### Task 5: 订单竞态超卖（MALL-001）

**Files:**
- Modify: `app/routers/orders.py`（create 的库存检查-扣减段）
- Test: `tests/test_vuln_oversell.py`

**Interfaces:**
- Produces（库存分支结构）:

```python
if settings.safe_mode:
    with lock:   # SAFE(MALL-001): 原子条件扣减，rowcount==0 即库存不足
        cur = conn.execute("UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?",
                           (qty, pid, qty))
        if cur.rowcount == 0:
            return err(400, 40002, "insufficient stock")
else:
    with lock:
        stock = conn.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()[0]
    if stock < qty:
        return err(400, 40002, "insufficient stock")
    time.sleep(settings.race_window_ms / 1000)   # VULN(MALL-001): 竞态窗——锁外、检查与扣减之间
    with lock:
        conn.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (qty, pid))  # 无条件扣减
```

- [ ] **Step 1:** 写 `tests/test_vuln_oversell.py`（并发用 `ThreadPoolExecutor` + `threading.Barrier` 对齐起跑；测试内自建 app 并把 `race_window_ms` 设 200 保证 CI 稳定）：

```python
import threading
from concurrent.futures import ThreadPoolExecutor
from app.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient
from tests.conftest import login, auth

def _two_concurrent_orders(tmp_path, safe_mode):
    settings = Settings(db_path=tmp_path / "m.db", safe_mode=safe_mode, race_window_ms=200)
    app = create_app(settings)
    c1, c2 = TestClient(app), TestClient(app)   # 两个客户端 → 各自事件循环 → 真并发
    pairs = [(c1, login(c1)), (c2, login(c2, "bob"))]
    barrier = threading.Barrier(2)

    def fire(client, token):
        barrier.wait(timeout=10)                # 对齐起跑，确保都落进竞态窗；超时即失败，防挂起
        return client.post("/api/orders", headers=auth(token),
                           json={"items": [{"product_id": 5, "quantity": 1}]})

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(fire, c, t) for c, t in pairs]
        r1, r2 = (f.result() for f in futures)
    return c1, r1, r2

def test_vuln_mall001_concurrent_orders_oversell(tmp_path):
    c1, r1, r2 = _two_concurrent_orders(tmp_path, safe_mode=False)
    assert r1.status_code == 200 and r2.status_code == 200           # 双双成单
    assert c1.get("/api/products/5").json()["data"]["stock"] == -1   # 超卖：库存 -1

def test_safe_mall001_atomic_decrement_no_oversell(tmp_path):
    c1, r1, r2 = _two_concurrent_orders(tmp_path, safe_mode=True)
    assert sorted([r1.status_code, r2.status_code]) == [200, 400]    # 恰一笔成单
    assert c1.get("/api/products/5").json()["data"]["stock"] == 0
```

- [ ] **Step 2:** 运行 `uv run pytest tests/test_vuln_oversell.py -v`，Expected: safe 测试 FAIL（Task 3 核心是"检查→扣减"两步、无原子条件扣减兜底，Barrier 对齐的并发可双双通过→超卖）；vuln 测试**红绿皆可能**——无显式窗口时两请求也可能在检查-扣减间隙交错而过，属预期内的调度不确定性，加显式竞态窗后转为稳定 PASS（红步判据以 safe 测试为准）
- [ ] **Step 3:** 按 Interfaces 实现（sleep 必须在**锁外**——锁内 sleep 会串行化整个窗，竞态消失）
- [ ] **Step 4:** 运行同测试，Expected: 2 PASS
- [ ] **Step 5:** Commit：`feat(m2-pre): 订单竞态超卖漏洞`

---

### Task 6: 越权漏洞（MALL-005 订单 IDOR + MALL-006 垂直提权）

**Files:**
- Modify: `app/routers/orders.py`（加 GET /api/orders/{id}）、`app/routers/users.py`（加 PUT /api/users/me）
- Create: `app/routers/admin.py`
- Test: `tests/test_vuln_idor.py`、`tests/test_vuln_privesc.py`

**Interfaces:**
- Produces:

```python
# GET /api/orders/{id}（Bearer）
order = SELECT * FROM orders WHERE id=?          # 不存在 → 404/40401（两种模式一致）
if settings.safe_mode and order.user_id != current.id:
    return err(403, 40301, "not your order")      # SAFE(MALL-005)
return ok(order_payload)                          # VULN(MALL-005): 无归属校验，任意登录用户可读任意订单

# PUT /api/users/me（Bearer）
updates = {"nickname": req.nickname}
if not settings.safe_mode and req.role is not None:
    updates["role"] = req.role                    # VULN(MALL-006): 角色可自改（mass assignment）
# SAFE(MALL-006): role 字段静默忽略，仅 nickname 生效

# GET /api/admin/users（Bearer）—— 现象面
# 未登录 401/40101；role!="admin" 403/40301（两种模式一致）；admin → 200 全部用户
```

- [ ] **Step 1:** 写 `tests/test_vuln_idor.py`：
  - `test_vuln_mall005_order_detail_cross_user_idor` — alice 下单得 1001；bob 读 1001 → 200 且 `user_id==1`
  - `test_vuln_mall005_order_id_enumeration` — alice/bob 交替下 3 单后，bob 遍历 1001..1003 全部 200
  - `test_safe_mall005_cross_user_403_own_200` — safe 模式 bob 读 alice 单 403/40301、读自己单 200
  - `test_order_detail_unknown_404`（两种模式一致：id=9999 → 404）
- [ ] **Step 2:** 写 `tests/test_vuln_privesc.py`：
  - `test_admin_users_requires_admin_403_and_anon_401` — 基线：未登录 401；bob（user）403；seed 的 admin 账号 200（正常功能，两种模式一致）
  - `test_vuln_mall006_role_mass_assignment_privesc` — alice `PUT {"role":"admin"}` → 200 返回 role="admin"；原 token 调 `GET /api/admin/users` → 200 拿到全部用户
  - `test_safe_mall006_role_assignment_ignored` — safe 模式同操作后 role 仍 "user"，admin 接口 403/40301
- [ ] **Step 3:** 运行 `uv run pytest tests/test_vuln_idor.py tests/test_vuln_privesc.py -v`，Expected: FAIL
- [ ] **Step 4:** 按 Interfaces 实现三处；`create_app` 挂 admin 路由
- [ ] **Step 5:** 运行同测试，Expected: 7 PASS
- [ ] **Step 6:** Commit：`feat(m2-pre): 越权漏洞（订单 IDOR 与垂直提权）`

---

### Task 7: 优惠券漏洞族（MALL-007 循环领取 / MALL-008 面额篡改 / MALL-009 并发核销）

**Files:**
- Create: `app/routers/coupons.py`
- Modify: `app/routers/orders.py`（create 接入 coupon_code 核销）
- Test: `tests/test_vuln_coupon.py`

**Interfaces:**
- Produces:

```python
# POST /api/coupons/claim（Bearer）req {"code":"SAVE10"[,"amount":10000?]}
#   200 {"user_coupon_id":1,"code":"SAVE10","amount":10.0,"status":"unused"}；未知 code → 404
if not settings.safe_mode:
    amount = req.amount if req.amount is not None else template.amount
    # VULN(MALL-008): 客户端 amount 覆写实例面额（负数/超大照收）
    # VULN(MALL-007): 无领取上限——每次 claim 都插新实例
else:
    # SAFE(MALL-007): 每用户每码限 1 张，重复 → 400/40003
    # SAFE(MALL-008): amount 一律取模板面额

# POST /api/orders 的 coupon_code 核销段：
# 实例匹配：本人该码 **status='unused'** 的实例（id 最小者优先）；无匹配 → 400/40003
#   —— 未使用限定是 MALL-007 的前提：第二张订单须匹配到第 2 个未用实例才享折扣
uc = SELECT user_coupons JOIN coupons ... WHERE user_id=? AND code=? AND status='unused'
     ORDER BY id LIMIT 1
if not settings.safe_mode:
    time.sleep(race_window_ms/1000)          # VULN(MALL-009): 检查（SELECT 已过滤 unused）与回写分离（锁外竞态窗）
    UPDATE user_coupons SET status='used' WHERE id=?   # 无条件回写 → 一券两用
    total -= uc.amount                       # VULN 系 float 减
else:
    cur = UPDATE user_coupons SET status='used' WHERE id=? AND status='unused'  # SAFE(MALL-009): 原子
    if cur.rowcount == 0: 400/40003
    total_cents -= round(uc.amount * 100)    # SAFE 系分运算

# POST /api/orders 全流程事务顺序（两种模式一致；Task 5 草图中窗口后的扣减移入本节统一落库）：
#   1. 校验（商品存在性/价格取值/数量/金额）——纯读，无写入
#   2. 模式分支的检查与竞态窗（窗在锁外；库存 SELECT 与券 SELECT 各带一个窗）
#   3. 单一锁定事务：库存扣减 + 券核销回写 + orders/order_items INSERT → COMMIT
#      事务内任一步要 err() 返回 → 先 ROLLBACK 再返回——不落无券订单、不烧券、不留孤儿扣减
#   （SAFE(MALL-009) 的核销与订单 INSERT 同事务：核销失败整单 400，库存/券/订单零残留）
```

- [ ] **Step 1:** 写 `tests/test_vuln_coupon.py`（测试名固定）：
  - `test_claim_happy_path`（领 SAVE10 → 200，amount=10.0，status="unused"）
  - `test_claim_unknown_code_404`
  - `test_order_with_legit_coupon_discounts_total`（商品 1 ×1 + SAVE10 → total=89.0）
  - `test_vuln_mall007_unlimited_claims_reuse` — alice 连领 SAVE10 两次（两次均 200、两个实例）→ 两笔订单各享 10 元折扣（89.0 ×2）
  - `test_safe_mall007_claim_once_per_user_per_code` — 第 2 次领取 400/40003
  - `test_vuln_mall008_claim_amount_tampering_negative_total` — `{"code":"SAVE10","amount":10000}` 领取后买商品 5 → total == -9501.0
  - `test_vuln_mall008_claim_negative_denomination_increases_total` — amount=-50 → total == 549.0（499+50）
  - `test_safe_mall008_claim_ignores_client_amount` — 同篡改请求，实例 amount==10.0，订单 total==489.0
  - `test_vuln_mall009_concurrent_redeem_double_discount` — 领 1 张后两并发订单（Task 5 同款 Barrier 手法，`wait(timeout=10)`，race_window_ms=200，商品 1 各 ×1）→ 均 200 且 total 均 89.0
  - `test_safe_mall009_atomic_redeem_single_use` — 同场景 safe 模式：一笔 200（total=89.0），另一笔 400/40003（整单拒绝）；随后 `GET /api/orders` 断言 alice 名下**仅 1 笔订单**且 total=89.0——无无券订单、无半单残留（对应事务顺序规约）
- [ ] **Step 2:** 运行 `uv run pytest tests/test_vuln_coupon.py -v`，Expected: FAIL
- [ ] **Step 3:** 按 Interfaces 实现 coupons 路由与 orders 核销段；同时把 create_order 落库阶段重构为 Interfaces 规约的单一锁定事务（Task 5 草图中窗口后的无条件扣减移入事务，行为不变——Task 4/5 既有测试保持全绿）；下单请求 `coupon_code=null` 时行为与 Task 4/5 完全一致
- [ ] **Step 4:** 运行 `uv run pytest -v`（全量），Expected: 全绿（本任务 10 条 + 前序全部）
- [ ] **Step 5:** Commit：`feat(m2-pre): 优惠券漏洞族（循环领取/面额篡改/并发核销）`

---

### Task 8: ground truth 落库 + 一键部署 + 验收收尾

**Files:**
- Create: `targets/mock-mall/ground_truth.yaml`、`GROUND_TRUTH.md`、`Dockerfile`、`.dockerignore`、`docker-compose.yml`、`README.md`、`app/__main__.py`
- Modify: 根 `README.md`（§6 当前状态补 M2-pre 一条）
- Test: `tests/test_ground_truth.py`

**Interfaces:**
- Produces:

```yaml
# ground_truth.yaml（单一事实源；9 条逐字取自本 plan「Ground Truth 总表」两节）
- id: MALL-001          # 其余字段：title/category/surface/endpoint/trigger/phenomenon/
  title: 订单竞态超卖    #           safe_mode_behavior/detection_tags——值照抄总表
  category: race        # category ∈ {race, amount, authz, coupon}
  surface: order        # surface ∈ {auth, order, payment, coupon, user, admin}（PLAN §3.2）
  endpoint: POST /api/orders
  trigger: 商品 5（stock=1）；alice、bob 两个并发请求各提交 {"items":[{"product_id":5,"quantity":1}]}（竞态窗内同时通过库存检查）
  phenomenon: 两个请求均 HTTP 200、两张订单均创建；随后 GET /api/products/5 返回 stock=-1
  safe_mode_behavior: 原子条件扣减，仅 1 笔 200，另一笔 400/40002，stock=0
  detection_tags: [http_2xx]
# ……MALL-002..MALL-009 同构，共 9 条
```

```dockerfile
# Dockerfile
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY app ./app
EXPOSE 8400
CMD ["uv", "run", "--no-dev", "python", "-m", "app"]   # 走 Settings.from_env() 守卫路径
```

```yaml
# docker-compose.yml
services:
  mock-mall:
    build: .
    ports:
      - "127.0.0.1:8400:8400"   # 宿主机侧仅回环可达——靶场唯一入口
    environment:
      MALL_HOST: "0.0.0.0"       # 容器内监听（容器网络隔离，无其他发布口）
      MALL_ALLOW_REMOTE: "1"     # 非回环绑定显式豁免（对应 Global Constraints）
      SAFE_MODE: "${SAFE_MODE:-0}"
      MALL_SEED: "1"             # 每次启动确定性重置
```

```python
# app/__main__.py
import uvicorn
from app.config import Settings

s = Settings.from_env()          # 含 validate_bind：非回环未豁免直接拒绝启动
uvicorn.run("app.main:app", host=s.host, port=s.port)
```

- [ ] **Step 1:** 写 `tests/test_ground_truth.py`：
  - `test_ground_truth_yaml_schema_and_tag_vocabulary` — 9 条；id 唯一且为 MALL-001..009；字段齐全非空；`detection_tags ⊆ {PLAN §3.2 的 15 tag}`（http_2xx/http_401/http_403/http_404/http_429/http_5xx/timeout/dns_fail/tls_error/waf_block_page/redirect_external/set_cookie/rate_limited/body_reflect/body_diff）；`category ∈ {race,amount,authz,coupon}`；`surface ∈ {auth,order,payment,coupon,user,admin}`
  - `test_ground_truth_md_yaml_in_sync` — GROUND_TRUTH.md 中出现的 MALL-xxx 集合与 yaml 完全一致（无多无少）
  - `test_every_vuln_has_paired_vuln_and_safe_tests` — 对每个 yaml id（slug 如 `mall002`），`tests/test_vuln_*.py` 五个模块的全部函数名中存在 `test_vuln_<slug>_` 前缀与 `test_safe_<slug>_` 前缀各至少 1 个
- [ ] **Step 2:** 运行 `uv run pytest tests/test_ground_truth.py -v`，Expected: FAIL
- [ ] **Step 3:** 写 `ground_truth.yaml`（9 条逐字照抄本 plan 总表）与 `GROUND_TRUTH.md`（同表 markdown 化 + 阅读说明：这是靶场答案册，M2 评测前勿喂给被测 agent）
- [ ] **Step 4:** 运行 `uv run pytest tests/test_ground_truth.py -v`，Expected: 3 PASS
- [ ] **Step 5:** 写 `app/__main__.py`、`Dockerfile`、`.dockerignore`（.venv/tests/data/__pycache__）、`docker-compose.yml`、`README.md`（首行加粗警告：**故意脆弱·仅限本机 localhost 测试靶场，禁止暴露公网**；一键部署 `docker compose up -d --build`；`SAFE_MODE=1 docker compose up -d --build` 起基线；种子账号表；GROUND_TRUTH.md 链接）
- [ ] **Step 6:** 一键部署验收（有 docker 环境时）：
  - `cd targets/mock-mall && docker compose up -d --build`
  - `curl -s http://127.0.0.1:8400/api/health` → `{"code":0,...,"safe_mode":false}`
  - 抽查 1 条 ground truth（MALL-005 现象）：curl 用 alice 登录并下一单（得订单 1001）→ 换 bob 的 token `GET /api/orders/1001` → 200 返回 alice 的订单
  - `docker compose down && SAFE_MODE=1 docker compose up -d --build` 重建 → health `"safe_mode":true`，bob 同请求 → 403
  - 无 docker 环境时以 `uv run python -m app`（另一终端 curl 同序列验证）+ `docker compose config` 语法校验替代，并在 PR 注明
- [ ] **Step 7:** M2-pre 验收对照（PLAN §7 M2-pre 行）：
  - [ ] 靶场可部署：一条命令起靶场，health/self-check 通过
  - [ ] ground truth 清单完备：9 条全字段 + MD/YAML 同步 + vuln/safe 测试配对（3 条 meta 测试绿）
  - [ ] 确定性：重部署后种子/token/订单号完全一致（`test_seed_deterministic...` 绿）
- [ ] **Step 8:** 根 `README.md` §6 补一行 M2-pre 状态与 `targets/mock-mall/` 指引；`uv run pytest -v`（靶场全量 51 测试）+ 根目录 `uv run pytest -q`（主包 49 测试）双绿
- [ ] **Step 9:** Commit：`feat(m2-pre): ground truth 落库与一键部署（docker-compose）`
- [ ] **Step 10:** Commit：`chore(m2-pre): M2-pre 验收通过，文档状态更新`；push 全部提交
