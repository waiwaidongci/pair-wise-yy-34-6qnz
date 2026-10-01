# 工伤事故调查与纠正措施

记录工伤经过、伤害、现场和证人，维护调查、纠正措施、验证与关闭流程。支持**可恢复的续办交接**：短期持有凭证 + 检查点 + 超时交接 + 迟到提交留史 + 失败重试。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误（携带details）、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限、租约TTL与关闭不变量。
- `src/repository.py`：SQLite建表/老库迁移、事务、版本控制、租约/检查点/交接/尝试/迟到历史和审计链。
- `src/service.py`：权限检查、用例编排、领取续办、失败重试、超时扫描、即时重算与封存。
- `src/http_api.py`：JSON路由（GET/POST/PATCH）和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：续办工作台演示页（当前持有人、失效原因、重试结果）。
- `tests/`：完整流程、规则、失败、交接续办和HTTP端到端测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8311
```

默认端口为`8311`，首次启动自动建库；老库启动时自动迁移（补齐列、回填优先级/期限、把历史已关闭事故标记封存）。使用`X-Actor`和`X-Role`请求头传递身份。

## 可恢复续办流程

1. **领取** `POST /api/items/{id}/claim` `{ttl_seconds?}`（investigator/safety_manager）：
   生成随机短期持有凭证 token（默认600秒，1~86400），同时写第一条检查点和 `start` 交接。
   TTL 内他人领取返回 409 并携带当前持有人。领取响应的 `resume` 给出最近检查点、现场记录和失败尝试，掉线回来从这里续查。
2. **续办** `POST /api/items/{id}/continue` `{token, batch_ref, records[]}`：
   只有当前持有人本人能提交；整批措施在一个事务内写入，成功后推进到新检查点，并即时重算优先级/期限。
   - 同一 `batch_ref` 重复提交幂等返回 `duplicate:true`，**不重复生成措施**。
   - 校验失败或措施标识冲突：整批不生效，写 `failed` 尝试，409/422 响应带 `attempt_id` 和 `retriable:true`，可用同批次号重试。
3. **超时交接**：每次读/领/续办前自动扫描到期租约，标记 `expired`（reason=`timeout`），
   最近检查点保留现场进度；下一人领取时 handoff 记录 `timeout`，响应标明从哪个检查点恢复。主动释放走 `/release`（reason=`release`）。
4. **迟到提交只留历史**：旧持有人掉线回来后用失效/他人/封存凭证提交（包括重试），
   内容写入 `stale_submissions`（token 脱敏、只留指纹），返回 `stale:true, applied:false` 及失效原因与当前持有人，
   **不覆盖当前续办、不生成措施**。失效原因：`token_invalid / lease_expired / lease_released / lease_sealed`。
5. **重试** `POST /api/items/{id}/retry` `{token, batch_ref, records?}`：
   复用原批次号；失败时保存的措施内容可缺省复用；成功后再次重试幂等；凭证已失效则重试本身也只进历史（`retry_result:"stale"`）。

## 严重度/伤害指数与封存

- `PATCH /api/items/{id}` `{severity?, quantity?, expected_version}`（safety_manager）：
  改动后**立即重算该未关闭事故**的 priority/deadline_hours（纳入未关闭措施数）并写审计。
- 事故流转到 `closed` 时**封存**：`sealed=1` 并快照 priority/deadline_hours，活跃租约置 `sealed`；
  封存事故拒绝 PATCH、拒绝领取/续办，展示永远保留关闭时原结果。

## 主要接口

- `GET /health`
- `GET /api/items`（列表含 current_holder、lease_expires_at、sealed）
- `POST /api/items`
- `GET /api/items/{id}`（含 `continuation`：当前持有人、最近检查点、交接链、尝试、迟到历史、最近失效原因与重试结果）
- `POST /api/items/{id}/records`（旧的无租约现场记录入口，仍可用）
- `POST /api/items/{id}/transition`，必须提交`expected_version`（关闭即封存）
- `POST /api/items/{id}/claim` / `/release` / `/continue` / `/retry`
- `PATCH /api/items/{id}`（重算未关闭事故）
- `GET /api/audit`（claim / continuation / continuation_failed / lease_timeout / lease_release / stale_submission / severity_change / transition(sealed) 全部入链）

允许角色：reporter, investigator, safety_manager, viewer。严重度越高、伤害指数越大或未关闭措施越多，优先级越高；严重事故必须在4小时内启动调查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
