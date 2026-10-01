from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import STATES

LEASE_ACTIVE = "active"
REASON_TIMEOUT = "timeout"
REASON_RELEASE = "release"
REASON_START = "start"
REASON_SEALED = "sealed"


class Repository:
    def __init__(self, db_path: str, now_fn: Callable[[], str] = utc_now):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.now_fn = now_fn
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()
        self._migrate()

    # ---------------------------------------------------------------- schema
    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        lease_states = "'" + "','".join(("active", "expired", "released", "sealed")) + "'"
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    priority INTEGER,
                    deadline_hours INTEGER,
                    sealed INTEGER NOT NULL DEFAULT 0,
                    sealed_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    batch_ref TEXT,
                    checkpoint_id INTEGER,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS leases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    token TEXT NOT NULL UNIQUE,
                    holder TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ({lease_states})),
                    invalidated_reason TEXT,
                    invalidated_at TEXT,
                    attempt_no INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS ix_leases_item ON leases(item_id, id);
                CREATE TABLE IF NOT EXISTS checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    lease_id INTEGER REFERENCES leases(id),
                    seq INTEGER NOT NULL,
                    item_version INTEGER NOT NULL,
                    item_status TEXT NOT NULL,
                    open_record_count INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, seq)
                );
                CREATE TABLE IF NOT EXISTS handoffs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    from_lease_id INTEGER REFERENCES leases(id),
                    to_lease_id INTEGER REFERENCES leases(id),
                    from_checkpoint_id INTEGER REFERENCES checkpoints(id),
                    reason TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_handoffs_item ON handoffs(item_id, id);
                CREATE TABLE IF NOT EXISTS continuation_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    lease_id INTEGER REFERENCES leases(id),
                    checkpoint_id INTEGER REFERENCES checkpoints(id),
                    batch_ref TEXT NOT NULL,
                    result TEXT NOT NULL CHECK(result IN ('failed','succeeded')),
                    error_kind TEXT,
                    message TEXT NOT NULL,
                    retriable INTEGER NOT NULL DEFAULT 1,
                    retried_of_id INTEGER REFERENCES continuation_attempts(id),
                    payload TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_attempt_succeeded
                    ON continuation_attempts(item_id, batch_ref)
                    WHERE result='succeeded';
                CREATE INDEX IF NOT EXISTS ix_attempts_item ON continuation_attempts(item_id, id);
                CREATE TABLE IF NOT EXISTS stale_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    lease_id INTEGER,
                    token_fingerprint TEXT,
                    batch_ref TEXT,
                    payload TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    submitted_by TEXT NOT NULL,
                    submitted_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_stale_item ON stale_submissions(item_id, id);
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)

    def _migrate(self) -> None:
        """给老库补齐新列，并回填封存快照。"""
        from .rules import priority_score, response_deadline_hours, is_sealed_status
        with self._lock, self.conn:
            cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(items)")}
            adds = [
                ("priority", "ALTER TABLE items ADD COLUMN priority INTEGER"),
                ("deadline_hours", "ALTER TABLE items ADD COLUMN deadline_hours INTEGER"),
                ("sealed", "ALTER TABLE items ADD COLUMN sealed INTEGER NOT NULL DEFAULT 0"),
                ("sealed_at", "ALTER TABLE items ADD COLUMN sealed_at TEXT"),
            ]
            for name, sql in adds:
                if name not in cols:
                    self.conn.execute(sql)
            rcols = {r["name"] for r in self.conn.execute("PRAGMA table_info(records)")}
            if "batch_ref" not in rcols:
                self.conn.execute("ALTER TABLE records ADD COLUMN batch_ref TEXT")
            if "checkpoint_id" not in rcols:
                self.conn.execute("ALTER TABLE records ADD COLUMN checkpoint_id INTEGER")
            rows = self.conn.execute(
                "SELECT id, severity, quantity, threshold, status, priority, deadline_hours "
                "FROM items WHERE priority IS NULL OR deadline_hours IS NULL"
            ).fetchall()
            for row in rows:
                priority = priority_score(row["severity"], row["quantity"], row["threshold"])
                deadline = response_deadline_hours(
                    row["severity"], row["quantity"], row["threshold"])
                self.conn.execute(
                    "UPDATE items SET priority=?, deadline_hours=? WHERE id=?",
                    (priority, deadline, row["id"]))
            self.conn.execute(
                "UPDATE items SET sealed=1 WHERE status='closed' AND sealed=0")

    def now(self) -> str:
        return self.now_fn()

    # ------------------------------------------------------------------ items
    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, priority: int, deadline_hours: int) -> Dict[str, Any]:
        now = self.now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, priority, deadline_hours, sealed,
                       created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, priority, deadline_hours, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def list_open_items(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM items WHERE sealed=0 ORDER BY id").fetchall()
        return [self._item(row) for row in rows]

    def update_metrics(self, item_id: int, priority: int, deadline_hours: int) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE items SET priority=?, deadline_hours=?, updated_at=? "
                "WHERE id=? AND sealed=0",
                (priority, deadline_hours, self.now(), item_id))

    def patch_item(self, item_id: int, severity: str, quantity: float,
                   expected_version: int, priority: int, deadline_hours: int) -> Dict[str, Any]:
        now = self.now()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT sealed, status FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("项目不存在")
            if row["sealed"]:
                raise ConflictError("已封存的已关闭事故不能修改严重度或伤害指数")
            cur = self.conn.execute(
                """UPDATE items SET severity=?, quantity=?, priority=?, deadline_hours=?,
                   version=version+1, updated_at=?
                   WHERE id=? AND version=? AND sealed=0""",
                (severity, quantity, priority, deadline_hours, now,
                 item_id, expected_version))
            if cur.rowcount == 0:
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = self.now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def seal_item(self, item_id: int) -> None:
        """关闭瞬间封存当前期限/优先级快照，之后重算不再触及它。"""
        now = self.now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE items SET sealed=1, sealed_at=? WHERE id=?", (now, item_id))
            self.conn.execute(
                "UPDATE leases SET status='sealed', invalidated_reason=?, invalidated_at=? "
                "WHERE item_id=? AND status='active'",
                (REASON_SEALED, now, item_id))

    # ---------------------------------------------------------------- records
    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str,
                   batch_ref: Optional[str] = None,
                   checkpoint_id: Optional[int] = None) -> Dict[str, Any]:
        now = self.now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       batch_ref, checkpoint_id, created_by, created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, batch_ref,
                     checkpoint_id, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    # ----------------------------------------------------------------- leases
    def expire_active_leases(self) -> List[Dict[str, Any]]:
        """把所有到期租约标记失效。返回刚失效的租约（供服务写交接/审计）。"""
        now = self.now()
        expired: List[Dict[str, Any]] = []
        with self._lock, self.conn:
            rows = self.conn.execute(
                "SELECT * FROM leases WHERE status='active' AND expires_at<=?",
                (now,)).fetchall()
            for row in rows:
                self.conn.execute(
                    "UPDATE leases SET status='expired', invalidated_reason=?, "
                    "invalidated_at=? WHERE id=?",
                    (REASON_TIMEOUT, now, row["id"]))
                lease = dict(row)
                lease["status"] = "expired"
                lease["invalidated_reason"] = REASON_TIMEOUT
                lease["invalidated_at"] = now
                expired.append(lease)
        return expired

    def get_lease(self, lease_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM leases WHERE id=?", (lease_id,)).fetchone()
        if row is None:
            raise NotFoundError("持有凭证不存在")
        return dict(row)

    def get_active_lease(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM leases WHERE item_id=? AND status='active' AND expires_at>? "
                "ORDER BY id DESC LIMIT 1",
                (item_id, self.now())).fetchone()
        return dict(row) if row else None

    def find_lease_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        if not isinstance(token, str) or not token:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM leases WHERE token=?", (token,)).fetchone()
        return dict(row) if row else None

    def claim(self, item_id: int, holder: str, ttl_seconds: int,
              summary: str, open_records: int, item_version: int,
              item_status: str, attempt_no: int) -> Dict[str, Any]:
        now = self.now()
        token = secrets.token_urlsafe(24)
        with self._lock, self.conn:
            exists = self.conn.execute(
                "SELECT 1 FROM leases WHERE item_id=? AND status='active' AND expires_at>?",
                (item_id, now)).fetchone()
            if exists:
                raise ConflictError("该事故已有在期持有人，请等待其超时或释放")
            cur = self.conn.execute(
                """INSERT INTO leases(item_id, token, holder, acquired_at, expires_at,
                   status, attempt_no) VALUES(?,?,?,?,?, 'active', ?)""",
                (item_id, token, holder, now,
                 self._shift(now, ttl_seconds), attempt_no))
            lease_id = int(cur.lastrowid)
            row = self.conn.execute(
                "SELECT COALESCE(MAX(seq),0)+1 AS next_seq FROM checkpoints WHERE item_id=?",
                (item_id,)).fetchone()
            seq = int(row["next_seq"])
            ccur = self.conn.execute(
                """INSERT INTO checkpoints(item_id, lease_id, seq, item_version, item_status,
                   open_record_count, summary, created_by, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (item_id, lease_id, seq, item_version, item_status,
                 open_records, summary, holder, now))
            checkpoint_id = int(ccur.lastrowid)
        lease = self.get_lease(lease_id)
        lease["checkpoint_id"] = checkpoint_id
        return lease

    def release_lease(self, lease_id: int) -> None:
        now = self.now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE leases SET status='released', invalidated_reason=?, invalidated_at=? "
                "WHERE id=? AND status='active'",
                (REASON_RELEASE, now, lease_id))

    def next_attempt_no(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COALESCE(MAX(attempt_no),0)+1 AS n FROM leases WHERE item_id=?",
                (item_id,)).fetchone()
        return int(row["n"])

    # ------------------------------------------------------------- checkpoints
    def latest_checkpoint(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM checkpoints WHERE item_id=? ORDER BY seq DESC LIMIT 1",
                (item_id,)).fetchone()
        return dict(row) if row else None

    def get_checkpoint(self, checkpoint_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM checkpoints WHERE id=?", (checkpoint_id,)).fetchone()
        if row is None:
            raise NotFoundError("检查点不存在")
        return dict(row)

    def create_checkpoint(self, item_id: int, lease_id: int, item_version: int,
                          item_status: str, open_records: int, summary: str,
                          actor: str) -> Dict[str, Any]:
        now = self.now()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT COALESCE(MAX(seq),0)+1 AS next_seq FROM checkpoints WHERE item_id=?",
                (item_id,)).fetchone()
            seq = int(row["next_seq"])
            cur = self.conn.execute(
                """INSERT INTO checkpoints(item_id, lease_id, seq, item_version, item_status,
                   open_record_count, summary, created_by, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (item_id, lease_id, seq, item_version, item_status,
                 open_records, summary, actor, now))
            checkpoint_id = int(cur.lastrowid)
        return self.get_checkpoint(checkpoint_id)

    # ---------------------------------------------------------------- handoffs
    def insert_handoff(self, item_id: int, from_lease_id: Optional[int],
                       to_lease_id: Optional[int], from_checkpoint_id: Optional[int],
                       reason: str, detail: str, actor: str) -> Dict[str, Any]:
        now = self.now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO handoffs(item_id, from_lease_id, to_lease_id,
                   from_checkpoint_id, reason, detail, created_by, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, from_lease_id, to_lease_id, from_checkpoint_id,
                 reason, detail, actor, now))
            handoff_id = int(cur.lastrowid)
            row = self.conn.execute(
                "SELECT * FROM handoffs WHERE id=?", (handoff_id,)).fetchone()
        return dict(row)

    def list_handoffs(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM handoffs WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
        return [dict(row) for row in rows]

    def list_checkpoints(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM checkpoints WHERE item_id=? ORDER BY seq",
                (item_id,)).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------- attempts
    def get_attempt(self, attempt_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM continuation_attempts WHERE id=?",
                (attempt_id,)).fetchone()
        return dict(row) if row else None

    def find_attempt_by_batch(self, item_id: int, batch_ref: str) -> Optional[Dict[str, Any]]:
        """成功尝试优先（最多一条）；否则返回最近一次失败尝试。"""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM continuation_attempts WHERE item_id=? AND batch_ref=? "
                "ORDER BY CASE result WHEN 'succeeded' THEN 0 ELSE 1 END, id DESC LIMIT 1",
                (item_id, batch_ref)).fetchone()
        return dict(row) if row else None

    def record_failed_attempt(self, item_id: int, lease_id: Optional[int],
                              checkpoint_id: Optional[int], batch_ref: str,
                              error_kind: str, message: str, retriable: bool,
                              actor: str, payload: Dict[str, Any],
                              retried_of_id: Optional[int] = None) -> Dict[str, Any]:
        now = self.now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO continuation_attempts(item_id, lease_id, checkpoint_id,
                   batch_ref, result, error_kind, message, retriable, retried_of_id,
                   payload, created_by, created_at)
                   VALUES(?,?,?,?,'failed',?,?,?,?,?,?,?)""",
                (item_id, lease_id, checkpoint_id, batch_ref, error_kind, message,
                 1 if retriable else 0, retried_of_id,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
                 actor, now))
            attempt_id = int(cur.lastrowid)
        return self.get_attempt(attempt_id)

    def list_attempts(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM continuation_attempts WHERE item_id=? ORDER BY id",
                (item_id,)).fetchall()
        result = []
        for row in rows:
            entry = dict(row)
            if entry.get("payload"):
                entry["payload"] = json.loads(entry["payload"])
            result.append(entry)
        return result

    # ------------------------------------------------------- stale submissions
    def record_stale_submission(self, item_id: int, lease_id: Optional[int],
                                token_fingerprint: str, batch_ref: Optional[str],
                                payload: Dict[str, Any], reason: str,
                                actor: str) -> Dict[str, Any]:
        now = self.now()
        safe_payload = dict(payload)
        if "token" in safe_payload:
            safe_payload["token"] = "***redacted***"
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO stale_submissions(item_id, lease_id, token_fingerprint,
                   batch_ref, payload, reason, submitted_by, submitted_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, lease_id, token_fingerprint, batch_ref,
                 json.dumps(safe_payload, ensure_ascii=False, sort_keys=True, default=str),
                 reason, actor, now))
            stale_id = int(cur.lastrowid)
            row = self.conn.execute(
                "SELECT * FROM stale_submissions WHERE id=?", (stale_id,)).fetchone()
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def list_stale_submissions(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM stale_submissions WHERE item_id=? ORDER BY id",
                (item_id,)).fetchall()
        result = []
        for row in rows:
            entry = dict(row)
            entry["payload"] = json.loads(entry["payload"])
            result.append(entry)
        return result

    # ------------------------------------------------------------- continuations
    def apply_continuation(self, item_id: int, lease_id: int, checkpoint_id: int,
                           records: List[Dict[str, Any]], batch_ref: str,
                           priority: int, deadline_hours: int, actor: str,
                           retried_of_id: Optional[int]) -> Dict[str, Any]:
        """一次事务内：写入措施记录、推进检查点、登记成功尝试、刷新指标。"""
        now = self.now()
        with self._lock, self.conn:
            record_ids: List[int] = []
            try:
                for rec in records:
                    cur = self.conn.execute(
                        """INSERT INTO records(item_id, kind, detail, status, external_ref,
                           batch_ref, checkpoint_id, created_by, created_at)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (item_id, rec["kind"], rec["detail"], rec["status"],
                         rec.get("external_ref"), batch_ref, checkpoint_id, actor, now))
                    record_ids.append(int(cur.lastrowid))
                item_row = self.conn.execute(
                    "SELECT version, status FROM items WHERE id=?", (item_id,)).fetchone()
                open_count = int(self.conn.execute(
                    "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                    (item_id,)).fetchone()["n"])
                summary = self._summary_text(batch_ref, len(record_ids), open_count)
                crow = self.conn.execute(
                    "SELECT COALESCE(MAX(seq),0)+1 AS next_seq FROM checkpoints WHERE item_id=?",
                    (item_id,)).fetchone()
                new_cp = self.conn.execute(
                    """INSERT INTO checkpoints(item_id, lease_id, seq, item_version, item_status,
                       open_record_count, summary, created_by, created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (item_id, lease_id, int(crow["next_seq"]), int(item_row["version"]),
                     item_row["status"], open_count, summary, actor, now))
                new_checkpoint_id = int(new_cp.lastrowid)
                self.conn.execute(
                    "UPDATE items SET priority=?, deadline_hours=?, updated_at=? "
                    "WHERE id=? AND sealed=0",
                    (priority, deadline_hours, now, item_id))
                acur = self.conn.execute(
                    """INSERT INTO continuation_attempts(item_id, lease_id, checkpoint_id,
                       batch_ref, result, error_kind, message, retriable, retried_of_id,
                       created_by, created_at)
                       VALUES(?,?,?,?,'succeeded',NULL,?,0,?,?,?)""",
                    (item_id, lease_id, new_checkpoint_id, batch_ref,
                     f"批次{batch_ref}已续办，生成{len(record_ids)}条措施记录",
                     retried_of_id, actor, now))
                attempt_id = int(acur.lastrowid)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("记录唯一标识已存在，整批未生效，请修正后重试") from exc
        return {
            "attempt_id": attempt_id,
            "record_ids": record_ids,
            "checkpoint": self.get_checkpoint(new_checkpoint_id),
            "item": self.get_item(item_id),
        }

    # ------------------------------------------------------------------ audit
    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _shift(iso_ts: str, seconds: int) -> str:
        from datetime import datetime, timedelta
        dt = datetime.fromisoformat(iso_ts)
        return (dt + timedelta(seconds=seconds)).replace(microsecond=0).isoformat()

    @staticmethod
    def _summary_text(batch_ref: str, record_count: int, open_count: int) -> str:
        return f"批次{batch_ref}续办完成：新增{record_count}条记录，未关闭措施{open_count}条"

    def close(self) -> None:
        with self._lock:
            self.conn.close()
