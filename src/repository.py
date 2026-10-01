from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (ATTEMPT_FAILED, ATTEMPT_QUARANTINED, ATTEMPT_SUCCEEDED,
                    CHECKPOINT_CLAIM, CHECKPOINT_HANDOVER, CHECKPOINT_PROGRESS,
                    ID_PREFIX, LEASE_ACTIVE, LEASE_EXPIRED, LEASE_RELEASED,
                    LEASE_TAKEN_OVER, STATES, priority_score,
                    response_deadline_hours)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
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
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
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
                CREATE TABLE IF NOT EXISTS checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    lease_token TEXT NOT NULL,
                    holder TEXT NOT NULL,
                    kind TEXT NOT NULL
                        CHECK(kind IN ('claim','progress','handover')),
                    seq INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_checkpoints_item
                    ON checkpoints(item_id, id);
                CREATE TABLE IF NOT EXISTS leases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    token TEXT NOT NULL UNIQUE,
                    holder TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('active','expired','released','taken_over')),
                    checkpoint_id INTEGER,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_leases_item
                    ON leases(item_id, id);
                CREATE TABLE IF NOT EXISTS late_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    lease_token TEXT,
                    holder TEXT,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS followup_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    idempotency_key TEXT NOT NULL,
                    lease_token TEXT,
                    holder TEXT,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('succeeded','failed','quarantined')),
                    record_id INTEGER,
                    failure_reason TEXT,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(item_id, idempotency_key)
                );
            """)
            self._migrate_items()

    def _migrate_items(self) -> None:
        """为旧库补充续办与封存字段（幂等）。"""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(items)").fetchall()}
        additions = {
            "holder": "TEXT",
            "lease_token": "TEXT",
            "lease_expires_at": "TEXT",
            "checkpoint_id": "INTEGER",
            "priority": "INTEGER",
            "deadline_hours": "INTEGER",
            "sealed_priority": "INTEGER",
            "sealed_deadline_hours": "INTEGER",
            "sealed_at": "TEXT",
        }
        for name, decl in additions.items():
            if name not in cols:
                self.conn.execute(f"ALTER TABLE items ADD COLUMN {name} {decl}")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ---------- 事故 ----------

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        priority = priority_score(severity, quantity, threshold)
        deadline = response_deadline_hours(severity, quantity, threshold)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at,
                       priority, deadline_hours)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now, priority, deadline),
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

    def transition_item(self, item_id: int, target: str, expected_version: int,
                         actor: str, seal: bool = False) -> Dict[str, Any]:
        """状态转换；seal=True 时封存当前优先级/期限结果。"""
        now = utc_now()
        with self._lock, self.conn:
            item = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            if int(item["version"]) != expected_version:
                raise ConflictError("版本冲突，请刷新后重试")
            if seal:
                cur = self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?,
                       sealed_priority=COALESCE(sealed_priority, priority),
                       sealed_deadline_hours=COALESCE(sealed_deadline_hours, deadline_hours),
                       sealed_at=?
                       WHERE id=? AND version=?""",
                    (target, now, now, item_id, expected_version),
                )
            else:
                cur = self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=?
                       WHERE id=? AND version=?""",
                    (target, now, item_id, expected_version),
                )
            if cur.rowcount == 0:
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def update_item_fields(self, item_id: int, expected_version: int,
                           fields: Dict[str, Any]) -> Dict[str, Any]:
        """更新严重度/伤害指数/阈值并重算未关闭事故的优先级与期限。"""
        now = utc_now()
        allowed = {"severity", "quantity", "threshold"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return self.get_item(item_id)
        with self._lock, self.conn:
            item = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            if int(item["version"]) != expected_version:
                raise ConflictError("版本冲突，请刷新后重试")
            if item["status"] == "closed":
                raise ConflictError("已关闭事故不可修改，结果已封存")
            severity = sets.get("severity", item["severity"])
            quantity = sets.get("quantity", item["quantity"])
            threshold = sets.get("threshold", item["threshold"])
            open_count = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()["n"]
            priority = priority_score(severity, quantity, threshold, open_count)
            deadline = response_deadline_hours(severity, quantity, threshold)
            cols = ", ".join(f"{k}=?" for k in sets)
            params = list(sets.values()) + [priority, deadline, now, item_id, expected_version]
            cur = self.conn.execute(
                f"""UPDATE items SET {cols}, priority=?, deadline_hours=?,
                    version=version+1, updated_at=?
                    WHERE id=? AND version=?""",
                params,
            )
            if cur.rowcount == 0:
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def recompute_open_item(self, item_id: int) -> Dict[str, Any]:
        """按当前记录数重算未关闭事故的优先级（期限不依赖记录数）。"""
        now = utc_now()
        with self._lock, self.conn:
            item = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            if item["status"] == "closed":
                return self.get_item(item_id)
            open_count = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()["n"]
            priority = priority_score(item["severity"], item["quantity"],
                                      item["threshold"], open_count)
            self.conn.execute(
                "UPDATE items SET priority=?, updated_at=? WHERE id=?",
                (priority, now, item_id),
            )
        return self.get_item(item_id)

    # ---------- 记录 ----------

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def get_record(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row) if row else None

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

    # ---------- 持有凭证（lease）与检查点 ----------

    def _row_to_lease(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "item_id": row["item_id"], "token": row["token"],
            "holder": row["holder"], "issued_at": row["issued_at"],
            "expires_at": row["expires_at"], "status": row["status"],
            "checkpoint_id": row["checkpoint_id"], "created_at": row["created_at"],
        }

    def _row_to_checkpoint(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "item_id": row["item_id"], "lease_token": row["lease_token"],
            "holder": row["holder"], "kind": row["kind"], "seq": row["seq"],
            "payload": json.loads(row["payload"]), "created_at": row["created_at"],
        }

    def get_active_lease(self, item_id: int, now: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """返回当前有效凭证；若已过期则惰性置为 expired。"""
        now = now or utc_now()
        with self._lock, self.conn:
            row = self.conn.execute(
                """SELECT * FROM leases WHERE item_id=? AND status='active'
                   ORDER BY id DESC LIMIT 1""",
                (item_id,),
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= now:
                self.conn.execute(
                    "UPDATE leases SET status=? WHERE id=?",
                    (LEASE_EXPIRED, row["id"]),
                )
                self.conn.execute(
                    """UPDATE items SET holder=NULL, lease_token=NULL, lease_expires_at=NULL
                       WHERE id=? AND lease_token=?""",
                    (item_id, row["token"]),
                )
                return None
            return self._row_to_lease(row)

    def claim_lease(self, item_id: int, holder: str, lease_seconds: int,
                    note: Optional[str], now: Optional[str] = None) -> Dict[str, Any]:
        """领取续办：签发短期持有凭证并记下检查点；逾期则交接给下一人。"""
        now = now or utc_now()
        token = secrets.token_urlsafe(24)
        from datetime import datetime, timedelta, timezone
        expires = (datetime.fromisoformat(now) + timedelta(seconds=lease_seconds)).isoformat()
        with self._lock, self.conn:
            item = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            if item["status"] == "closed":
                raise ConflictError("已关闭事故不可续办")
            previous = self.conn.execute(
                """SELECT * FROM leases WHERE item_id=? AND status='active'
                   ORDER BY id DESC LIMIT 1""",
                (item_id,),
            ).fetchone()
            handover = False
            if previous is not None:
                if previous["expires_at"] > now:
                    raise ConflictError(
                        f"该事故正由 {previous['holder']} 持有，凭证未到期")
                # 逾期：置为交接，交给下一人
                self.conn.execute(
                    "UPDATE leases SET status=? WHERE id=?",
                    (LEASE_TAKEN_OVER, previous["id"]),
                )
                handover = True
            seq_row = self.conn.execute(
                "SELECT COALESCE(MAX(seq),0) AS m FROM checkpoints WHERE item_id=?",
                (item_id,),
            ).fetchone()
            seq = int(seq_row["m"]) + 1
            kind = CHECKPOINT_HANDOVER if handover else CHECKPOINT_CLAIM
            payload = {
                "version": item["version"], "status": item["status"],
                "open_records": self.open_record_count(item_id),
                "holder": holder, "note": note or "",
                "from_holder": previous["holder"] if handover else None,
                "previous_checkpoint_id": item["checkpoint_id"],
            }
            cur = self.conn.execute(
                """INSERT INTO checkpoints(item_id, lease_token, holder, kind, seq,
                   payload, created_at) VALUES(?,?,?,?,?,?,?)""",
                (item_id, token, holder, kind, seq,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), now),
            )
            checkpoint_id = int(cur.lastrowid)
            cur = self.conn.execute(
                """INSERT INTO leases(item_id, token, holder, issued_at, expires_at,
                   status, checkpoint_id, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, token, holder, now, expires, LEASE_ACTIVE, checkpoint_id, now),
            )
            lease_id = int(cur.lastrowid)
            self.conn.execute(
                """UPDATE items SET holder=?, lease_token=?, lease_expires_at=?,
                   checkpoint_id=?, updated_at=? WHERE id=?""",
                (holder, token, expires, checkpoint_id, now, item_id),
            )
            lease = self._row_to_lease(self.conn.execute(
                "SELECT * FROM leases WHERE id=?", (lease_id,)).fetchone())
            checkpoint = self._row_to_checkpoint(self.conn.execute(
                "SELECT * FROM checkpoints WHERE id=?", (checkpoint_id,)).fetchone())
        return {"lease": lease, "checkpoint": checkpoint, "handover": handover}

    def add_checkpoint(self, item_id: int, lease_token: str, holder: str,
                       kind: str, note: Optional[str], now: Optional[str] = None,
                       payload_extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        now = now or utc_now()
        with self._lock, self.conn:
            item = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("项目不存在")
            seq_row = self.conn.execute(
                "SELECT COALESCE(MAX(seq),0) AS m FROM checkpoints WHERE item_id=?",
                (item_id,),
            ).fetchone()
            seq = int(seq_row["m"]) + 1
            payload = {
                "version": item["version"], "status": item["status"],
                "open_records": self.open_record_count(item_id),
                "holder": holder, "note": note or "",
            }
            if payload_extra:
                payload.update(payload_extra)
            cur = self.conn.execute(
                """INSERT INTO checkpoints(item_id, lease_token, holder, kind, seq,
                   payload, created_at) VALUES(?,?,?,?,?,?,?)""",
                (item_id, lease_token, holder, kind, seq,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), now),
            )
            checkpoint_id = int(cur.lastrowid)
            self.conn.execute(
                "UPDATE items SET checkpoint_id=?, updated_at=? WHERE id=?",
                (checkpoint_id, now, item_id),
            )
            row = self.conn.execute(
                "SELECT * FROM checkpoints WHERE id=?", (checkpoint_id,)).fetchone()
        return self._row_to_checkpoint(row)

    def release_lease(self, item_id: int, lease_token: str,
                      now: Optional[str] = None) -> Dict[str, Any]:
        now = now or utc_now()
        with self._lock, self.conn:
            lease = self.conn.execute(
                "SELECT * FROM leases WHERE item_id=? AND token=?",
                (item_id, lease_token),
            ).fetchone()
            if lease is None:
                raise NotFoundError("持有凭证不存在")
            if lease["status"] != LEASE_ACTIVE:
                raise ConflictError("持有凭证已失效")
            self.conn.execute(
                "UPDATE leases SET status=? WHERE id=?", (LEASE_RELEASED, lease["id"]))
            self.conn.execute(
                """UPDATE items SET holder=NULL, lease_token=NULL, lease_expires_at=NULL,
                   updated_at=? WHERE id=? AND lease_token=?""",
                (now, item_id, lease_token),
            )
        return self.get_item(item_id)

    def expire_overdue_leases(self, now: Optional[str] = None) -> int:
        now = now or utc_now()
        with self._lock, self.conn:
            rows = self.conn.execute(
                "SELECT * FROM leases WHERE status='active' AND expires_at<=?",
                (now,),
            ).fetchall()
            for row in rows:
                self.conn.execute(
                    "UPDATE leases SET status=? WHERE id=?",
                    (LEASE_EXPIRED, row["id"]),
                )
                self.conn.execute(
                    """UPDATE items SET holder=NULL, lease_token=NULL, lease_expires_at=NULL
                       WHERE id=? AND lease_token=?""",
                    (row["item_id"], row["token"]),
                )
        return len(rows)

    def list_checkpoints(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM checkpoints WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [self._row_to_checkpoint(row) for row in rows]

    def list_leases(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM leases WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [self._row_to_lease(row) for row in rows]

    # ---------- 迟到提交（历史留痕） ----------

    def add_late_submission(self, item_id: int, lease_token: Optional[str],
                            holder: Optional[str], kind: str, detail: str,
                            payload: Dict[str, Any], reason: str,
                            now: Optional[str] = None) -> Dict[str, Any]:
        now = now or utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO late_submissions(item_id, lease_token, holder, kind, detail,
                   payload, reason, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, lease_token, holder, kind, detail,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), reason, now),
            )
            late_id = int(cur.lastrowid)
            row = self.conn.execute(
                "SELECT * FROM late_submissions WHERE id=?", (late_id,)).fetchone()
        return {
            "id": row["id"], "item_id": row["item_id"], "lease_token": row["lease_token"],
            "holder": row["holder"], "kind": row["kind"], "detail": row["detail"],
            "payload": json.loads(row["payload"]), "reason": row["reason"],
            "created_at": row["created_at"],
        }

    def list_late_submissions(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM late_submissions WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["payload"] = json.loads(item["payload"])
                result.append(item)
            return result

    # ---------- 续办尝试（幂等与重试） ----------

    @staticmethod
    def measure_ref(idempotency_key: str) -> str:
        digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        return "FX-" + digest[:24]

    def get_followup_attempt(self, item_id: int, idempotency_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM followup_attempts WHERE item_id=? AND idempotency_key=?",
                (item_id, idempotency_key),
            ).fetchone()
        return self._row_to_attempt(row) if row else None

    def _row_to_attempt(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "item_id": row["item_id"],
            "idempotency_key": row["idempotency_key"], "lease_token": row["lease_token"],
            "holder": row["holder"], "kind": row["kind"], "detail": row["detail"],
            "status": row["status"], "record_id": row["record_id"],
            "failure_reason": row["failure_reason"],
            "payload": json.loads(row["payload"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def create_followup_attempt(self, item_id: int, idempotency_key: str,
                                lease_token: Optional[str], holder: str, kind: str,
                                detail: str, payload: Dict[str, Any],
                                now: Optional[str] = None) -> Dict[str, Any]:
        now = now or utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO followup_attempts(item_id, idempotency_key, lease_token,
                   holder, kind, detail, status, payload, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (item_id, idempotency_key, lease_token, holder, kind, detail,
                 ATTEMPT_FAILED, json.dumps(payload, ensure_ascii=False, sort_keys=True),
                 now, now),
            )
            attempt_id = int(cur.lastrowid)
            row = self.conn.execute(
                "SELECT * FROM followup_attempts WHERE id=?", (attempt_id,)).fetchone()
        return self._row_to_attempt(row)

    def mark_followup_attempt(self, attempt_id: int, status: str,
                              record_id: Optional[int] = None,
                              failure_reason: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE followup_attempts SET status=?, record_id=?, failure_reason=?,
                   updated_at=? WHERE id=?""",
                (status, record_id, failure_reason, now, attempt_id),
            )
            row = self.conn.execute(
                "SELECT * FROM followup_attempts WHERE id=?", (attempt_id,)).fetchone()
        return self._row_to_attempt(row)

    def list_followup_attempts(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM followup_attempts WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [self._row_to_attempt(row) for row in rows]

    # ---------- 审计链 ----------

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

    def close(self) -> None:
        with self._lock:
            self.conn.close()
