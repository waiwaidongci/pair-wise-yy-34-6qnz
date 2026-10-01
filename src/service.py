from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from .domain import (ConflictError, NotFoundError, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (ATTEMPT_FAILED, ATTEMPT_QUARANTINED, ATTEMPT_SUCCEEDED,
                    AUDIT_ROLES, CHECKPOINT_PROGRESS, CLAIM_ROLES, CREATE_ROLES,
                    ENTITY, LATE_EXPIRED, LATE_NO_LEASE, LATE_TOKEN_MISMATCH,
                    LEASE_ACTIVE, RECORD_ROLES, UPDATE_ROLES, VIEW_ROLES,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition,
                    validate_transition, DEFAULT_LEASE_SECONDS, MAX_LEASE_SECONDS,
                    MIN_LEASE_SECONDS)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    # ---------- 事故 ----------

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def update_item(self, item_id: int, payload: Dict[str, Any], actor: str,
                    role: str) -> Dict[str, Any]:
        """严重度/伤害指数/阈值改动后立即重算未关闭事故的期限与优先级。"""
        ensure_role(role, UPDATE_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        fields: Dict[str, Any] = {}
        if "severity" in payload:
            fields["severity"] = normalize_severity(payload["severity"])
        if "quantity" in payload:
            fields["quantity"] = require_number(payload["quantity"], "quantity")
        if "threshold" in payload:
            fields["threshold"] = require_number(payload["threshold"], "threshold", 0.000001)
        if not fields:
            raise ValueError("没有需要更新的字段")
        updated = self.repository.update_item_fields(item_id, expected_version, fields)
        self.repository.append_audit("recalculated", ENTITY, item_id, actor, {
            "fields": fields, "priority": updated["priority"],
            "deadline_hours": updated["deadline_hours"],
            "sealed": updated["status"] == "closed",
        })
        return self.enrich(updated)

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        seal = (target == "closed")
        updated = self.repository.transition_item(item_id, target, expected_version,
                                                  actor, seal=seal)
        detail: Dict[str, Any] = {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        }
        if seal:
            detail["sealed_priority"] = updated.get("sealed_priority")
            detail["sealed_deadline_hours"] = updated.get("sealed_deadline_hours")
        self.repository.append_audit("transition", ENTITY, item_id, actor, detail)
        if seal:
            self.repository.append_audit("sealed", ENTITY, item_id, actor, {
                "priority": updated.get("sealed_priority"),
                "deadline_hours": updated.get("sealed_deadline_hours"),
            })
        return self.enrich(updated)

    # ---------- 记录（直接登记，保留兼容） ----------

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    # ---------- 续办：领取 / 检查点 / 释放 ----------

    def claim(self, item_id: int, payload: Dict[str, Any], actor: str,
              role: str) -> Dict[str, Any]:
        ensure_role(role, CLAIM_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_item(item_id)
        lease_seconds = payload.get("lease_seconds", DEFAULT_LEASE_SECONDS)
        if not isinstance(lease_seconds, int) or lease_seconds < MIN_LEASE_SECONDS:
            lease_seconds = DEFAULT_LEASE_SECONDS
        lease_seconds = min(lease_seconds, MAX_LEASE_SECONDS)
        note = payload.get("note")
        result = self.repository.claim_lease(item_id, actor, lease_seconds, note)
        action = "handover" if result["handover"] else "claim"
        self.repository.append_audit(action, ENTITY, item_id, actor, {
            "holder": actor, "lease_token": result["lease"]["token"],
            "expires_at": result["lease"]["expires_at"],
            "checkpoint_id": result["checkpoint"]["id"],
            "from_holder": result["checkpoint"]["payload"].get("from_holder"),
        })
        return {"lease": result["lease"], "checkpoint": result["checkpoint"],
                "handover": result["handover"],
                "item": self.enrich(self.repository.get_item(item_id))}

    def checkpoint(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, CLAIM_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_item(item_id)
        lease_token = require_text(payload.get("lease_token"), "lease_token", 200)
        note = payload.get("note")
        active = self.repository.get_active_lease(item_id)
        if active is None or active["token"] != lease_token:
            raise ConflictError("持有凭证无效或已过期")
        cp = self.repository.add_checkpoint(item_id, lease_token, actor,
                                            CHECKPOINT_PROGRESS, note)
        self.repository.append_audit("checkpoint", ENTITY, item_id, actor, {
            "checkpoint_id": cp["id"], "seq": cp["seq"],
        })
        return {"checkpoint": cp, "item": self.enrich(self.repository.get_item(item_id))}

    def release(self, item_id: int, payload: Dict[str, Any], actor: str,
                role: str) -> Dict[str, Any]:
        ensure_role(role, CLAIM_ROLES)
        actor = require_text(actor, "actor", 100)
        lease_token = require_text(payload.get("lease_token"), "lease_token", 200)
        item = self.repository.release_lease(item_id, lease_token)
        self.repository.append_audit("release", ENTITY, item_id, actor, {
            "lease_token": lease_token,
        })
        return {"item": self.enrich(item)}

    # ---------- 续办提交（幂等 / 迟到隔离 / 失败可重试） ----------

    def _lease_state(self, item: Dict[str, Any], lease_token: Optional[str]):
        """返回 (有效凭证, 失效原因)。无有效凭证时原因非空。"""
        active = self.repository.get_active_lease(item["id"])
        if active is not None:
            if lease_token and lease_token == active["token"]:
                return active, None
            # 凭证与当前持有人不符：若为已知旧凭证 -> 已过期/交接，否则令牌不匹配
            if lease_token:
                known = next((l for l in self.repository.list_leases(item["id"])
                              if l["token"] == lease_token), None)
                if known is not None and known["status"] != LEASE_ACTIVE:
                    return None, LATE_EXPIRED
            return None, LATE_TOKEN_MISMATCH
        if lease_token:
            known = any(l["token"] == lease_token
                        for l in self.repository.list_leases(item["id"]))
            return (None, LATE_EXPIRED) if known else (None, LATE_TOKEN_MISMATCH)
        return None, LATE_NO_LEASE

    def _quarantine(self, item: Dict[str, Any], lease_token: Optional[str],
                    actor: str, kind: str, detail: str, reason: str,
                    payload: Dict[str, Any], idem: str) -> Dict[str, Any]:
        late = self.repository.add_late_submission(
            item["id"], lease_token, actor, kind, detail, payload, reason)
        attempt = self.repository.get_followup_attempt(item["id"], idem)
        if attempt is None:
            attempt = self.repository.create_followup_attempt(
                item["id"], idem, lease_token, actor, kind, detail, payload)
        attempt = self.repository.mark_followup_attempt(
            attempt["id"], ATTEMPT_QUARANTINED, failure_reason=reason)
        self.repository.append_audit("late_submission", ENTITY, item["id"], actor, {
            "reason": reason, "late_submission_id": late["id"], "kind": kind,
            "idempotency_key": idem,
        })
        return {"applied": False, "reason": reason, "late_submission": late,
                "attempt": attempt}

    def _apply_followup(self, item: Dict[str, Any], active: Dict[str, Any],
                        idem: str, kind: str, detail: str, rec_status: str,
                        expected_version: Optional[int], note: Optional[str],
                        actor: str, existing: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        # 版本冲突 -> 记为失败，可重试（不生成措施、不覆盖续办）
        if expected_version is not None and expected_version != item["version"]:
            if existing is None:
                attempt = self.repository.create_followup_attempt(
                    item["id"], idem, active["token"], actor, kind, detail,
                    {"kind": kind, "detail": detail, "status": rec_status,
                     "expected_version": expected_version, "note": note})
            else:
                attempt = existing
            attempt = self.repository.mark_followup_attempt(
                attempt["id"], ATTEMPT_FAILED, failure_reason="version_conflict")
            self.repository.append_audit("followup_failed", ENTITY, item["id"], actor, {
                "reason": "version_conflict", "attempt_id": attempt["id"],
                "expected_version": expected_version, "current_version": item["version"],
            })
            return {"applied": False, "reason": "version_conflict",
                    "failure_reason": "version_conflict", "attempt": attempt,
                    "current_version": item["version"]}
        # 生成措施/记录（external_ref 幂等兜底，重试不重复生成）
        external_ref = self.repository.measure_ref(idem)
        try:
            record = self.repository.add_record(item["id"], kind, detail,
                                                rec_status, external_ref, actor)
        except ConflictError:
            record = next((r for r in self.repository.list_records(item["id"])
                           if r["external_ref"] == external_ref), None)
            if record is None:
                raise
        checkpoint = self.repository.add_checkpoint(
            item["id"], active["token"], actor, CHECKPOINT_PROGRESS, note,
            payload_extra={"record_id": record["id"], "kind": kind})
        enriched = self.repository.recompute_open_item(item["id"])
        if existing is None:
            attempt = self.repository.create_followup_attempt(
                item["id"], idem, active["token"], actor, kind, detail,
                {"kind": kind, "detail": detail, "status": rec_status,
                 "expected_version": expected_version, "note": note})
        else:
            attempt = existing
        attempt = self.repository.mark_followup_attempt(
            attempt["id"], ATTEMPT_SUCCEEDED, record_id=record["id"])
        self.repository.append_audit("followup", ENTITY, item["id"], actor, {
            "record_id": record["id"], "kind": kind, "status": rec_status,
            "checkpoint_id": checkpoint["id"], "idempotency_key": idem,
            "retry": existing is not None,
        })
        return {"applied": True, "idempotent": existing is not None,
                "record": record, "attempt": attempt, "checkpoint": checkpoint,
                "item": self.enrich(enriched)}

    def followup(self, item_id: int, payload: Dict[str, Any], actor: str,
                 role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        rec_status = payload.get("status", "open")
        if rec_status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        note = payload.get("note")
        expected_version = payload.get("expected_version")
        if expected_version is not None:
            if not isinstance(expected_version, int) or expected_version < 1:
                raise ValueError("expected_version必须是正整数")
        lease_token = payload.get("lease_token")
        if lease_token is not None:
            lease_token = require_text(lease_token, "lease_token", 200)
        idem = payload.get("idempotency_key") or payload.get("client_key")
        if idem:
            idem = require_text(idem, "idempotency_key", 200)
        else:
            digest = hashlib.sha256(detail.strip().encode("utf-8")).hexdigest()
            idem = f"{lease_token or 'none'}:{kind}:{digest[:16]}"

        existing = self.repository.get_followup_attempt(item["id"], idem)
        if existing and existing["status"] == ATTEMPT_SUCCEEDED:
            record = (self.repository.get_record(existing["record_id"])
                      if existing["record_id"] else None)
            return {"applied": True, "idempotent": True, "record": record,
                    "attempt": existing}

        if item["status"] == "closed":
            return self._quarantine(item, lease_token, actor, kind, detail,
                                    "item_closed", payload, idem)
        active, reason = self._lease_state(item, lease_token)
        if reason is not None:
            return self._quarantine(item, lease_token, actor, kind, detail,
                                    reason, payload, idem)
        return self._apply_followup(item, active, idem, kind, detail, rec_status,
                                    expected_version, note, actor, existing)

    def retry_followup(self, item_id: int, payload: Dict[str, Any], actor: str,
                        role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        idem = require_text(payload.get("idempotency_key"), "idempotency_key", 200)
        attempt = self.repository.get_followup_attempt(item["id"], idem)
        if attempt is None:
            raise NotFoundError("续办尝试不存在")
        if attempt["status"] == ATTEMPT_SUCCEEDED:
            record = (self.repository.get_record(attempt["record_id"])
                      if attempt["record_id"] else None)
            return {"applied": True, "idempotent": True, "record": record,
                    "attempt": attempt}
        lease_token = payload.get("lease_token")
        if lease_token is not None:
            lease_token = require_text(lease_token, "lease_token", 200)
        active, reason = self._lease_state(item, lease_token)
        if reason is not None:
            late = self.repository.add_late_submission(
                item["id"], lease_token, actor, attempt["kind"], attempt["detail"],
                {"idempotency_key": idem, "retry": True}, reason)
            self.repository.append_audit("late_submission", ENTITY, item["id"], actor, {
                "reason": reason, "late_submission_id": late["id"], "retry": True,
                "idempotency_key": idem,
            })
            return {"applied": False, "reason": reason, "late_submission": late,
                    "attempt": attempt}
        stored = attempt["payload"]
        rec_status = stored.get("status", "open")
        expected_version = payload.get("expected_version",
                                      stored.get("expected_version"))
        note = payload.get("note", stored.get("note"))
        result = self._apply_followup(item, active, idem, attempt["kind"],
                                      attempt["detail"], rec_status,
                                      expected_version, note, actor, attempt)
        self.repository.append_audit("followup_retried", ENTITY, item["id"], actor, {
            "attempt_id": attempt["id"], "idempotency_key": idem,
            "applied": result["applied"],
        })
        return result

    # ---------- 查询 ----------

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def list_checkpoints(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_checkpoints(item_id)

    def list_leases(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_leases(item_id)

    def list_late_submissions(self, item_id: int, role: str) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_late_submissions(item_id)

    def list_attempts(self, item_id: int, role: str) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_followup_attempts(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        priority = item.get("priority")
        deadline = item.get("deadline_hours")
        if item["status"] == "closed":
            if item.get("sealed_priority") is not None:
                priority = item["sealed_priority"]
            if item.get("sealed_deadline_hours") is not None:
                deadline = item["sealed_deadline_hours"]
        # 兼容旧库：新字段缺失时按当前规则回退计算
        if priority is None:
            priority = priority_score(item["severity"], item["quantity"], item["threshold"])
        if deadline is None:
            deadline = response_deadline_hours(item["severity"], item["quantity"],
                                               item["threshold"])
        result["priority"] = priority
        result["deadline_hours"] = deadline
        result["sealed"] = (item["status"] == "closed")
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        result["holder"] = item.get("holder")
        result["lease_active"] = bool(item.get("lease_token"))
        result["lease_expires_at"] = item.get("lease_expires_at")
        result["checkpoint_id"] = item.get("checkpoint_id")
        return result
