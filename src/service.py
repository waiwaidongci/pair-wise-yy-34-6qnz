from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, NotFoundError, PermissionDenied,
                     ValidationError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import (REASON_RELEASE, REASON_SEALED, REASON_START,
                         REASON_TIMEOUT, Repository)
from .rules import (AUDIT_ROLES, CLAIM_ROLES, CREATE_ROLES, ENTITY,
                    RECORD_ROLES, SEVERITY_CHANGE_ROLES, VIEW_ROLES,
                    completion_blockers, escalation_required, is_sealed_status,
                    priority_score, response_deadline_hours,
                    role_for_transition, validate_lease_ttl, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def _metrics(self, severity: str, quantity: float, threshold: float,
                 open_records: int) -> tuple:
        return (priority_score(severity, quantity, threshold, open_records),
                response_deadline_hours(severity, quantity, threshold))

    def sweep_expired(self, actor: str = "system") -> List[Dict[str, Any]]:
        """把到期租约转成交接记录，并写审计。幂等。"""
        expired = self.repository.expire_active_leases()
        for lease in expired:
            checkpoint = self.repository.latest_checkpoint(lease["item_id"])
            self.repository.insert_handoff(
                lease["item_id"], lease["id"], None,
                checkpoint["id"] if checkpoint else None,
                REASON_TIMEOUT,
                f"持有人{lease['holder']}的凭证于{lease['expires_at']}超时，"
                "调查从最近检查点交给下一持有人", actor)
            self.repository.append_audit("lease_timeout", ENTITY, lease["item_id"], actor, {
                "lease_id": lease["id"], "holder": lease["holder"],
                "expires_at": lease["expires_at"], "reason": REASON_TIMEOUT,
                "checkpoint_id": checkpoint["id"] if checkpoint else None,
            })
        return expired

    # ------------------------------------------------------------------ items
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
        priority, deadline = self._metrics(severity, quantity, threshold, 0)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor,
                                           priority, deadline)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority, "deadline_hours": deadline,
        })
        return self.enrich(item)

    def change_severity(self, item_id: int, payload: Dict[str, Any],
                        actor: str, role: str) -> Dict[str, Any]:
        """严重度/伤害指数改动后立即重算该未关闭事故的期限和优先级。"""
        ensure_role(role, SEVERITY_CHANGE_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        if item["sealed"] or is_sealed_status(item["status"]):
            raise ConflictError("已封存的已关闭事故保留原结果，不能修改",
                                {"sealed": True, "priority": item["priority"],
                                 "deadline_hours": item["deadline_hours"]})
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        severity = normalize_severity(payload.get("severity", item["severity"]))
        if "quantity" in payload:
            quantity = require_number(payload.get("quantity"), "quantity")
        else:
            quantity = item["quantity"]
        threshold = item["threshold"]
        open_records = self.repository.open_record_count(item_id)
        priority, deadline = self._metrics(severity, quantity, threshold, open_records)
        updated = self.repository.patch_item(item_id, severity, quantity,
                                             expected_version, priority, deadline)
        self.repository.append_audit("severity_change", ENTITY, item_id, actor, {
            "severity": {"from": item["severity"], "to": severity},
            "quantity": {"from": item["quantity"], "to": quantity},
            "recalculated_priority": priority,
            "recalculated_deadline_hours": deadline,
            "sealed_preserved": False,
        })
        return self.enrich(updated)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        """兼容旧接口：无租约上下文的现场记录，仍追加历史（不经过续办批次）。"""
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValidationError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        item = self.repository.get_item(item_id)
        if not item["sealed"]:
            open_count = self.repository.open_record_count(item_id)
            priority, deadline = self._metrics(
                item["severity"], item["quantity"], item["threshold"], open_count)
            self.repository.update_metrics(item_id, priority, deadline)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        sealed = is_sealed_status(target)
        if sealed:
            open_count = self.repository.open_record_count(item_id)
            priority, deadline = self._metrics(
                updated["severity"], updated["quantity"], updated["threshold"], open_count)
            self.repository.update_metrics(item_id, priority, deadline)
            self.repository.seal_item(item_id)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
            "sealed": sealed,
            "sealed_priority": updated["priority"] if sealed else None,
            "sealed_deadline_hours": updated["deadline_hours"] if sealed else None,
        })
        return self.enrich(self.repository.get_item(item_id))

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        self.sweep_expired()
        item = self.enrich(self.repository.get_item(item_id))
        item["continuation"] = self._continuation_view(item_id)
        return item

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        self.sweep_expired()
        result = []
        for item in self.repository.list_items(status):
            enriched = self.enrich(item)
            active = self.repository.get_active_lease(item["id"])
            enriched["current_holder"] = active["holder"] if active else None
            enriched["lease_expires_at"] = active["expires_at"] if active else None
            result.append(enriched)
        return result

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    # ------------------------------------------------------------------ lease
    def claim(self, item_id: int, payload: Dict[str, Any], actor: str,
              role: str) -> Dict[str, Any]:
        """领取续办：记下短期持有凭证和初始检查点。"""
        ensure_role(role, CLAIM_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        self.sweep_expired()
        if item["sealed"] or is_sealed_status(item["status"]):
            raise ConflictError("事故已关闭封存，无需续办")
        ttl_seconds = validate_lease_ttl(payload.get("ttl_seconds", 600))
        active = self.repository.get_active_lease(item_id)
        if active:
            raise ConflictError("该事故已有在期持有人", {
                "current_holder": active["holder"],
                "lease_expires_at": active["expires_at"],
            })
        checkpoint = self.repository.latest_checkpoint(item_id)
        open_count = self.repository.open_record_count(item_id)
        attempt_no = 1
        from_lease_id = None
        from_checkpoint_id = None
        prev_status = None
        if checkpoint is None:
            summary = "领取初始检查点：开始续办"
            reason = REASON_START
        else:
            summary = (f"从检查点#{checkpoint['seq']}恢复：{checkpoint['summary']}")
            from_checkpoint_id = checkpoint["id"]
            if checkpoint["lease_id"]:
                from_lease_id = checkpoint["lease_id"]
                prev_lease = self.repository.get_lease(from_lease_id)
                prev_status = prev_lease["status"]
            reason = {"expired": REASON_TIMEOUT, "released": REASON_RELEASE,
                      "sealed": REASON_SEALED}.get(prev_status, REASON_TIMEOUT)
            attempt_no = self.repository.next_attempt_no(item_id)
        lease = self.repository.claim(item_id, actor, ttl_seconds, summary,
                                      open_count, item["version"],
                                      item["status"], attempt_no)
        new_checkpoint = self.repository.get_checkpoint(lease["checkpoint_id"])
        self.repository.insert_handoff(
            item_id, from_lease_id, lease["id"],
            from_checkpoint_id if from_checkpoint_id else new_checkpoint["id"],
            reason, f"{actor}领取续办凭证，有效期至{lease['expires_at']}", actor)
        self.repository.append_audit("claim", ENTITY, item_id, actor, {
            "lease_id": lease["id"], "attempt_no": attempt_no,
            "ttl_seconds": ttl_seconds, "expires_at": lease["expires_at"],
            "checkpoint_id": new_checkpoint["id"], "checkpoint_seq": new_checkpoint["seq"],
            "resumed_from": from_checkpoint_id,
        })
        resume = self._resume_pack(item_id)
        # resume从“领取前最近的检查点”恢复，而非本次新建的检查点
        resume["from_checkpoint_seq"] = (
            self.repository.get_checkpoint(from_checkpoint_id)["seq"]
            if from_checkpoint_id else 0)
        return {
            "lease": self._lease_public(lease),
            "token": lease["token"],
            "checkpoint": new_checkpoint,
            "resume": resume,
        }

    def release(self, item_id: int, payload: Dict[str, Any], actor: str,
                role: str) -> Dict[str, Any]:
        """持有人主动释放，之后从最近检查点交给下一人。"""
        ensure_role(role, CLAIM_ROLES)
        actor = require_text(actor, "actor", 100)
        token = require_text(payload.get("token"), "token", 200)
        lease, reason = self._authorize_lease(item_id, token)
        if reason:
            return self._stale_response(item_id, payload, actor, lease, reason, "release")
        self.repository.release_lease(lease["id"])
        checkpoint = self.repository.latest_checkpoint(item_id)
        self.repository.insert_handoff(
            item_id, lease["id"], None,
            checkpoint["id"] if checkpoint else None,
            REASON_RELEASE, f"持有人{actor}主动释放凭证", actor)
        self.repository.append_audit("lease_release", ENTITY, item_id, actor, {
            "lease_id": lease["id"], "reason": REASON_RELEASE,
            "checkpoint_id": checkpoint["id"] if checkpoint else None,
        })
        return {"released": True, "lease": self._lease_public(
            self.repository.get_lease(lease["id"])),
            "next_resume_checkpoint_id": checkpoint["id"] if checkpoint else None}

    def continue_investigation(self, item_id: int, payload: Dict[str, Any],
                               actor: str, role: str,
                               retried_of_id: Optional[int] = None) -> Dict[str, Any]:
        """当前持有人凭凭证续办：成功推进检查点；失败可重试；迟到提交只留历史。"""
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        self.sweep_expired()
        token = require_text(payload.get("token"), "token", 200)
        batch_ref = require_text(payload.get("batch_ref"), "batch_ref", 100)
        lease, reason = self._authorize_lease(item_id, token)

        existing = self.repository.find_attempt_by_batch(item_id, batch_ref)
        if existing and existing["result"] == "succeeded":
            return {"duplicate": True, "applied": False,
                    "attempt_id": existing["id"],
                    "message": f"批次{batch_ref}已成功续办，幂等返回，未重复生成措施",
                    "checkpoint_id": existing["checkpoint_id"]}

        if reason:
            return self._stale_response(
                item_id, payload, actor, lease, reason, "continuation",
                batch_ref=batch_ref, retried_of_id=retried_of_id,
                prior_attempt=existing)

        if lease["holder"] != actor:
            self.repository.record_stale_submission(
                item_id, lease["id"], self._fingerprint(token), batch_ref,
                payload, "token_holder_mismatch", actor)
            self.repository.append_audit("stale_submission", ENTITY, item_id, actor, {
                "lease_id": lease["id"], "batch_ref": batch_ref,
                "reason": "token_holder_mismatch", "applied": False,
            })
            raise PermissionDenied("凭证属于其他持有人，不能代为续办")

        records: List[Dict[str, Any]] = []
        checkpoint = self.repository.latest_checkpoint(item_id)

        retriable_error: Optional[Exception] = None
        try:
            records = self._parse_records(payload)
            ext_seen: set = set()
            for rec in records:
                if rec.get("external_ref") and rec["external_ref"] in ext_seen:
                    raise ValidationError("同批措施的external_ref不能重复")
                ext_seen.add(rec.get("external_ref"))
            if item["sealed"] or is_sealed_status(item["status"]):
                raise ConflictError("事故已关闭封存，不能再续办")
        except (ValidationError, ConflictError) as exc:
            retriable_error = exc

        if retriable_error is not None:
            attempt = self._record_failure(
                item_id, lease, checkpoint, batch_ref, retriable_error,
                actor, retried_of_id, payload)
            self.repository.append_audit("continuation_failed", ENTITY, item_id, actor, {
                "lease_id": lease["id"], "batch_ref": batch_ref,
                "attempt_id": attempt["id"], "error": retriable_error.message,
                "error_kind": retriable_error.kind, "retriable": True,
                "retried_of_id": retried_of_id,
            })
            wrapped = (ConflictError if isinstance(retriable_error, ConflictError)
                       else ValidationError)(
                f"续办失败（批次{batch_ref}已记录，可重试）：{retriable_error.message}",
                {"attempt_id": attempt["id"], "batch_ref": batch_ref,
                 "retriable": True, "reason": "continuation_failed",
                 "error_kind": retriable_error.kind})
            raise wrapped

        priority, deadline = self._metrics(
            item["severity"], item["quantity"], item["threshold"],
            self.repository.open_record_count(item_id))
        try:
            outcome = self.repository.apply_continuation(
                item_id, lease["id"], checkpoint["id"], records, batch_ref,
                priority, deadline, actor, retried_of_id)
        except ConflictError as exc:
            # external_ref冲突等：落失败尝试，允许用同一batch_ref重试
            attempt = self._record_failure(
                item_id, lease, checkpoint, batch_ref, exc, actor,
                retried_of_id, payload)
            self.repository.append_audit("continuation_failed", ENTITY, item_id, actor, {
                "lease_id": lease["id"], "batch_ref": batch_ref,
                "attempt_id": attempt["id"], "error": exc.message,
                "error_kind": exc.kind, "retriable": True,
                "retried_of_id": retried_of_id,
            })
            raise ConflictError(
                f"续办失败（批次{batch_ref}已记录，可重试）：{exc.message}",
                {"attempt_id": attempt["id"], "batch_ref": batch_ref,
                 "retriable": True, "reason": "continuation_failed",
                 "error_kind": exc.kind}) from exc

        self.repository.append_audit("continuation", ENTITY, item_id, actor, {
            "lease_id": lease["id"], "batch_ref": batch_ref,
            "attempt_id": outcome["attempt_id"],
            "record_ids": outcome["record_ids"],
            "checkpoint_id": outcome["checkpoint"]["id"],
            "checkpoint_seq": outcome["checkpoint"]["seq"],
            "record_count": len(outcome["record_ids"]),
            "recalculated_priority": priority,
            "recalculated_deadline_hours": deadline,
            "retried_of_id": retried_of_id,
        })
        return {"duplicate": False, "applied": True, "attempt_id": outcome["attempt_id"],
                "record_ids": outcome["record_ids"],
                "checkpoint": outcome["checkpoint"],
                "item": self.enrich(outcome["item"]),
                "message": f"批次{batch_ref}续办成功",
                "retry_result": "success" if retried_of_id else None}

    def retry_continuation(self, item_id: int, payload: Dict[str, Any],
                           actor: str, role: str) -> Dict[str, Any]:
        """续办失败后重试：复用原批次号，成功不会重复生成措施。"""
        batch_ref = require_text(payload.get("batch_ref"), "batch_ref", 100)
        prior = self.repository.find_attempt_by_batch(item_id, batch_ref)
        if prior is None:
            raise NotFoundError("找不到该批次的续办尝试，无法重试")
        if prior["result"] == "succeeded":
            return {"duplicate": True, "applied": False, "attempt_id": prior["id"],
                    "message": f"批次{batch_ref}已成功，无需重试",
                    "retry_result": "already_succeeded",
                    "checkpoint_id": prior["checkpoint_id"]}
        # 复用失败时保存的原始措施内容，也允许本次用新内容覆盖
        retry_payload = dict(payload)
        stored = prior.get("payload") or {}
        if "records" not in retry_payload and isinstance(stored, dict) and stored.get("records"):
            retry_payload["records"] = stored["records"]
        return self.continue_investigation(
            item_id, retry_payload, actor, role, retried_of_id=prior["id"])

    # ---------------------------------------------------------------- helpers
    def _authorize_lease(self, item_id: int, token: str) -> tuple:
        """返回(lease, 失效原因)。active返回(lease, None)。"""
        lease = self.repository.find_lease_by_token(token)
        if lease is None or lease["item_id"] != item_id:
            return None, "token_invalid"
        if lease["status"] == "expired":
            return lease, "lease_expired"
        if lease["status"] == "released":
            return lease, "lease_released"
        if lease["status"] == "sealed":
            return lease, "lease_sealed"
        if lease["expires_at"] <= self.repository.now():
            self.sweep_expired()
            lease = self.repository.get_lease(lease["id"])
            status_reason = {"expired": "lease_expired",
                             "released": "lease_released",
                             "sealed": "lease_sealed"}.get(lease["status"])
            if status_reason:
                return lease, status_reason
        return lease, None

    def _stale_response(self, item_id: int, payload: Dict[str, Any], actor: str,
                        lease: Optional[Dict[str, Any]], reason: str,
                        context: str, batch_ref: Optional[str] = None,
                        retried_of_id: Optional[int] = None,
                        prior_attempt: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        token = payload.get("token") if isinstance(payload, dict) else None
        stale = self.repository.record_stale_submission(
            item_id, lease["id"] if lease else None,
            self._fingerprint(token), batch_ref, payload, reason, actor)
        current = self.repository.get_active_lease(item_id)
        self.repository.append_audit("stale_submission", ENTITY, item_id, actor, {
            "stale_id": stale["id"], "lease_id": lease["id"] if lease else None,
            "batch_ref": batch_ref, "reason": reason, "context": context,
            "applied": False, "duplicate": False,
            "current_holder": current["holder"] if current else None,
            "retried_of_id": retried_of_id,
        })
        return {
            "applied": False, "duplicate": False, "stale": True,
            "stale_id": stale["id"], "invalid_reason": reason,
            "message": f"凭证已失效（{reason}），迟到提交已留在历史，未覆盖当前续办、未生成措施",
            "current_holder": current["holder"] if current else None,
            "lease_expires_at": current["expires_at"] if current else None,
            "retry_result": "stale",
            "retriable": False,
        }

    def _record_failure(self, item_id: int, lease: Optional[Dict[str, Any]],
                        checkpoint: Optional[Dict[str, Any]], batch_ref: str,
                        exc: Exception, actor: str, retried_of_id: Optional[int],
                        payload: Dict[str, Any]) -> Dict[str, Any]:
        from .domain import DomainError
        kind = exc.kind if isinstance(exc, DomainError) else "validation"
        retriable = not (isinstance(exc, ConflictError)
                         and getattr(exc, "details", {}).get("sealed"))
        safe_payload = dict(payload)
        safe_payload.pop("token", None)
        return self.repository.record_failed_attempt(
            item_id, lease["id"] if lease else None,
            checkpoint["id"] if checkpoint else None,
            batch_ref, kind, str(exc), retriable, actor, safe_payload, retried_of_id)

    def _parse_records(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = payload.get("records", [])
        if not isinstance(raw, list) or not raw:
            raise ValidationError("records必须是非空数组，每项含kind/detail/status")
        records: List[Dict[str, Any]] = []
        for index, entry in enumerate(raw):
            if not isinstance(entry, dict):
                raise ValidationError(f"records[{index}]必须是对象")
            kind = require_text(entry.get("kind"), f"records[{index}].kind", 100)
            detail = require_text(entry.get("detail"), f"records[{index}].detail")
            status = entry.get("status", "open")
            if status not in ("open", "closed"):
                raise ValidationError(f"records[{index}].status必须是open或closed")
            external_ref = entry.get("external_ref")
            if external_ref is not None:
                external_ref = require_text(
                    external_ref, f"records[{index}].external_ref", 100)
            records.append({"kind": kind, "detail": detail, "status": status,
                            "external_ref": external_ref})
        return records

    def _continuation_view(self, item_id: int) -> Dict[str, Any]:
        active = self.repository.get_active_lease(item_id)
        checkpoint = self.repository.latest_checkpoint(item_id)
        handoffs = self.repository.list_handoffs(item_id)
        attempts = self.repository.list_attempts(item_id)
        stale = self.repository.list_stale_submissions(item_id)
        last_invalid = None
        if handoffs:
            for h in reversed(handoffs):
                if h["reason"] in ("timeout", "release", "sealed"):
                    last_invalid = {"reason": h["reason"], "detail": h["detail"],
                                    "created_at": h["created_at"],
                                    "created_by": h["created_by"]}
                    break
        for s in reversed(stale):
            if not last_invalid or s["submitted_at"] >= last_invalid["created_at"]:
                last_invalid = {"reason": s["reason"],
                                "detail": f"迟到提交#{s['id']}（批次{s.get('batch_ref')}）仅入历史",
                                "created_at": s["submitted_at"],
                                "created_by": s["submitted_by"]}
                break
        latest_attempt = attempts[-1] if attempts else None
        return {
            "current_holder": active["holder"] if active else None,
            "lease_expires_at": active["expires_at"] if active else None,
            "lease_status": active["status"] if active else None,
            "latest_checkpoint": checkpoint,
            "handoffs": handoffs,
            "attempts": attempts,
            "stale_submissions": [
                {"id": s["id"], "batch_ref": s["batch_ref"], "reason": s["reason"],
                 "submitted_by": s["submitted_by"], "submitted_at": s["submitted_at"]}
                for s in stale],
            "last_invalidation": last_invalid,
            "last_retry_result": latest_attempt["result"] if latest_attempt else None,
        }

    def _resume_pack(self, item_id: int) -> Dict[str, Any]:
        checkpoint = self.repository.latest_checkpoint(item_id)
        return {
            "from_checkpoint_seq": checkpoint["seq"] if checkpoint else 0,
            "summary": checkpoint["summary"] if checkpoint else None,
            "open_record_count": checkpoint["open_record_count"] if checkpoint else 0,
            "records": self.repository.list_records(item_id),
            "failed_attempts": [
                a for a in self.repository.list_attempts(item_id)
                if a["result"] == "failed"],
        }

    @staticmethod
    def _lease_public(lease: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in lease.items() if k != "token"}

    @staticmethod
    def _fingerprint(token: Any) -> str:
        if not isinstance(token, str) or not token:
            return ""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        sealed = bool(item.get("sealed")) or is_sealed_status(item["status"])
        # 存储列由各写路径（创建/续办/严重度变更/关闭封存）即时维护，优先展示；
        # 老库缺列时才现场计算兜底。封存值永远以快照为准。
        if item.get("priority") is not None and item.get("deadline_hours") is not None:
            result["priority"] = item["priority"]
            result["deadline_hours"] = item["deadline_hours"]
        else:
            result["priority"] = priority_score(
                item["severity"], item["quantity"], item["threshold"])
            result["deadline_hours"] = response_deadline_hours(
                item["severity"], item["quantity"], item["threshold"])
        result["sealed"] = sealed
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
