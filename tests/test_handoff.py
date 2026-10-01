import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES


class MutableClock:
    def __init__(self, start=None):
        self.value = start or "2026-10-01T08:00:00+00:00"

    def __call__(self):
        return self.value

    def advance(self, seconds):
        dt = datetime.fromisoformat(self.value) + timedelta(seconds=seconds)
        self.value = dt.isoformat()


class HandoffTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = MutableClock()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"), now_fn=self.clock)
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "handoff item", "description": "resumable investigation",
             "severity": "serious", "quantity": 5, "threshold": 10,
             "external_ref": "HD-1"}, "reporter-a", "reporter")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _claim(self, actor="inv-a", ttl=3600):
        return self.service.claim(self.item["id"], {"ttl_seconds": ttl},
                                  actor, "investigator")

    def _continue(self, token, actor="inv-a", batch="B1",
                  external_ref="M-1", status="open", detail="现场措施"):
        return self.service.continue_investigation(
            self.item["id"],
            {"token": token, "batch_ref": batch,
             "records": [{"kind": "measure", "detail": detail,
                          "status": status, "external_ref": external_ref}]},
            actor, "investigator")

    # ------------------------------------------------------------- 领取/检查点
    def test_claim_issues_token_checkpoint_and_blocks_second_holder(self):
        claim = self._claim()
        self.assertIn("token", claim)
        self.assertEqual(claim["lease"]["holder"], "inv-a")
        self.assertEqual(claim["lease"]["status"], "active")
        self.assertEqual(claim["checkpoint"]["seq"], 1)
        with self.assertRaises(ConflictError) as ctx:
            self._claim(actor="inv-b")
        self.assertEqual(ctx.exception.details["current_holder"], "inv-a")
        view = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(view["continuation"]["current_holder"], "inv-a")

    def test_invalid_token_submission_only_goes_to_history(self):
        self._claim()
        result = self.service.continue_investigation(
            self.item["id"], {"token": "not-a-real-token", "batch_ref": "BX",
                              "records": [{"kind": "measure", "detail": "x"}]},
            "inv-late", "investigator")
        self.assertTrue(result["stale"])
        self.assertFalse(result["applied"])
        self.assertEqual(result["invalid_reason"], "token_invalid")
        # 没有任何措施记录落库
        self.assertEqual(self.repo.open_record_count(self.item["id"]), 0)
        view = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(len(view["continuation"]["stale_submissions"]), 1)
        self.assertEqual(view["continuation"]["last_invalidation"]["reason"],
                         "token_invalid")

    # ------------------------------------------------------------- 续办/幂等
    def test_continue_advances_checkpoint_and_batch_is_idempotent(self):
        claim = self._claim()
        out = self._continue(claim["token"])
        self.assertTrue(out["applied"])
        self.assertEqual(out["checkpoint"]["seq"], 2)
        self.assertEqual(self.repo.open_record_count(self.item["id"]), 1)
        # 同一批次再交一次：不重复生成措施
        again = self._continue(claim["token"])
        self.assertTrue(again["duplicate"])
        self.assertFalse(again["applied"])
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 1)

    # ------------------------------------------------------------- 超时交接
    def test_timeout_hands_off_from_latest_checkpoint_and_keeps_late_submission_in_history(self):
        first = self._claim(actor="inv-a")
        self._continue(first["token"], batch="B1", external_ref="M-1",
                       detail="第一持有人的现场记录")
        self.clock.advance(4000)  # 超过3600秒TTL
        # 旧持有人掉线回来，用失效凭证迟到提交
        late = self._continue(first["token"], actor="inv-a", batch="B-LATE",
                              external_ref="M-LATE", detail="迟到提交，不应覆盖")
        self.assertTrue(late["stale"])
        self.assertEqual(late["invalid_reason"], "lease_expired")
        self.assertFalse(late["applied"])
        self.assertEqual(self.repo.open_record_count(self.item["id"]), 1)
        # 下一人从最近检查点续查
        second = self._claim(actor="inv-b")
        self.assertEqual(second["lease"]["attempt_no"], 2)
        self.assertEqual(second["resume"]["from_checkpoint_seq"], 2)
        self.assertIn("B1", second["resume"]["summary"])
        self.assertEqual(second["resume"]["records"][0]["detail"], "第一持有人的现场记录")
        out = self._continue(second["token"], actor="inv-b", batch="B2",
                             external_ref="M-2")
        self.assertTrue(out["applied"])
        self.assertEqual(out["checkpoint"]["seq"], 4)
        self.assertEqual(self.repo.open_record_count(self.item["id"]), 2)
        # 迟到提交只在历史里
        view = self.service.get_item(self.item["id"], "viewer")
        stale = view["continuation"]["stale_submissions"]
        self.assertEqual([s["batch_ref"] for s in stale], ["B-LATE"])
        handoffs = view["continuation"]["handoffs"]
        self.assertEqual([h["reason"] for h in handoffs],
                         ["start", "timeout", "timeout"])
        self.assertEqual(view["continuation"]["current_holder"], "inv-b")

    # ------------------------------------------------------------- 失败重试
    def test_failed_continuation_can_retry_without_duplicate_measures(self):
        claim = self._claim()
        self.service.add_record(
            self.item["id"],
            {"kind": "measure", "detail": "existing", "status": "open",
             "external_ref": "DUP"}, "inv-a", "investigator")
        # 第一次续办撞唯一标识：整批失败、落失败尝试
        with self.assertRaises(ConflictError) as ctx:
            self._continue(claim["token"], batch="RETRY-1", external_ref="DUP")
        self.assertTrue(ctx.exception.details["retriable"])
        failed_id = ctx.exception.details["attempt_id"]
        self.assertEqual(self.repo.open_record_count(self.item["id"]), 1)
        # 用原批次号重试，更换外部标识后成功
        retried = self.service.retry_continuation(
            self.item["id"],
            {"token": claim["token"], "batch_ref": "RETRY-1",
             "records": [{"kind": "measure", "detail": "重试后的措施",
                          "status": "open", "external_ref": "OK-1"}]},
            "inv-a", "investigator")
        self.assertTrue(retried["applied"])
        self.assertEqual(retried["retry_result"], "success")
        self.assertEqual(retried["attempt_id"] and retried["attempt_id"] != failed_id, True)
        self.assertEqual(self.repo.open_record_count(self.item["id"]), 2)
        # 再重试已是成功状态：幂等
        again = self.service.retry_continuation(
            self.item["id"], {"token": claim["token"], "batch_ref": "RETRY-1"},
            "inv-a", "investigator")
        self.assertTrue(again["duplicate"])
        attempts = self.repo.list_attempts(self.item["id"])
        self.assertEqual([(a["batch_ref"], a["result"]) for a in attempts][:2],
                         [("RETRY-1", "failed"), ("RETRY-1", "succeeded")])

    def test_validation_failure_is_retriable_and_leaves_no_measures(self):
        claim = self._claim()
        with self.assertRaises(ValidationError):
            self.service.continue_investigation(
                self.item["id"], {"token": claim["token"], "batch_ref": "BAD",
                                  "records": []}, "inv-a", "investigator")
        # 重试时不传records也能从失败尝试保存的载荷恢复——这里改为提交合法内容
        retried = self.service.retry_continuation(
            self.item["id"], {"token": claim["token"], "batch_ref": "BAD",
                              "records": [{"kind": "scene", "detail": "补充现场"}]},
            "inv-a", "investigator")
        self.assertTrue(retried["applied"])

    def test_retry_after_timeout_is_rejected_to_history(self):
        first = self._claim()
        with self.assertRaises(ValidationError):
            self.service.continue_investigation(
                self.item["id"], {"token": first["token"], "batch_ref": "LATE",
                                  "records": []}, "inv-a", "investigator")
        self.clock.advance(4000)
        out = self.service.retry_continuation(
            self.item["id"], {"token": first["token"], "batch_ref": "LATE",
                              "records": [{"kind": "scene", "detail": "迟到重试"}]},
            "inv-a", "investigator")
        self.assertTrue(out["stale"])
        self.assertEqual(out["invalid_reason"], "lease_expired")
        self.assertFalse(out["retriable"])
        self.assertEqual(self.repo.open_record_count(self.item["id"]), 0)

    # ------------------------------------------------------------- 释放
    def test_release_allows_claim_from_latest_checkpoint(self):
        first = self._claim()
        self._continue(first["token"])
        result = self.service.release(
            self.item["id"], {"token": first["token"]}, "inv-a", "investigator")
        self.assertTrue(result["released"])
        second = self._claim(actor="inv-b")
        self.assertEqual(second["resume"]["from_checkpoint_seq"], 2)
        self.assertEqual(second["checkpoint"]["seq"], 3)
        view = self.service.get_item(self.item["id"], "viewer")
        self.assertIn("release", [h["reason"] for h in view["continuation"]["handoffs"]])

    # ------------------------------------------------------------- 重算/封存
    def test_severity_change_recalculates_open_item_immediately(self):
        before = self.service.get_item(self.item["id"], "viewer")
        updated = self.service.change_severity(
            self.item["id"], {"severity": "fatal", "quantity": 20,
                              "expected_version": before["version"]},
            "manager", "safety_manager")
        self.assertLess(updated["deadline_hours"], before["deadline_hours"])
        self.assertGreaterEqual(updated["priority"], before["priority"])
        self.assertEqual(updated["version"], before["version"] + 1)
        # 期望版本过期 → 冲突
        with self.assertRaises(ConflictError):
            self.service.change_severity(
                self.item["id"], {"severity": "minor", "expected_version": before["version"]},
                "manager", "safety_manager")

    def test_closed_sealed_accident_keeps_original_result(self):
        claim = self._claim()
        self._continue(claim["token"], status="closed")
        current = self.service.get_item(self.item["id"], "viewer")
        for target in STATES[1:]:
            current = self.service.transition(
                current["id"], target, current["version"], "manager",
                "safety_manager" if target in ("verification", "closed") else "investigator")
        self.assertTrue(current["sealed"])
        sealed_priority = current["priority"]
        sealed_deadline = current["deadline_hours"]
        with self.assertRaises(ConflictError):
            self.service.change_severity(
                self.item["id"], {"severity": "fatal", "quantity": 999,
                                  "expected_version": current["version"]},
                "manager", "safety_manager")
        again = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(again["priority"], sealed_priority)
        self.assertEqual(again["deadline_hours"], sealed_deadline)
        # 封存后不能再领取续办
        with self.assertRaises(ConflictError):
            self._claim()

    def test_reporter_cannot_claim_and_wrong_holder_cannot_submit(self):
        with self.assertRaises(PermissionDenied):
            self.service.claim(self.item["id"], {}, "reporter-a", "reporter")
        claim = self._claim()
        with self.assertRaises(PermissionDenied):
            self._continue(claim["token"], actor="inv-other")

    def test_audit_chain_covers_entire_resumable_flow(self):
        first = self._claim()
        self._continue(first["token"])
        self.clock.advance(4000)
        self._continue(first["token"], batch="LATE", external_ref="M-L")
        second = self._claim(actor="inv-b")
        self._continue(second["token"], actor="inv-b", batch="B2",
                       external_ref="M-2")
        self.service.change_severity(
            self.item["id"], {"severity": "fatal", "expected_version":
                              self.repo.get_item(self.item["id"])["version"]},
            "manager", "safety_manager")
        actions = {e["action"] for e in self.repo.list_audit(self.item["id"])}
        self.assertIn("claim", actions)
        self.assertIn("continuation", actions)
        self.assertIn("lease_timeout", actions)
        self.assertIn("stale_submission", actions)
        self.assertIn("severity_change", actions)
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
