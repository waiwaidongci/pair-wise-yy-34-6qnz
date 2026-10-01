import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import src.repository as repo_mod
from src.domain import ConflictError
from src.repository import Repository
from src.service import Service


def future_now(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).replace(
        microsecond=0).isoformat()


class FollowupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "followup item", "description": "resumable",
             "severity": "serious", "quantity": 12, "threshold": 6,
             "external_ref": "F-1"}, "creator", "reporter")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_claim_records_lease_and_checkpoint(self):
        r = self.service.claim(self.item["id"], {"note": "start"}, "alice", "investigator")
        self.assertFalse(r["handover"])
        self.assertIn("token", r["lease"])
        self.assertEqual(r["lease"]["holder"], "alice")
        self.assertEqual(r["checkpoint"]["kind"], "claim")
        self.assertEqual(r["item"]["holder"], "alice")
        self.assertTrue(r["item"]["lease_active"])
        # 同一事故在凭证未到期时不能被第二人领取
        with self.assertRaises(ConflictError):
            self.service.claim(self.item["id"], {}, "bob", "investigator")
        # 记录检查点
        cp = self.service.checkpoint(self.item["id"], {
            "lease_token": r["lease"]["token"], "note": "progress"}, "alice", "investigator")
        self.assertEqual(cp["checkpoint"]["kind"], "progress")
        # 释放
        released = self.service.release(self.item["id"], {
            "lease_token": r["lease"]["token"]}, "alice", "investigator")
        self.assertIsNone(released["item"]["holder"])
        self.assertFalse(released["item"]["lease_active"])

    def test_followup_idempotent_retry_no_duplicate_measure(self):
        r = self.service.claim(self.item["id"], {}, "alice", "investigator")
        token = r["lease"]["token"]
        body = {"lease_token": token, "kind": "measure", "detail": "install guard",
                "status": "open", "client_key": "m-1", "expected_version": 1}
        first = self.service.followup(self.item["id"], body, "alice", "investigator")
        self.assertTrue(first["applied"])
        self.assertFalse(first["idempotent"])
        # 同样的幂等键重试 -> 幂等重放，不重复生成措施
        second = self.service.followup(self.item["id"], body, "alice", "investigator")
        self.assertTrue(second["applied"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["record"]["id"], second["record"]["id"])
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertEqual(len(records), 1)

    def test_late_submission_quarantined_and_kept_in_history(self):
        r = self.service.claim(self.item["id"], {}, "alice", "investigator")
        token = r["lease"]["token"]
        self.service.followup(self.item["id"], {
            "lease_token": token, "kind": "evidence", "detail": "on time",
            "client_key": "e-1", "expected_version": 1}, "alice", "investigator")
        # 他人持有中、无凭证提交 -> 隔离（令牌不匹配），不覆盖当前续办
        late = self.service.followup(self.item["id"], {
            "kind": "evidence", "detail": "late no token", "client_key": "e-2"},
            "stranger", "investigator")
        self.assertFalse(late["applied"])
        self.assertEqual(late["reason"], "lease_token_mismatch")
        # 错误凭证 -> 隔离
        wrong = self.service.followup(self.item["id"], {
            "lease_token": "bogus", "kind": "measure", "detail": "late wrong token",
            "client_key": "e-3"}, "stranger", "investigator")
        self.assertFalse(wrong["applied"])
        self.assertEqual(wrong["reason"], "lease_token_mismatch")
        # 释放后无人持有 -> 无有效凭证
        self.service.release(self.item["id"], {"lease_token": token}, "alice", "investigator")
        none = self.service.followup(self.item["id"], {
            "kind": "evidence", "detail": "late after release", "client_key": "e-4"},
            "stranger", "investigator")
        self.assertFalse(none["applied"])
        self.assertEqual(none["reason"], "no_active_lease")
        # 历史留痕，措施未增加
        history = self.service.list_late_submissions(self.item["id"], "safety_manager")
        self.assertEqual(len(history), 3)
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["detail"], "on time")

    def test_timeout_handover_from_latest_checkpoint(self):
        r = self.service.claim(self.item["id"], {"note": "alice shift"}, "alice", "investigator")
        alice_token = r["lease"]["token"]
        self.service.followup(self.item["id"], {
            "lease_token": alice_token, "kind": "evidence", "detail": "alice work",
            "client_key": "a-1", "expected_version": 1}, "alice", "investigator")
        # 时间快进 1 小时，凭证过期
        with patch.object(repo_mod, "utc_now", lambda: future_now(3600)):
            # 下一人从最近检查点交接续办
            h = self.service.claim(self.item["id"], {"note": "bob take over"}, "bob", "investigator")
            self.assertTrue(h["handover"])
            self.assertEqual(h["checkpoint"]["kind"], "handover")
            self.assertEqual(h["checkpoint"]["payload"]["from_holder"], "alice")
            bob_token = h["lease"]["token"]
            # bob 用新凭证续办成功
            bob = self.service.followup(self.item["id"], {
                "lease_token": bob_token, "kind": "measure", "detail": "bob measure",
                "client_key": "b-1", "expected_version": 1}, "bob", "investigator")
            self.assertTrue(bob["applied"])
            # alice 的迟到提交 -> 隔离（已过期），不覆盖当前续办
            late = self.service.followup(self.item["id"], {
                "lease_token": alice_token, "kind": "measure", "detail": "alice late overwrite",
                "client_key": "a-2", "expected_version": 1}, "alice", "investigator")
            self.assertFalse(late["applied"])
            self.assertEqual(late["reason"], "lease_expired")
        # 当前持有人是 bob，措施只有两条且未被覆盖
        current = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(current["holder"], "bob")
        self.assertTrue(current["lease_active"])
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertEqual(len(records), 2)
        details = {r["detail"] for r in records}
        self.assertIn("alice work", details)
        self.assertIn("bob measure", details)
        self.assertNotIn("alice late overwrite", details)
        # 检查点序列包含交接
        cps = self.service.list_checkpoints(self.item["id"], "viewer")
        self.assertTrue(any(c["kind"] == "handover" for c in cps))
        # 迟到历史
        history = self.service.list_late_submissions(self.item["id"], "safety_manager")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["reason"], "lease_expired")

    def test_version_conflict_fails_then_retry_succeeds(self):
        r = self.service.claim(self.item["id"], {}, "alice", "investigator")
        token = r["lease"]["token"]
        # 期间严重度被他人改动，版本从 1 -> 2
        self.service.update_item(self.item["id"], {
            "severity": "moderate", "expected_version": 1}, "manager", "safety_manager")
        # 旧版本续办 -> 失败（可重试）
        failed = self.service.followup(self.item["id"], {
            "lease_token": token, "kind": "measure", "detail": "need retry",
            "client_key": "r-1", "expected_version": 1}, "alice", "investigator")
        self.assertFalse(failed["applied"])
        self.assertEqual(failed["reason"], "version_conflict")
        self.assertEqual(failed["attempt"]["status"], "failed")
        # 用新期望版本重试 -> 成功，且不重复生成
        retried = self.service.retry_followup(self.item["id"], {
            "idempotency_key": "r-1", "lease_token": token, "expected_version": 2},
            "alice", "investigator")
        self.assertTrue(retried["applied"])
        self.assertEqual(retried["attempt"]["status"], "succeeded")
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertEqual(len(records), 1)
        # 再次重试已成功的尝试 -> 幂等重放
        again = self.service.retry_followup(self.item["id"], {
            "idempotency_key": "r-1", "lease_token": token, "expected_version": 2},
            "alice", "investigator")
        self.assertTrue(again["idempotent"])
        self.assertEqual(again["record"]["id"], retried["record"]["id"])

    def test_recalculate_open_and_seal_closed(self):
        # 初始 serious/12/6 -> 优先级 10，期限 4h
        self.assertEqual(self.item["priority"], 10)
        self.assertEqual(self.item["deadline_hours"], 4)
        # 未关闭事故改动严重度 -> 立即重算
        updated = self.service.update_item(self.item["id"], {
            "severity": "moderate", "expected_version": 1}, "manager", "safety_manager")
        self.assertEqual(updated["priority"], 7)
        self.assertEqual(updated["deadline_hours"], 12)
        self.assertFalse(updated["sealed"])
        # 推进到关闭并封存
        current = updated
        for target in ["investigating", "corrective_action", "verification", "closed"]:
            role = "investigator" if target in ("investigating", "corrective_action") else "safety_manager"
            current = self.service.transition(self.item["id"], target, current["version"],
                                              "officer", role)
        self.assertEqual(current["status"], "closed")
        self.assertTrue(current["sealed"])
        # 已关闭事故保留封存结果（moderate -> 7 / 12h）
        self.assertEqual(current["priority"], 7)
        self.assertEqual(current["deadline_hours"], 12)
        self.assertIsNotNone(current["sealed_at"])
        # 已关闭事故不可再改、不可续办
        with self.assertRaises(ConflictError):
            self.service.update_item(self.item["id"], {
                "severity": "fatal", "expected_version": current["version"]},
                "manager", "safety_manager")
        with self.assertRaises(ConflictError):
            self.service.claim(self.item["id"], {}, "alice", "investigator")

    def test_followup_on_closed_item_quarantined(self):
        current = self.item
        for target in ["investigating", "corrective_action", "verification", "closed"]:
            role = "investigator" if target in ("investigating", "corrective_action") else "safety_manager"
            current = self.service.transition(self.item["id"], target, current["version"],
                                              "officer", role)
        late = self.service.followup(self.item["id"], {
            "kind": "measure", "detail": "after close", "client_key": "x-1"},
            "alice", "investigator")
        self.assertFalse(late["applied"])
        self.assertEqual(late["reason"], "item_closed")

    def test_audit_chain_remains_valid(self):
        r = self.service.claim(self.item["id"], {}, "alice", "investigator")
        self.service.followup(self.item["id"], {
            "lease_token": r["lease"]["token"], "kind": "evidence", "detail": "x",
            "client_key": "k-1", "expected_version": 1}, "alice", "investigator")
        self.service.followup(self.item["id"], {
            "kind": "evidence", "detail": "late", "client_key": "k-2"},
            "bob", "investigator")
        self.service.update_item(self.item["id"], {
            "severity": "moderate", "expected_version": 1}, "manager", "safety_manager")
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
