import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from src.http_api import make_handler
from src.repository import Repository
from src.service import Service


class HttpClient:
    def __init__(self, base_url):
        self.base_url = base_url

    def request(self, method, path, body=None, actor="demo", role="investigator"):
        data = None
        headers = {"X-Actor": actor, "X-Role": role}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class HttpApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "http.db"))
        self.service = Service(self.repo)
        handler = make_handler(self.service, str(Path(__file__).resolve().parents[1] / "static"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.api = HttpClient(f"http://127.0.0.1:{self.port}")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.repo.close()
        self.tmp.cleanup()

    def _create(self):
        status, body = self.api.request("POST", "/api/items", {
            "title": "http accident", "description": "via http",
            "severity": "serious", "quantity": 4, "threshold": 8,
            "external_ref": "HTTP-1"}, actor="r1", role="reporter")
        self.assertEqual(status, 201, body)
        return body["id"]

    def test_full_resumable_flow_over_http(self):
        item_id = self._create()

        # 领取
        status, claim = self.api.request("POST", f"/api/items/{item_id}/claim",
                                         {"ttl_seconds": 1}, actor="inv-a")
        self.assertEqual(status, 201, claim)
        token = claim["token"]

        # 成功续办
        status, done = self.api.request("POST", f"/api/items/{item_id}/continue", {
            "token": token, "batch_ref": "HB1",
            "records": [{"kind": "scene", "detail": "现场记录A",
                         "status": "open", "external_ref": "HA-1"}]}, actor="inv-a")
        self.assertEqual(status, 200, done)
        self.assertTrue(done["applied"])
        self.assertEqual(done["retry_result"], None)

        # 幂等重复提交
        status, dup = self.api.request("POST", f"/api/items/{item_id}/continue", {
            "token": token, "batch_ref": "HB1",
            "records": [{"kind": "scene", "detail": "现场记录A",
                         "external_ref": "HA-1"}]}, actor="inv-a")
        self.assertTrue(dup["duplicate"])

        # 失败批次（external_ref冲突）可重试
        status, fail = self.api.request("POST", f"/api/items/{item_id}/continue", {
            "token": token, "batch_ref": "HB2",
            "records": [{"kind": "action", "detail": "撞车",
                         "external_ref": "HA-1"}]}, actor="inv-a")
        self.assertEqual(status, 409, fail)
        self.assertTrue(fail["details"]["retriable"])

        # 等租约超时：旧凭证重试只入历史
        import time
        time.sleep(1.2)
        status, stale = self.api.request("POST", f"/api/items/{item_id}/retry", {
            "token": token, "batch_ref": "HB2",
            "records": [{"kind": "action", "detail": "迟到重试",
                         "external_ref": "HA-2"}]}, actor="inv-a")
        self.assertEqual(status, 200, stale)
        self.assertTrue(stale["stale"])
        self.assertEqual(stale["invalid_reason"], "lease_expired")
        self.assertFalse(stale["retriable"])
        self.assertIsNone(stale["current_holder"])

        # 下一人领取，从最近检查点恢复后重试成功自己的批次
        status, claim2 = self.api.request("POST", f"/api/items/{item_id}/claim",
                                          {"ttl_seconds": 600}, actor="inv-b")
        self.assertEqual(status, 201, claim2)
        self.assertEqual(claim2["resume"]["from_checkpoint_seq"], 2)
        status, cont = self.api.request("POST", f"/api/items/{item_id}/continue", {
            "token": claim2["token"], "batch_ref": "HB3",
            "records": [{"kind": "action", "detail": "第二持有人措施",
                         "external_ref": "HA-3"}]}, actor="inv-b")
        self.assertEqual(status, 200, cont)

        # 详情显示当前持有人与失效原因
        status, detail = self.api.request("GET", f"/api/items/{item_id}",
                                          role="viewer")
        self.assertEqual(detail["continuation"]["current_holder"], "inv-b")
        self.assertEqual(detail["continuation"]["last_invalidation"]["reason"],
                         "lease_expired")
        stale_list = detail["continuation"]["stale_submissions"]
        self.assertTrue(any(s["reason"] == "lease_expired" for s in stale_list))

        # 严重度改动立即重算
        before = (detail["priority"], detail["deadline_hours"])
        status, changed = self.api.request(
            "PATCH", f"/api/items/{item_id}",
            {"severity": "fatal", "quantity": 20,
             "expected_version": detail["version"]},
            actor="mgr", role="safety_manager")
        self.assertEqual(status, 200, changed)
        self.assertNotEqual((changed["priority"], changed["deadline_hours"]), before)

        # 审计链完整
        status, audit = self.api.request("GET", "/api/audit",
                                         actor="mgr", role="safety_manager")
        self.assertEqual(status, 200)
        actions = {e["action"] for e in audit["events"]
                   if e["entity_id"] == item_id}
        self.assertIn("stale_submission", actions)
        self.assertIn("lease_timeout", actions)
        self.assertIn("severity_change", actions)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_sealed_closed_accident_rejects_patch(self):
        item_id = self._create()
        status, claim = self.api.request("POST", f"/api/items/{item_id}/claim",
                                         {"ttl_seconds": 600}, actor="inv-a")
        self.api.request("POST", f"/api/items/{item_id}/continue", {
            "token": claim["token"], "batch_ref": "C1",
            "records": [{"kind": "measure", "detail": "done",
                         "status": "closed", "external_ref": "C-1"}]},
            actor="inv-a")
        current = self.api.request("GET", f"/api/items/{item_id}", role="viewer")[1]
        for target, who in [("investigating", "investigator"),
                            ("corrective_action", "investigator"),
                            ("verification", "safety_manager"),
                            ("closed", "safety_manager")]:
            status, current = self.api.request(
                "POST", f"/api/items/{item_id}/transition",
                {"target": target, "expected_version": current["version"]},
                actor=who, role=who)
            self.assertEqual(status, 200, current)
        status, denied = self.api.request(
            "PATCH", f"/api/items/{item_id}",
            {"severity": "fatal", "expected_version": current["version"]},
            actor="mgr", role="safety_manager")
        self.assertEqual(status, 409, denied)
        self.assertTrue(denied["details"]["sealed"])


if __name__ == "__main__":
    unittest.main()
