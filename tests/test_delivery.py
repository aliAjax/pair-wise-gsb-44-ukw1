import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, PrivacyRequestService  # noqa: E402


def fp(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class DeliveryPackageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = PrivacyRequestService(Path(self.tmp.name) / "test.db")
        self.service.configure_jurisdiction("sup1", "supervisor", "CN", "中国", 30, 30, True, True)
        self.subject = self.service.create_subject("intake1", "intake", "SUB-001", "CN", False, "person@example.test")

    def tearDown(self):
        self.tmp.cleanup()

    def make_access_request(self, number="PR-001"):
        req = self.service.create_request("intake1", "intake", number, self.subject["id"], "access", "IDEM-" + number)["request"]
        req = self.service.verify_identity("officer1", "privacy_officer", req["id"], req["version"], "ID-001")
        return self.service.assign_request("sup1", "supervisor", req["id"], "officer1", req["version"])

    def add_classified_pair(self, request_id):
        normal = self.service.add_data_location("officer1", "privacy_officer", request_id, "CRM", "profile", "customer")
        third = self.service.add_data_location("officer1", "privacy_officer", request_id, "SUPPORT", "messages", "service")
        self.service.classify_location("officer1", "privacy_officer", normal["id"], False, False, False)
        self.service.classify_location("officer1", "privacy_officer", third["id"], True, False, False, "含第三方对话")
        return normal, third

    def fingerprint_pair(self, normal, third, normal_fp="crm-v1", third_fp="support-v1"):
        self.service.record_fingerprint("officer1", "privacy_officer", normal["id"], fp(normal_fp), "not_required")
        self.service.record_fingerprint("officer1", "privacy_officer", third["id"], fp(third_fp), "redacted")

    def test_seal_withdraw_release_correct_lifecycle(self):
        request = self.make_access_request()
        normal, third = self.add_classified_pair(request["id"])

        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"])
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("缺少内容指纹", str(ctx.exception))

        with self.assertRaises(DomainError):
            self.service.record_fingerprint("officer1", "privacy_officer", normal["id"], "not-hex", "not_required")
        self.fingerprint_pair(normal, third)

        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"] + 9)
        self.assertEqual(409, ctx.exception.status)

        package = self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"])
        self.assertEqual(1, package["version_no"])
        self.assertEqual("sealed", package["status"])
        self.assertEqual(2, package["item_count"])
        self.assertEqual(64, len(package["manifest_hash"]))
        item = [i for i in package["items"] if i["location_id"] == third["id"]][0]
        self.assertEqual("SUPPORT", item["system_name"])
        self.assertEqual("messages", item["data_category"])
        self.assertEqual("redacted", item["redaction_status"])
        self.assertEqual(fp("support-v1"), item["content_fingerprint"])

        # 封存后清单和指纹固定，不能直接改
        with self.assertRaises(DomainError) as ctx:
            self.service.record_fingerprint("officer1", "privacy_officer", normal["id"], fp("crm-v2"), "not_required")
        self.assertEqual(409, ctx.exception.status)
        with self.assertRaises(DomainError):
            self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"] + 1)

        # 撤回未发出的包会释放待处理位置并留下时间线
        withdrawn = self.service.withdraw_package("officer1", "privacy_officer", package["id"], "发现遗漏系统")
        self.assertEqual("withdrawn", withdrawn["status"])
        detail = self.service.get_request("sup1", "supervisor", request["id"])
        events = [t["action"] for t in detail["timeline"]]
        self.assertIn("package.sealed", events)
        self.assertIn("package.withdrawn", events)

        # 位置已释放，可以更新指纹后重新封包为 v2
        self.service.record_fingerprint("officer1", "privacy_officer", normal["id"], fp("crm-v2"), "not_required")
        request = detail["request"]
        v2 = self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"])
        self.assertEqual(2, v2["version_no"])
        self.assertNotEqual(package["manifest_hash"], v2["manifest_hash"])

        released = self.service.release_package("officer1", "privacy_officer", v2["id"])
        self.assertEqual("released", released["status"])
        self.assertIsNotNone(released["released_at"])

        # 已发出的包不能撤回
        with self.assertRaises(DomainError) as ctx:
            self.service.withdraw_package("officer1", "privacy_officer", v2["id"], "太晚了")
        self.assertEqual(409, ctx.exception.status)

        # 补正生成带原因的新版本，旧包仍可查
        v3 = self.service.correct_package(
            "officer1", "privacy_officer", v2["id"], "第三方遮蔽范围调整",
            items=[{"location_id": third["id"], "content_fingerprint": fp("support-v2"), "redaction_status": "redacted"}],
        )
        self.assertEqual(3, v3["version_no"])
        self.assertEqual("第三方遮蔽范围调整", v3["correction_reason"])
        self.assertEqual(v2["id"], v3["supersedes_id"])
        self.assertEqual("sealed", v3["status"])

        board = self.service.list_packages("sup1", "supervisor", request["id"])
        self.assertEqual(3, len(board["packages"]))
        old = [p for p in board["packages"] if p["id"] == v2["id"]][0]
        self.assertEqual("superseded", old["status"])
        self.assertIsNotNone(old["released_at"])  # 旧包曾发出，记录保留可查
        self.assertIsNone(board["pending_correction"])
        self.assertEqual([v2["id"]], [p["id"] for p in board["released_versions"]])

    def test_seal_blocked_by_pending_redaction_and_legal_hold(self):
        request = self.make_access_request("PR-002")
        normal, third = self.add_classified_pair(request["id"])
        self.service.record_fingerprint("officer1", "privacy_officer", normal["id"], fp("crm"), "not_required")

        # 第三方位置已分类但遮蔽状态未登记
        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"])
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("遮蔽状态未登记", str(ctx.exception))

        self.service.record_fingerprint("officer1", "privacy_officer", third["id"], fp("support"), "redacted")
        hold = self.service.add_data_location("officer1", "privacy_officer", request["id"], "ARCHIVE", "records", "legal")
        self.service.classify_location("officer1", "privacy_officer", hold["id"], False, True, False)
        self.service.record_fingerprint("officer1", "privacy_officer", hold["id"], fp("archive"), "not_required")

        # 仍有法律保留时不能封包
        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"])
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("法律保留", str(ctx.exception))

        # 非查阅请求不需要交付包
        deletion = self.service.create_request("intake1", "intake", "PR-003", self.subject["id"], "deletion", "IDEM-PR-003")["request"]
        deletion = self.service.verify_identity("officer1", "privacy_officer", deletion["id"], deletion["version"], "ID-003")
        deletion = self.service.assign_request("sup1", "supervisor", deletion["id"], "officer1", deletion["version"])
        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("officer1", "privacy_officer", deletion["id"], deletion["version"])
        self.assertEqual(409, ctx.exception.status)

    def test_reopen_shows_sealable_pending_and_released(self):
        request = self.make_access_request("PR-004")
        normal, third = self.add_classified_pair(request["id"])
        self.fingerprint_pair(normal, third)
        package = self.service.seal_package("officer1", "privacy_officer", request["id"], request["version"])
        request = self.service.prepare_response("officer1", "privacy_officer", request["id"], request["version"] + 1)
        request = self.service.fulfill_request("officer1", "privacy_officer", request["id"], "已交付", request["version"])
        self.assertEqual("fulfilled", request["status"])

        # 办结后不能补正，需要先重开
        with self.assertRaises(DomainError) as ctx:
            self.service.correct_package("officer1", "privacy_officer", package["id"], "办结后补正")
        self.assertEqual(409, ctx.exception.status)
        with self.assertRaises(DomainError):
            self.service.reopen_request("officer1", "privacy_officer", request["id"], "重复重开", request["version"] + 5)

        request = self.service.reopen_request("officer1", "privacy_officer", request["id"], "申请人补正要求", request["version"])
        self.assertEqual("processing", request["status"])

        board = self.service.list_packages("officer1", "privacy_officer", request["id"])
        self.assertFalse(board["sealable"]["ready"])  # 仍有未发出的封存包
        self.assertIsNone(board["pending_correction"])
        self.assertEqual([], board["released_versions"])

        self.service.withdraw_package("officer1", "privacy_officer", package["id"], "重开后重做交付")
        board = self.service.list_packages("officer1", "privacy_officer", request["id"])
        self.assertTrue(board["sealable"]["ready"])
        self.assertTrue(all(loc["ready"] for loc in board["sealable"]["locations"]))
        self.assertEqual(package["id"], board["pending_correction"]["id"])
        self.assertEqual("withdrawn", board["pending_correction"]["status"])

        detail = self.service.get_request("officer1", "privacy_officer", request["id"])
        events = [t["action"] for t in detail["timeline"]]
        self.assertIn("request.reopened", events)
        self.assertIn("package.withdrawn", events)

    def test_fingerprint_and_seal_permissions(self):
        request = self.make_access_request("PR-005")
        normal, _ = self.add_classified_pair(request["id"])
        with self.assertRaises(DomainError) as ctx:
            self.service.record_fingerprint("other", "privacy_officer", normal["id"], fp("x"), "not_required")
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx:
            self.service.record_fingerprint("intake1", "intake", normal["id"], fp("x"), "not_required")
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("intake1", "intake", request["id"], request["version"])
        self.assertEqual(403, ctx.exception.status)
        board = self.service.list_packages("auditor1", "auditor", request["id"])
        self.assertEqual([], board["packages"])


if __name__ == "__main__":
    unittest.main()
