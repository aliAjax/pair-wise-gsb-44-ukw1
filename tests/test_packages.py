import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, PrivacyRequestService, sha256_text  # noqa: E402


class DeliveryPackageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = PrivacyRequestService(Path(self.tmp.name) / "test.db")
        self.service.configure_jurisdiction("sup1", "supervisor", "CN", "中国", 30, 30, True, True)
        self.subject = self.service.create_subject("intake1", "intake", "SUB-PKG", "CN", False, "person@example.test")

    def tearDown(self):
        self.tmp.cleanup()

    def make_request(self, number, kind="access", subject=None):
        req = self.service.create_request("intake1", "intake", number, (subject or self.subject)["id"], kind, "IDEM-" + number)["request"]
        req = self.service.verify_identity("officer1", "privacy_officer", req["id"], req["version"], "ID-" + number)
        return self.service.assign_request("sup1", "supervisor", req["id"], "officer1", req["version"])

    def add_location(self, request_id, system, category, third=False, hold=False, note="", exception=False):
        loc = self.service.add_data_location("officer1", "privacy_officer", request_id, system, category, "team-" + system)
        return self.service.classify_location("officer1", "privacy_officer", loc["id"], third, hold, False, note, exception)

    def location_status(self, request_id):
        detail = self.service.get_request("sup1", "supervisor", request_id)
        return {loc["id"]: loc["status"] for loc in detail["locations"]}

    def test_seal_freezes_manifest_and_release(self):
        req = self.make_request("PR-PKG-1")
        loc1 = self.add_location(req["id"], "CRM", "profile")
        loc2 = self.add_location(req["id"], "SUPPORT", "messages", third=True, note="含第三方姓名")
        pkg = self.service.create_package("officer1", "privacy_officer", req["id"])
        self.assertEqual("draft", pkg["status"])
        self.assertEqual(1, pkg["version"])
        self.assertFalse(pkg["seal_ready"])
        item1 = self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc1["id"], content="profile-json")
        self.assertEqual("not_required", item1["redaction_status"])
        self.assertEqual(sha256_text("profile-json"), item1["content_fingerprint"])
        item2 = self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc2["id"], content="messages-json")
        self.assertEqual("pending", item2["redaction_status"])
        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("officer1", "privacy_officer", pkg["id"])
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("第三方遮蔽", str(ctx.exception))
        item2 = self.service.update_package_item("officer1", "privacy_officer", item2["id"],
                                                 redaction_status="redacted", redaction_note="已遮蔽第三方姓名")
        self.assertEqual("redacted", item2["redaction_status"])
        sealed = self.service.seal_package("officer1", "privacy_officer", pkg["id"])
        self.assertEqual("sealed", sealed["status"])
        self.assertEqual(64, len(sealed["seal_hash"]))
        self.assertEqual("packaged", self.location_status(req["id"])[loc1["id"]])
        # 封包后清单和指纹固定
        with self.assertRaises(DomainError):
            self.service.update_package_item("officer1", "privacy_officer", item1["id"], redaction_note="改动")
        with self.assertRaises(DomainError):
            self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc1["id"], content="x")
        with self.assertRaises(DomainError):
            self.service.remove_package_item("officer1", "privacy_officer", item1["id"])
        released = self.service.release_package("officer1", "privacy_officer", pkg["id"])
        self.assertEqual("released", released["status"])
        self.assertEqual("delivered", self.location_status(req["id"])[loc1["id"]])
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        self.assertIn(pkg["id"], detail["package_summary"]["released"])
        self.assertEqual(sealed["seal_hash"], detail["packages"][0]["seal_hash"])

    def test_seal_blocked_by_hold_redaction_and_missing_locations(self):
        req = self.make_request("PR-PKG-2")
        loc_hold = self.add_location(req["id"], "ARCHIVE", "records", hold=True)
        loc_third = self.add_location(req["id"], "SUPPORT", "messages", third=True, note="待遮蔽")
        self.add_location(req["id"], "CRM", "profile")
        pkg = self.service.create_package("officer1", "privacy_officer", req["id"])
        self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc_hold["id"], content="a")
        item_third = self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc_third["id"], content="b")
        with self.assertRaises(DomainError) as ctx:
            self.service.seal_package("officer1", "privacy_officer", pkg["id"])
        message = str(ctx.exception)
        self.assertIn("未全部纳入", message)
        self.assertIn("法律保留", message)
        self.assertIn("第三方遮蔽", message)
        # 补齐位置并完成遮蔽后，法律保留仍然阻止封包
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        remaining = [loc for loc in detail["locations"] if loc["system_name"] == "CRM"][0]
        self.service.add_package_item("officer1", "privacy_officer", pkg["id"], remaining["id"], content="c")
        self.service.update_package_item("officer1", "privacy_officer", item_third["id"], redaction_status="exempted")
        with self.assertRaises(DomainError) as ctx2:
            self.service.seal_package("officer1", "privacy_officer", pkg["id"])
        self.assertIn("法律保留", str(ctx2.exception))
        self.assertNotIn("第三方遮蔽", str(ctx2.exception))

    def test_withdraw_releases_locations_and_leaves_timeline(self):
        req = self.make_request("PR-PKG-3")
        loc = self.add_location(req["id"], "CRM", "profile")
        pkg = self.service.create_package("officer1", "privacy_officer", req["id"])
        self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc["id"], content="a")
        self.service.seal_package("officer1", "privacy_officer", pkg["id"])
        self.assertEqual("packaged", self.location_status(req["id"])[loc["id"]])
        withdrawn = self.service.withdraw_package("officer1", "privacy_officer", pkg["id"], "申请人撤回请求")
        self.assertEqual("withdrawn", withdrawn["status"])
        self.assertEqual("申请人撤回请求", withdrawn["withdraw_reason"])
        self.assertEqual("classified", self.location_status(req["id"])[loc["id"]])
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        events = [e for e in detail["timeline"] if e["action"] == "package.withdrawn"]
        self.assertEqual(1, len(events))
        self.assertIn("申请人撤回请求", events[0]["details"])
        self.assertIn(pkg["id"], detail["package_summary"]["history"])
        # 撤回后可以重新建包；已发出的包不能撤回
        pkg2 = self.service.create_package("officer1", "privacy_officer", req["id"])
        self.service.add_package_item("officer1", "privacy_officer", pkg2["id"], loc["id"], content="a2")
        self.service.seal_package("officer1", "privacy_officer", pkg2["id"])
        self.service.release_package("officer1", "privacy_officer", pkg2["id"])
        with self.assertRaises(DomainError) as ctx:
            self.service.withdraw_package("officer1", "privacy_officer", pkg2["id"], "太晚了")
        self.assertEqual(409, ctx.exception.status)

    def test_correction_versions_and_history_remain_queryable(self):
        req = self.make_request("PR-PKG-4")
        loc1 = self.add_location(req["id"], "CRM", "profile")
        loc2 = self.add_location(req["id"], "SUPPORT", "messages", third=True, note="含第三方")
        pkg = self.service.create_package("officer1", "privacy_officer", req["id"])
        item1 = self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc1["id"], content="v1-profile")
        self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc2["id"],
                                      redaction_status="redacted", content="v1-messages")
        sealed = self.service.seal_package("officer1", "privacy_officer", pkg["id"])
        # 补正生成带原因的新版本，旧包位置释放回可处理状态
        corr = self.service.correct_package("officer1", "privacy_officer", pkg["id"], "指纹与导出文件不一致")
        self.assertEqual("draft", corr["status"])
        self.assertEqual(2, corr["version"])
        self.assertEqual(pkg["id"], corr["corrected_from"])
        self.assertEqual("指纹与导出文件不一致", corr["correction_reason"])
        self.assertEqual(2, corr["item_count"])
        self.assertEqual("classified", self.location_status(req["id"])[loc1["id"]])
        old = self.service.get_package("sup1", "supervisor", pkg["id"])
        self.assertEqual("superseded", old["status"])
        self.assertEqual(corr["id"], old["superseded_by"])
        self.assertEqual(sealed["seal_hash"], old["seal_hash"])
        self.assertEqual(2, len(old["items"]))
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        self.assertIn(corr["id"], detail["package_summary"]["pending_correction"])
        self.assertIn(corr["id"], detail["package_summary"]["sealable"])
        # 在新版本上修正指纹后封包、发出
        new_items = self.service.get_package("officer1", "privacy_officer", corr["id"])["items"]
        copied = [it for it in new_items if it["location_id"] == loc1["id"]][0]
        self.assertEqual(item1["content_fingerprint"], copied["content_fingerprint"])
        self.service.update_package_item("officer1", "privacy_officer", copied["id"], content="v2-profile")
        sealed2 = self.service.seal_package("officer1", "privacy_officer", corr["id"])
        self.assertNotEqual(sealed["seal_hash"], sealed2["seal_hash"])
        self.service.release_package("officer1", "privacy_officer", corr["id"])
        detail = self.service.get_request("sup1", "supervisor", req["id"])
        self.assertIn(corr["id"], detail["package_summary"]["released"])
        self.assertIn(pkg["id"], detail["package_summary"]["history"])
        # 已发出的版本也可以补正，旧版本保留 released 状态可查
        corr2 = self.service.correct_package("officer1", "privacy_officer", corr["id"], "补充遗漏系统")
        self.assertEqual(3, corr2["version"])
        old2 = self.service.get_package("sup1", "supervisor", corr["id"])
        self.assertEqual("released", old2["status"])
        self.assertEqual(corr2["id"], old2["superseded_by"])
        self.assertEqual("delivered", self.location_status(req["id"])[loc1["id"]])
        sealed3 = self.service.seal_package("officer1", "privacy_officer", corr2["id"])
        self.assertEqual("sealed", sealed3["status"])

    def test_package_permissions_and_validation(self):
        req = self.make_request("PR-PKG-5")
        loc = self.add_location(req["id"], "CRM", "profile")
        pkg = self.service.create_package("officer1", "privacy_officer", req["id"])
        with self.assertRaises(DomainError) as ctx:
            self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc["id"], content_fingerprint="zz")
        self.assertEqual(400, ctx.exception.status)
        self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc["id"], content="a")
        with self.assertRaises(DomainError) as ctx2:
            self.service.add_package_item("officer1", "privacy_officer", pkg["id"], loc["id"], content="b")
        self.assertEqual(409, ctx2.exception.status)
        with self.assertRaises(DomainError) as ctx3:
            self.service.create_package("officer1", "privacy_officer", req["id"])
        self.assertEqual(409, ctx3.exception.status)
        with self.assertRaises(DomainError) as ctx4:
            self.service.create_package("other", "privacy_officer", req["id"])
        self.assertEqual(403, ctx4.exception.status)
        with self.assertRaises(DomainError) as ctx5:
            self.service.create_package("intake1", "intake", req["id"])
        self.assertEqual(403, ctx5.exception.status)
        # 空包不能封包
        other_subject = self.service.create_subject("intake1", "intake", "SUB-PKG-2", "CN", False, "other@example.test")
        req_empty = self.make_request("PR-PKG-6", subject=other_subject)
        empty_pkg = self.service.create_package("officer1", "privacy_officer", req_empty["id"])
        with self.assertRaises(DomainError) as ctx6:
            self.service.seal_package("officer1", "privacy_officer", empty_pkg["id"])
        self.assertIn("没有任何条目", str(ctx6.exception))
        # 审计角色可以查看交付包，未指派人员不能查看
        view = self.service.get_package("aud1", "auditor", pkg["id"])
        self.assertEqual(1, len(view["items"]))
        with self.assertRaises(DomainError) as ctx7:
            self.service.get_package("other", "privacy_officer", pkg["id"])
        self.assertEqual(403, ctx7.exception.status)
        # 非查阅请求不建交付包
        deletion = self.make_request("PR-PKG-DEL", "deletion")
        with self.assertRaises(DomainError) as ctx8:
            self.service.create_package("officer1", "privacy_officer", deletion["id"])
        self.assertEqual(409, ctx8.exception.status)


if __name__ == "__main__":
    unittest.main()
