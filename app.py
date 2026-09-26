"""Personal data-rights request workflow service."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "privacy_requests.db"
REQUEST_TYPES = {"access", "correction", "deletion", "withdraw_consent", "restriction"}
OPEN_STATUSES = {"received", "verifying", "processing", "extended", "response_ready"}
FINAL_STATUSES = {"fulfilled", "rejected", "duplicate"}
REDACTION_STATUSES = {"pending", "not_required", "redacted", "exempted"}
PACKAGE_STATUSES = {"sealed", "released", "withdrawn", "superseded"}
SEALABLE_REQUEST_STATUSES = {"processing", "extended", "response_ready"}
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")


class DomainError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DomainError("日期格式无效") from exc
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def clean_actor(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor:
        raise DomainError("缺少操作人")
    return actor


def require_role(role: str, allowed: set[str], action: str) -> None:
    if role not in allowed:
        raise DomainError("角色无权执行：%s" % action, 403)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def manifest_hash(items: list[dict[str, Any]]) -> str:
    canonical = json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_text(canonical)


class PrivacyRequestService:
    def __init__(self, db_path: str | os.PathLike[str] = DEFAULT_DB):
        self.db_path = str(db_path)
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS jurisdictions (
                    code TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    response_days INTEGER NOT NULL,
                    max_extension_days INTEGER NOT NULL,
                    minor_guardian_required INTEGER NOT NULL,
                    agent_authority_required INTEGER NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS data_subjects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject_ref TEXT NOT NULL UNIQUE,
                    region TEXT NOT NULL,
                    is_minor INTEGER NOT NULL DEFAULT 0,
                    contact_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_no TEXT NOT NULL UNIQUE,
                    subject_id INTEGER NOT NULL REFERENCES data_subjects(id),
                    request_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'received',
                    jurisdiction TEXT NOT NULL REFERENCES jurisdictions(code),
                    requester_kind TEXT NOT NULL,
                    agent_authority_ref TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    duplicate_of INTEGER REFERENCES requests(id),
                    submitted_at TEXT NOT NULL,
                    due_date TEXT NOT NULL,
                    original_due_date TEXT NOT NULL,
                    extension_days INTEGER NOT NULL DEFAULT 0,
                    verified_at TEXT,
                    verified_by TEXT,
                    assigned_to TEXT,
                    denial_reason TEXT,
                    response_summary TEXT,
                    created_by TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS data_locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER NOT NULL REFERENCES requests(id),
                    system_name TEXT NOT NULL,
                    data_category TEXT NOT NULL,
                    owner_team TEXT NOT NULL,
                    contains_third_party INTEGER NOT NULL DEFAULT 0,
                    legal_hold INTEGER NOT NULL DEFAULT 0,
                    retention_exception INTEGER NOT NULL DEFAULT 0,
                    third_party_exception INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'located',
                    note TEXT NOT NULL DEFAULT '',
                    redaction_status TEXT NOT NULL DEFAULT 'pending',
                    content_fingerprint TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(request_id,system_name,data_category)
                );
                CREATE TABLE IF NOT EXISTS delivery_packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER NOT NULL REFERENCES requests(id),
                    version_no INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'sealed',
                    manifest_hash TEXT NOT NULL,
                    item_count INTEGER NOT NULL,
                    correction_reason TEXT,
                    supersedes_id INTEGER REFERENCES delivery_packages(id),
                    sealed_by TEXT NOT NULL,
                    sealed_at TEXT NOT NULL,
                    released_by TEXT,
                    released_at TEXT,
                    withdrawn_by TEXT,
                    withdrawn_at TEXT,
                    withdraw_reason TEXT,
                    UNIQUE(request_id,version_no)
                );
                CREATE TABLE IF NOT EXISTS delivery_package_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_id INTEGER NOT NULL REFERENCES delivery_packages(id),
                    location_id INTEGER NOT NULL REFERENCES data_locations(id),
                    system_name TEXT NOT NULL,
                    data_category TEXT NOT NULL,
                    redaction_status TEXT NOT NULL,
                    content_fingerprint TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER REFERENCES requests(id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_requests_due ON requests(status,due_date);
                CREATE INDEX IF NOT EXISTS idx_requests_subject ON requests(subject_id,request_type,submitted_at);
                CREATE INDEX IF NOT EXISTS idx_packages_request ON delivery_packages(request_id,version_no);
                CREATE INDEX IF NOT EXISTS idx_package_items ON delivery_package_items(package_id,location_id);
                """
            )
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(data_locations)")}
        if "redaction_status" not in columns:
            conn.execute("ALTER TABLE data_locations ADD COLUMN redaction_status TEXT NOT NULL DEFAULT 'pending'")
        if "content_fingerprint" not in columns:
            conn.execute("ALTER TABLE data_locations ADD COLUMN content_fingerprint TEXT")

    def _audit(self, conn: sqlite3.Connection, request_id: int | None, actor: str,
               action: str, details: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO timeline(request_id,actor,action,details,created_at) VALUES(?,?,?,?,?)",
            (request_id, actor, action, json.dumps(details, ensure_ascii=False, sort_keys=True), utcnow()),
        )

    def configure_jurisdiction(self, actor: str, role: str, code: str, name: str,
                               response_days: int, max_extension_days: int,
                               minor_guardian_required: bool = True,
                               agent_authority_required: bool = True) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "配置地区规则")
        code, name = code.strip().upper(), name.strip()
        try:
            response_days, max_extension_days = int(response_days), int(max_extension_days)
        except (TypeError, ValueError) as exc:
            raise DomainError("时限必须是整数") from exc
        if not code or not name or not 1 <= response_days <= 180 or not 0 <= max_extension_days <= 180:
            raise DomainError("地区规则参数无效")
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO jurisdictions(code,name,response_days,max_extension_days,minor_guardian_required,agent_authority_required,updated_by,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(code) DO UPDATE SET name=excluded.name,response_days=excluded.response_days,
                   max_extension_days=excluded.max_extension_days,minor_guardian_required=excluded.minor_guardian_required,
                   agent_authority_required=excluded.agent_authority_required,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                (code, name, response_days, max_extension_days, int(bool(minor_guardian_required)), int(bool(agent_authority_required)), actor, utcnow()),
            )
            self._audit(conn, None, actor, "jurisdiction.configured", {"code": code})
            return dict(conn.execute("SELECT * FROM jurisdictions WHERE code=?", (code,)).fetchone())

    def create_subject(self, actor: str, role: str, subject_ref: str, region: str,
                       is_minor: bool, contact: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"intake", "privacy_officer"}, "建立数据主体索引")
        if not subject_ref.strip() or not region.strip() or not contact.strip():
            raise DomainError("主体编号、地区和联系方式不能为空")
        with self.connect() as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO data_subjects(subject_ref,region,is_minor,contact_hash,created_at) VALUES(?,?,?,?,?)",
                    (subject_ref.strip(), region.strip().upper(), int(bool(is_minor)), sha256_text(contact.strip().lower()), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("数据主体索引已存在", 409) from exc
            self._audit(conn, None, actor, "subject.created", {"subject_ref": subject_ref.strip()})
            return dict(conn.execute("SELECT id,subject_ref,region,is_minor,created_at FROM data_subjects WHERE id=?", (cur.lastrowid,)).fetchone())

    def create_request(self, actor: str, role: str, request_no: str, subject_id: int,
                       request_type: str, idempotency_key: str, requester_kind: str = "self",
                       agent_authority_ref: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"intake", "privacy_officer"}, "创建权利请求")
        request_type = request_type.strip().lower()
        requester_kind = requester_kind.strip().lower()
        if request_type not in REQUEST_TYPES or requester_kind not in {"self", "guardian", "authorized_agent"}:
            raise DomainError("请求类型或申请人类型无效")
        if not request_no.strip() or not idempotency_key.strip():
            raise DomainError("请求编号和幂等键不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM requests WHERE idempotency_key=?", (idempotency_key.strip(),)).fetchone()
            if existing:
                return {"idempotent": True, "request": dict(existing)}
            subject = conn.execute("SELECT * FROM data_subjects WHERE id=?", (subject_id,)).fetchone()
            if not subject:
                raise DomainError("数据主体不存在", 404)
            jurisdiction = conn.execute("SELECT * FROM jurisdictions WHERE code=?", (subject["region"],)).fetchone()
            if not jurisdiction:
                raise DomainError("数据主体所在地区尚未配置处理规则", 409)
            if subject["is_minor"] and jurisdiction["minor_guardian_required"] and requester_kind != "guardian":
                raise DomainError("未成年人请求必须由监护人提出", 403)
            if requester_kind == "authorized_agent" and jurisdiction["agent_authority_required"] and not (agent_authority_ref or "").strip():
                raise DomainError("授权代理必须提供有效授权引用", 403)
            now_dt = datetime.now(timezone.utc)
            duplicate = conn.execute(
                """SELECT * FROM requests WHERE subject_id=? AND request_type=? AND status IN ('received','verifying','processing','extended','response_ready')
                   ORDER BY id DESC LIMIT 1""",
                (subject_id, request_type),
            ).fetchone()
            duplicate_of = None
            if duplicate:
                elapsed = (now_dt - parse_time(duplicate["submitted_at"])).total_seconds()
                if 0 <= elapsed <= 30 * 86400:
                    duplicate_of = duplicate["id"]
            now = now_dt.isoformat(timespec="seconds")
            due = (now_dt + timedelta(days=jurisdiction["response_days"])).isoformat(timespec="seconds")
            status = "duplicate" if duplicate_of else "received"
            try:
                cur = conn.execute(
                    """INSERT INTO requests(request_no,subject_id,request_type,status,jurisdiction,requester_kind,agent_authority_ref,
                       idempotency_key,duplicate_of,submitted_at,due_date,original_due_date,created_by,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (request_no.strip(), subject_id, request_type, status, subject["region"], requester_kind,
                     (agent_authority_ref or "").strip() or None, idempotency_key.strip(), duplicate_of,
                     now, due, due, actor, now),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("请求编号已存在", 409) from exc
            request_id = cur.lastrowid
            self._audit(conn, request_id, actor, "request.created", {"type": request_type, "duplicate_of": duplicate_of})
            if duplicate_of:
                self._audit(conn, duplicate_of, actor, "request.duplicate_detected", {"new_request": request_no.strip()})
            return {"idempotent": False, "request": dict(conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone())}

    def _request(self, conn: sqlite3.Connection, request_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            raise DomainError("权利请求不存在", 404)
        return row

    def verify_identity(self, actor: str, role: str, request_id: int, expected_version: int,
                        identity_evidence_ref: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "核验身份")
        if not identity_evidence_ref.strip():
            raise DomainError("身份核验引用不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] != "received":
                raise DomainError("当前请求不能核验身份", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute(
                "UPDATE requests SET status='processing',verified_at=?,verified_by=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (utcnow(), actor, utcnow(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "identity.verified", {"evidence_ref": identity_evidence_ref.strip()})
            return dict(self._request(conn, request_id))

    def assign_request(self, actor: str, role: str, request_id: int, assignee: str,
                       expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "分配请求")
        if not assignee.strip():
            raise DomainError("处理人不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("当前请求不能分配", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute("UPDATE requests SET assigned_to=?,version=version+1,updated_at=? WHERE id=? AND version=?", (assignee.strip(), utcnow(), request_id, expected_version))
            self._audit(conn, request_id, actor, "request.assigned", {"assignee": assignee.strip()})
            return dict(self._request(conn, request_id))

    def _can_process(self, actor: str, role: str, req: sqlite3.Row, action: str) -> None:
        if role == "supervisor":
            return
        if role == "privacy_officer" and req["assigned_to"] == actor:
            return
        raise DomainError("只有被指派的隐私处理人员可以%s" % action, 403)

    def add_data_location(self, actor: str, role: str, request_id: int, system_name: str,
                          data_category: str, owner_team: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "定位数据")
        if not system_name.strip() or not data_category.strip() or not owner_team.strip():
            raise DomainError("系统、数据类别和负责团队不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("请求当前不能定位数据", 409)
            self._can_process(actor, role, req, "定位数据")
            try:
                cur = conn.execute(
                    """INSERT INTO data_locations(request_id,system_name,data_category,owner_team,created_at,updated_at)
                       VALUES(?,?,?,?,?,?)""",
                    (request_id, system_name.strip(), data_category.strip(), owner_team.strip(), utcnow(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("同一系统的数据类别已经登记", 409) from exc
            self._audit(conn, request_id, actor, "location.added", {"system": system_name.strip(), "category": data_category.strip()})
            return dict(conn.execute("SELECT * FROM data_locations WHERE id=?", (cur.lastrowid,)).fetchone())

    def classify_location(self, actor: str, role: str, location_id: int,
                          contains_third_party: bool, legal_hold: bool,
                          retention_exception: bool, note: str = "",
                          third_party_exception: bool = False) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "分类数据位置")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM data_locations WHERE id=?", (location_id,)).fetchone()
            if not row:
                raise DomainError("数据位置不存在", 404)
            req = self._request(conn, row["request_id"])
            self._can_process(actor, role, req, "分类数据位置")
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("请求当前不能分类数据", 409)
            if row["status"] != "located":
                raise DomainError("数据位置已经分类", 409)
            if third_party_exception and not contains_third_party:
                raise DomainError("不存在第三方数据时不能使用第三方例外", 409)
            if req["request_type"] == "deletion" and (legal_hold or retention_exception):
                status = "blocked"
            elif req["request_type"] == "access" and contains_third_party and not (third_party_exception or note.strip()):
                status = "needs_redaction"
            else:
                status = "classified"
            conn.execute(
                """UPDATE data_locations SET contains_third_party=?,legal_hold=?,retention_exception=?,third_party_exception=?,status=?,note=?,version=version+1,updated_at=?
                   WHERE id=? AND status='located'""",
                (int(bool(contains_third_party)), int(bool(legal_hold)), int(bool(retention_exception)),
                 int(bool(third_party_exception)), status, note.strip(), utcnow(), location_id),
            )
            self._audit(conn, row["request_id"], actor, "location.classified", {"location_id": location_id, "status": status})
            return dict(conn.execute("SELECT * FROM data_locations WHERE id=?", (location_id,)).fetchone())

    def _apply_fingerprint(self, conn: sqlite3.Connection, req: sqlite3.Row, location_id: int,
                           fingerprint: str, redaction_status: str, actor: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM data_locations WHERE id=? AND request_id=?", (location_id, req["id"])).fetchone()
        if not row:
            raise DomainError("数据位置不存在", 404)
        if row["status"] != "classified":
            raise DomainError("数据位置尚未完成分类，不能登记指纹", 409)
        if row["contains_third_party"] and redaction_status == "not_required":
            raise DomainError("含第三方数据的位置必须遮蔽或说明例外", 409)
        if not row["contains_third_party"] and redaction_status == "exempted":
            raise DomainError("不含第三方数据的位置不能使用例外状态", 409)
        if redaction_status == "exempted" and not (row["third_party_exception"] or row["note"].strip()):
            raise DomainError("使用例外状态需要第三方例外标记或说明", 409)
        conn.execute(
            "UPDATE data_locations SET content_fingerprint=?,redaction_status=?,version=version+1,updated_at=? WHERE id=?",
            (fingerprint, redaction_status, utcnow(), location_id),
        )
        self._audit(conn, req["id"], actor, "location.fingerprint_recorded",
                    {"location_id": location_id, "redaction_status": redaction_status, "fingerprint": fingerprint[:12]})
        return dict(conn.execute("SELECT * FROM data_locations WHERE id=?", (location_id,)).fetchone())

    def record_fingerprint(self, actor: str, role: str, location_id: int,
                           content_fingerprint: str, redaction_status: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "登记内容指纹")
        fingerprint = (content_fingerprint or "").strip().lower()
        if not FINGERPRINT_RE.fullmatch(fingerprint):
            raise DomainError("内容指纹必须是64位十六进制SHA-256")
        if redaction_status not in REDACTION_STATUSES - {"pending"}:
            raise DomainError("遮蔽状态无效")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM data_locations WHERE id=?", (location_id,)).fetchone()
            if not row:
                raise DomainError("数据位置不存在", 404)
            req = self._request(conn, row["request_id"])
            self._can_process(actor, role, req, "登记内容指纹")
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("请求当前不能登记内容指纹", 409)
            if self._sealed_package(conn, req["id"]):
                raise DomainError("交付包已封存，请先撤回或补正", 409)
            return self._apply_fingerprint(conn, req, row["id"], fingerprint, redaction_status, actor)

    def extend_request(self, actor: str, role: str, request_id: int, days: int,
                       reason: str, expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "延期处理")
        if not reason.strip():
            raise DomainError("延期原因不能为空")
        try:
            days = int(days)
        except (TypeError, ValueError) as exc:
            raise DomainError("延期天数必须是整数") from exc
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("当前请求不能延期", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            jurisdiction = conn.execute("SELECT * FROM jurisdictions WHERE code=?", (req["jurisdiction"],)).fetchone()
            if req["extension_days"] > 0:
                raise DomainError("每个请求只能延期一次", 409)
            if days <= 0 or days > jurisdiction["max_extension_days"]:
                raise DomainError("延期天数超出地区上限", 409)
            due = (parse_time(req["due_date"]) + timedelta(days=days)).isoformat(timespec="seconds")
            conn.execute(
                "UPDATE requests SET status='extended',due_date=?,extension_days=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (due, days, utcnow(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "request.extended", {"days": days, "reason": reason.strip(), "due_date": due})
            return dict(self._request(conn, request_id))

    def prepare_response(self, actor: str, role: str, request_id: int,
                         expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "准备回复")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "准备回复")
            if req["status"] not in {"processing", "extended"}:
                raise DomainError("当前请求不能准备回复", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            locations = conn.execute("SELECT * FROM data_locations WHERE request_id=?", (request_id,)).fetchall()
            if not locations:
                raise DomainError("尚未登记任何数据位置，不能回复", 409)
            unresolved = [row["id"] for row in locations if row["status"] in {"located", "needs_redaction"}]
            if unresolved:
                raise DomainError("仍有数据位置未分类或未完成去标识", 409)
            if req["request_type"] == "deletion":
                blocked = [row["id"] for row in locations if row["status"] == "blocked" or row["legal_hold"] or row["retention_exception"]]
                if blocked:
                    raise DomainError("存在法律保留或保存义务，不能执行删除", 409)
            if req["request_type"] == "access":
                bad = [row["id"] for row in locations if row["contains_third_party"] and not row["third_party_exception"] and not row["note"].strip()]
                if bad:
                    raise DomainError("第三方数据尚未完成去标识或例外说明", 409)
            conn.execute("UPDATE requests SET status='response_ready',version=version+1,updated_at=? WHERE id=? AND version=?", (utcnow(), request_id, expected_version))
            self._audit(conn, request_id, actor, "response.prepared", {"location_count": len(locations)})
            return dict(self._request(conn, request_id))

    def fulfill_request(self, actor: str, role: str, request_id: int, response_summary: str,
                        expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "完成请求")
        if not response_summary.strip():
            raise DomainError("回复摘要不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "完成请求")
            if req["status"] != "response_ready":
                raise DomainError("请求尚未完成回复准备", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute(
                "UPDATE requests SET status='fulfilled',response_summary=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (response_summary.strip(), utcnow(), request_id, expected_version),
            )
            self._audit(conn, request_id, actor, "request.fulfilled", {"summary": response_summary.strip()})
            return dict(self._request(conn, request_id))

    def reject_request(self, actor: str, role: str, request_id: int, reason: str,
                       expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "拒绝请求")
        if not reason.strip():
            raise DomainError("拒绝理由不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "拒绝请求")
            if req["status"] not in OPEN_STATUSES:
                raise DomainError("当前请求不能拒绝", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute("UPDATE requests SET status='rejected',denial_reason=?,version=version+1,updated_at=? WHERE id=? AND version=?", (reason.strip(), utcnow(), request_id, expected_version))
            self._audit(conn, request_id, actor, "request.rejected", {"reason": reason.strip()})
            return dict(self._request(conn, request_id))

    def _sealed_package(self, conn: sqlite3.Connection, request_id: int) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM delivery_packages WHERE request_id=? AND status='sealed' ORDER BY version_no DESC LIMIT 1",
            (request_id,),
        ).fetchone()

    def _package_dict(self, conn: sqlite3.Connection, pkg: sqlite3.Row) -> dict[str, Any]:
        data = dict(pkg)
        data["items"] = [dict(r) for r in conn.execute(
            "SELECT * FROM delivery_package_items WHERE package_id=? ORDER BY location_id", (pkg["id"],)).fetchall()]
        return data

    def _location_ready(self, row: sqlite3.Row) -> bool:
        return (row["status"] == "classified" and not row["legal_hold"]
                and row["redaction_status"] in {"not_required", "redacted", "exempted"}
                and (not row["contains_third_party"] or row["redaction_status"] in {"redacted", "exempted"})
                and bool(row["content_fingerprint"]))

    def _sealable_locations(self, conn: sqlite3.Connection, request_id: int) -> tuple[list[sqlite3.Row], list[str]]:
        locations = conn.execute("SELECT * FROM data_locations WHERE request_id=? ORDER BY id", (request_id,)).fetchall()
        problems: list[str] = []
        if not locations:
            problems.append("尚未登记任何数据位置")
        for row in locations:
            label = "%s/%s" % (row["system_name"], row["data_category"])
            if row["status"] in {"located", "needs_redaction"}:
                problems.append("%s：未分类或未完成去标识" % label)
                continue
            if row["legal_hold"]:
                problems.append("%s：仍存在法律保留" % label)
            if row["redaction_status"] == "pending":
                problems.append("%s：遮蔽状态未登记" % label)
            elif row["contains_third_party"] and row["redaction_status"] not in {"redacted", "exempted"}:
                problems.append("%s：第三方遮蔽未完成" % label)
            if not row["content_fingerprint"]:
                problems.append("%s：缺少内容指纹" % label)
        return locations, problems

    def _create_package(self, conn: sqlite3.Connection, req: sqlite3.Row, actor: str,
                        locations: list[sqlite3.Row], correction_reason: str | None = None,
                        supersedes_id: int | None = None) -> dict[str, Any]:
        items = [
            {"location_id": row["id"], "system_name": row["system_name"], "data_category": row["data_category"],
             "redaction_status": row["redaction_status"], "content_fingerprint": row["content_fingerprint"]}
            for row in locations
        ]
        manifest = manifest_hash(items)
        version_no = conn.execute(
            "SELECT COALESCE(MAX(version_no),0) AS v FROM delivery_packages WHERE request_id=?", (req["id"],)).fetchone()["v"] + 1
        now = utcnow()
        cur = conn.execute(
            """INSERT INTO delivery_packages(request_id,version_no,status,manifest_hash,item_count,correction_reason,supersedes_id,sealed_by,sealed_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (req["id"], version_no, "sealed", manifest, len(items), correction_reason, supersedes_id, actor, now),
        )
        package_id = cur.lastrowid
        for item in items:
            conn.execute(
                """INSERT INTO delivery_package_items(package_id,location_id,system_name,data_category,redaction_status,content_fingerprint)
                   VALUES(?,?,?,?,?,?)""",
                (package_id, item["location_id"], item["system_name"], item["data_category"],
                 item["redaction_status"], item["content_fingerprint"]),
            )
        pkg = conn.execute("SELECT * FROM delivery_packages WHERE id=?", (package_id,)).fetchone()
        return self._package_dict(conn, pkg)

    def seal_package(self, actor: str, role: str, request_id: int,
                     expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "封存交付包")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "封存交付包")
            if req["request_type"] != "access":
                raise DomainError("只有查阅请求需要交付包", 409)
            if req["status"] not in SEALABLE_REQUEST_STATUSES:
                raise DomainError("当前请求不能封存交付包", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            if self._sealed_package(conn, request_id):
                raise DomainError("存在未发出的交付包，请先发出或撤回", 409)
            locations, problems = self._sealable_locations(conn, request_id)
            if problems:
                raise DomainError("不能封包：" + "；".join(problems), 409)
            package = self._create_package(conn, req, actor, locations)
            conn.execute("UPDATE requests SET version=version+1,updated_at=? WHERE id=? AND version=?",
                         (utcnow(), request_id, expected_version))
            self._audit(conn, request_id, actor, "package.sealed",
                        {"package_id": package["id"], "version_no": package["version_no"],
                         "item_count": package["item_count"], "manifest_hash": package["manifest_hash"]})
            return package

    def _latest_package(self, conn: sqlite3.Connection, request_id: int) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM delivery_packages WHERE request_id=? ORDER BY version_no DESC LIMIT 1", (request_id,)).fetchone()

    def release_package(self, actor: str, role: str, package_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "发出交付包")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            pkg = conn.execute("SELECT * FROM delivery_packages WHERE id=?", (package_id,)).fetchone()
            if not pkg:
                raise DomainError("交付包不存在", 404)
            req = self._request(conn, pkg["request_id"])
            self._can_process(actor, role, req, "发出交付包")
            if pkg["status"] != "sealed":
                raise DomainError("只有已封存未发出的交付包可以发出", 409)
            now = utcnow()
            conn.execute("UPDATE delivery_packages SET status='released',released_by=?,released_at=? WHERE id=? AND status='sealed'",
                         (actor, now, package_id))
            self._audit(conn, pkg["request_id"], actor, "package.released",
                        {"package_id": package_id, "version_no": pkg["version_no"], "manifest_hash": pkg["manifest_hash"]})
            return self._package_dict(conn, conn.execute("SELECT * FROM delivery_packages WHERE id=?", (package_id,)).fetchone())

    def withdraw_package(self, actor: str, role: str, package_id: int, reason: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "撤回交付包")
        if not (reason or "").strip():
            raise DomainError("撤回原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            pkg = conn.execute("SELECT * FROM delivery_packages WHERE id=?", (package_id,)).fetchone()
            if not pkg:
                raise DomainError("交付包不存在", 404)
            req = self._request(conn, pkg["request_id"])
            self._can_process(actor, role, req, "撤回交付包")
            if pkg["status"] != "sealed":
                raise DomainError("只有未发出的交付包可以撤回", 409)
            now = utcnow()
            conn.execute(
                "UPDATE delivery_packages SET status='withdrawn',withdrawn_by=?,withdrawn_at=?,withdraw_reason=? WHERE id=? AND status='sealed'",
                (actor, now, reason.strip(), package_id))
            released_locations = [r["location_id"] for r in conn.execute(
                "SELECT location_id FROM delivery_package_items WHERE package_id=? ORDER BY location_id", (package_id,)).fetchall()]
            self._audit(conn, pkg["request_id"], actor, "package.withdrawn",
                        {"package_id": package_id, "version_no": pkg["version_no"],
                         "reason": reason.strip(), "released_locations": released_locations})
            return self._package_dict(conn, conn.execute("SELECT * FROM delivery_packages WHERE id=?", (package_id,)).fetchone())

    def correct_package(self, actor: str, role: str, package_id: int, reason: str,
                        items: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "补正交付包")
        if not (reason or "").strip():
            raise DomainError("补正原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            pkg = conn.execute("SELECT * FROM delivery_packages WHERE id=?", (package_id,)).fetchone()
            if not pkg:
                raise DomainError("交付包不存在", 404)
            req = self._request(conn, pkg["request_id"])
            self._can_process(actor, role, req, "补正交付包")
            latest = self._latest_package(conn, pkg["request_id"])
            if not latest or latest["id"] != pkg["id"] or pkg["status"] not in {"sealed", "released"}:
                raise DomainError("只能补正当前最新的已封存或已发出交付包", 409)
            if req["status"] not in SEALABLE_REQUEST_STATUSES:
                raise DomainError("案件已办结，请先重开再补正交付包", 409)
            for item in items or []:
                try:
                    location_id = int(item["location_id"])
                    fingerprint = str(item["content_fingerprint"]).strip().lower()
                    redaction_status = str(item["redaction_status"]).strip()
                except (KeyError, TypeError, ValueError) as exc:
                    raise DomainError("补正条目参数无效") from exc
                if not FINGERPRINT_RE.fullmatch(fingerprint):
                    raise DomainError("内容指纹必须是64位十六进制SHA-256")
                if redaction_status not in REDACTION_STATUSES - {"pending"}:
                    raise DomainError("遮蔽状态无效")
                self._apply_fingerprint(conn, req, location_id, fingerprint, redaction_status, actor)
            locations, problems = self._sealable_locations(conn, pkg["request_id"])
            if problems:
                raise DomainError("不能封包：" + "；".join(problems), 409)
            conn.execute("UPDATE delivery_packages SET status='superseded' WHERE id=?", (package_id,))
            package = self._create_package(conn, req, actor, locations,
                                           correction_reason=reason.strip(), supersedes_id=pkg["id"])
            self._audit(conn, pkg["request_id"], actor, "package.corrected",
                        {"superseded_package_id": package_id, "package_id": package["id"],
                         "from_version": pkg["version_no"], "to_version": package["version_no"],
                         "reason": reason.strip(), "manifest_hash": package["manifest_hash"]})
            return package

    def reopen_request(self, actor: str, role: str, request_id: int, reason: str,
                       expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"privacy_officer", "supervisor"}, "重开案件")
        if not reason.strip():
            raise DomainError("重开原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            req = self._request(conn, request_id)
            self._can_process(actor, role, req, "重开案件")
            if req["status"] != "fulfilled":
                raise DomainError("只有已办结的请求可以重开", 409)
            if req["version"] != int(expected_version):
                raise DomainError("请求已变化，请刷新后重试", 409)
            conn.execute("UPDATE requests SET status='processing',version=version+1,updated_at=? WHERE id=? AND version=?",
                         (utcnow(), request_id, expected_version))
            self._audit(conn, request_id, actor, "request.reopened", {"reason": reason.strip()})
            return dict(self._request(conn, request_id))

    def list_packages(self, actor: str, role: str, request_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        with self.connect() as conn:
            req = self._request(conn, request_id)
            if role in {"supervisor", "auditor"}:
                pass
            elif role == "privacy_officer" and req["assigned_to"] == actor:
                pass
            elif role == "intake" and req["created_by"] == actor:
                pass
            else:
                raise DomainError("无权查看该权利请求", 403)
            packages = [self._package_dict(conn, row) for row in conn.execute(
                "SELECT * FROM delivery_packages WHERE request_id=? ORDER BY version_no", (request_id,)).fetchall()]
            locations, problems = self._sealable_locations(conn, request_id)
            blocking = list(problems)
            if req["request_type"] != "access":
                blocking.append("非查阅请求不需要交付包")
            if req["status"] not in SEALABLE_REQUEST_STATUSES:
                blocking.append("请求状态为 %s，不能封包" % req["status"])
            sealed = self._sealed_package(conn, request_id)
            if sealed:
                blocking.append("版本 %d 已封存未发出" % sealed["version_no"])
            latest = packages[-1] if packages else None
            pending_correction = latest if latest and latest["status"] in {"superseded", "withdrawn"} else None
            return {
                "request_id": request_id,
                "packages": packages,
                "sealable": {
                    "ready": not blocking,
                    "blocking": blocking,
                    "locations": [dict(dict(row), ready=self._location_ready(row)) for row in locations],
                },
                "pending_correction": pending_correction,
                "released_versions": [pkg for pkg in packages if pkg["released_at"]],
            }

    def _visibility(self, actor: str, role: str, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        if role in {"supervisor", "auditor"}:
            return conn.execute("SELECT * FROM requests ORDER BY due_date,id").fetchall()
        if role == "privacy_officer":
            return conn.execute("SELECT * FROM requests WHERE assigned_to=? ORDER BY due_date,id", (actor,)).fetchall()
        if role == "intake":
            return conn.execute("SELECT * FROM requests WHERE created_by=? ORDER BY id DESC", (actor,)).fetchall()
        return []

    def get_request(self, actor: str, role: str, request_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        with self.connect() as conn:
            req = self._request(conn, request_id)
            if role in {"supervisor", "auditor"}:
                pass
            elif role == "privacy_officer" and req["assigned_to"] == actor:
                pass
            elif role == "intake" and req["created_by"] == actor:
                pass
            else:
                raise DomainError("无权查看该权利请求", 403)
            locations = [dict(r) for r in conn.execute("SELECT * FROM data_locations WHERE request_id=? ORDER BY id", (request_id,)).fetchall()]
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline WHERE request_id=? ORDER BY id", (request_id,)).fetchall()]
            packages = [self._package_dict(conn, row) for row in conn.execute(
                "SELECT * FROM delivery_packages WHERE request_id=? ORDER BY version_no", (request_id,)).fetchall()]
            return {"request": dict(req), "locations": locations, "timeline": timeline, "packages": packages}

    def queue(self, actor: str, role: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = self._visibility(actor, role, conn)
        now = datetime.now(timezone.utc)
        result = []
        for row in rows:
            item = dict(row)
            item["overdue"] = parse_time(item["due_date"]) < now and item["status"] in OPEN_STATUSES
            result.append(item)
        return result

    def state(self, actor: str = "", role: str = "viewer") -> dict[str, Any]:
        with self.connect() as conn:
            rows = self._visibility(actor, role, conn)
            requests = []
            locations = []
            packages = []
            for row in rows:
                item = dict(row)
                item["overdue"] = parse_time(item["due_date"]) < datetime.now(timezone.utc) and item["status"] in OPEN_STATUSES
                requests.append(item)
                locations.extend(dict(r) for r in conn.execute("SELECT * FROM data_locations WHERE request_id=? ORDER BY id", (row["id"],)).fetchall())
                packages.extend(dict(r) for r in conn.execute("SELECT * FROM delivery_packages WHERE request_id=? ORDER BY version_no", (row["id"],)).fetchall())
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline ORDER BY id DESC LIMIT 300").fetchall()]
            jurisdictions = [dict(r) for r in conn.execute("SELECT * FROM jurisdictions ORDER BY code").fetchall()]
        return {"requests": requests, "locations": locations, "packages": packages, "timeline": timeline, "jurisdictions": jurisdictions, "access_limited": not bool(requests)}

    def seed_demo(self) -> dict[str, Any]:
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) AS c FROM requests").fetchone()["c"]:
                return {"seeded": False, "reason": "已有数据"}
        self.configure_jurisdiction("sup-demo", "supervisor", "CN", "中国", 30, 30, True, True)
        subject = self.create_subject("intake-demo", "intake", "SUBJ-DEMO-001", "CN", False, "demo@example.test")
        req = self.create_request("intake-demo", "intake", "PR-DEMO-001", subject["id"], "access", "demo-idem-001")
        return {"seeded": True, "request_id": req["request"]["id"], "subject_id": subject["id"]}


class ApiHandler(BaseHTTPRequestHandler):
    service: PrivacyRequestService

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _headers(self) -> tuple[str, str]:
        return self.headers.get("X-User", ""), self.headers.get("X-Role", "viewer")

    def _json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise DomainError("请求体过大", 413)
        if not length:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DomainError("请求体不是有效 JSON") from exc
        if not isinstance(value, dict):
            raise DomainError("JSON 请求体必须是对象")
        return value

    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path in {"/", "/index.html"}:
                body = (ROOT / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            actor, role = self._headers()
            if path == "/health":
                self._send(200, {"status": "ok", "service": "privacy-requests"})
            elif path == "/api/state":
                self._send(200, self.service.state(actor, role))
            elif path == "/api/queue":
                self._send(200, {"queue": self.service.queue(actor, role)})
            elif path.startswith("/api/requests/"):
                parts = path.split("/")
                if len(parts) == 5 and parts[4] == "packages":
                    self._send(200, self.service.list_packages(actor, role, int(parts[3])))
                else:
                    self._send(200, self.service.get_request(actor, role, int(parts[3])))
            else:
                self._send(404, {"error": "接口不存在"})
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (ValueError, IndexError) as exc:
            self._send(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            path, data, (actor, role) = urlparse(self.path).path, self._json(), self._headers()
            if path == "/api/jurisdictions":
                result = self.service.configure_jurisdiction(actor, role, **data)
            elif path == "/api/subjects":
                result = self.service.create_subject(actor, role, **data)
            elif path == "/api/requests":
                result = self.service.create_request(actor, role, **data)
            elif path == "/api/requests/verify":
                result = self.service.verify_identity(actor, role, **data)
            elif path == "/api/requests/assign":
                result = self.service.assign_request(actor, role, **data)
            elif path == "/api/locations":
                result = self.service.add_data_location(actor, role, **data)
            elif path == "/api/locations/classify":
                result = self.service.classify_location(actor, role, **data)
            elif path == "/api/locations/fingerprint":
                result = self.service.record_fingerprint(actor, role, **data)
            elif path == "/api/packages/seal":
                result = self.service.seal_package(actor, role, **data)
            elif path == "/api/packages/release":
                result = self.service.release_package(actor, role, **data)
            elif path == "/api/packages/withdraw":
                result = self.service.withdraw_package(actor, role, **data)
            elif path == "/api/packages/correct":
                result = self.service.correct_package(actor, role, **data)
            elif path == "/api/requests/reopen":
                result = self.service.reopen_request(actor, role, **data)
            elif path == "/api/requests/extend":
                result = self.service.extend_request(actor, role, **data)
            elif path == "/api/requests/prepare":
                result = self.service.prepare_response(actor, role, **data)
            elif path == "/api/requests/fulfill":
                result = self.service.fulfill_request(actor, role, **data)
            elif path == "/api/requests/reject":
                result = self.service.reject_request(actor, role, **data)
            else:
                raise DomainError("接口不存在", 404)
            self._send(201, result)
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (KeyError, TypeError, ValueError) as exc:
            self._send(400, {"error": "请求参数错误: %s" % exc})
        except Exception as exc:
            self._send(500, {"error": "服务器内部错误", "detail": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def serve(service: PrivacyRequestService, host: str, port: int) -> None:
    ApiHandler.service = service
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print("Privacy request service listening on http://%s:%s" % (host, port))
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="个人数据权利请求处理服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8210)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    service = PrivacyRequestService(args.db)
    if args.init:
        print(json.dumps(service.seed_demo() if args.seed else {"initialized": True, "db": args.db}, ensure_ascii=False))
        return
    serve(service, args.host, args.port)


if __name__ == "__main__":
    main()
