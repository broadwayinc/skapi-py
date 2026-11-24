"""
Offline tests for source.can_modify_referencing_records, updated_by and the redacted record ip.

Run from the repo root (no network, no install needed):

    python3 -I tests/test_referencing_owner_rights.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "src"))

from skapi import SkapiError  # noqa: E402
from skapi._database import DatabaseMixin  # noqa: E402


class _Client(DatabaseMixin):
    """Just enough of a client for config validation and record decoding. Nothing here goes on the wire."""

    _enc = None

    def __init__(self, signed_in=True):
        self._my_unique_ids = {}
        self._is_signed_in = signed_in

    def _signed_in(self):
        return self._is_signed_in

    def _scope(self, *a, **k):
        return "s"

    def get_file(self, *a, **k):
        raise RuntimeError("no network in this test")

    def _maybe_decrypt(self, v, ctx):
        return v, None


# A stored record as the server returns it (short keys).
BASE = {"rec": "1AbCdEfGhI0000000", "usr": "uploader-id", "tbl": "posts/svc/1", "upd": 1}


def stored(**fields):
    return dict(BASE, **fields)


class SourceSetting(unittest.TestCase):
    def setUp(self):
        self.c = _Client()

    def test_true_is_sent_on_create(self):
        conf, _ = self.c._setup_post_config({"table": {"name": "anchors", "access_group": 1},
                                             "source": {"can_modify_referencing_records": True}})
        self.assertIs(conf["source"]["can_modify_referencing_records"], True)

    def test_false_is_sent_on_update(self):
        conf, _ = self.c._setup_post_config({"record_id": "1AbCdEfGhI0000000",
                                             "source": {"can_modify_referencing_records": False}})
        self.assertIs(conf["source"]["can_modify_referencing_records"], False)

    def test_not_sent_when_not_given(self):
        conf, _ = self.c._setup_post_config({"table": {"name": "anchors", "access_group": 1}})
        self.assertNotIn("source", conf)
        conf, _ = self.c._setup_post_config({"table": {"name": "anchors"}, "source": {"can_remove_referencing_records": True}})
        self.assertNotIn("can_modify_referencing_records", conf["source"])

    def test_non_boolean_is_refused(self):
        for bad in ("yes", 1, 0, None, [], {}):
            with self.subTest(value=bad):
                with self.assertRaises(SkapiError) as ctx:
                    self.c._setup_post_config({"table": {"name": "anchors"},
                                               "source": {"can_modify_referencing_records": bad}})
                self.assertIn("source.can_modify_referencing_records", str(ctx.exception))

    def test_defaults_to_false_when_read(self):
        r = self.c._normalize_record(stored(ip="1.2.3.4#u1"))
        self.assertIs(r["source"]["can_modify_referencing_records"], False)
        r = self.c._normalize_record(stored(ip="1.2.3.4#u1", prv_acs={"upload_to_feed": True}))
        self.assertIs(r["source"]["can_modify_referencing_records"], False)

    def test_read_back_from_prv_acs(self):
        r = self.c._normalize_record(stored(prv_acs={"can_modify_referencing_records": True}))
        self.assertIs(r["source"]["can_modify_referencing_records"], True)
        self.assertNotIn("can_modify_referencing_records", r["table"]["subscription"])


class UpdatedBy(unittest.TestCase):
    def setUp(self):
        self.c = _Client()

    def test_absent_by_default(self):
        r = self.c._normalize_record(stored(ip="1.2.3.4#u1"))
        self.assertNotIn("updated_by", r)
        r = self.c._normalize_record(stored(prv_acs={"upload_to_feed": True}))
        self.assertNotIn("updated_by", r)

    def test_upb_becomes_updated_by(self):
        r = self.c._normalize_record(stored(prv_acs={"can_modify_referencing_records": True, "upb": "editor-id",
                                                     "upload_to_feed": True}))
        self.assertEqual(r["updated_by"], "editor-id")
        self.assertIs(r["table"]["subscription"]["upload_to_feed"], True)
        self.assertIs(r["source"]["can_modify_referencing_records"], True)

    def test_upb_is_not_a_setting(self):
        r = self.c._normalize_record(stored(prv_acs={"upb": "editor-id"}))
        self.assertNotIn("upb", r)
        self.assertNotIn("upb", r["source"])
        self.assertNotIn("updated_by", r["source"])
        self.assertNotIn("upb", r["table"]["subscription"])

    def test_empty_or_non_string_upb_is_ignored(self):
        for bad in ("", None, 5, {"id": "x"}):
            with self.subTest(upb=bad):
                r = self.c._normalize_record(stored(prv_acs={"upb": bad}))
                self.assertNotIn("updated_by", r)
                self.assertNotIn("upb", r["source"])


class RedactedIp(unittest.TestCase):
    def setUp(self):
        self.c = _Client()

    def read(self, **fields):
        return self.c._normalize_record(stored(**fields))

    def test_full_address(self):
        r = self.read(ip="1.2.3.4#u1")
        self.assertEqual((r["ip"], r["readonly"], r["unique_id"], r["user_id"]), ("1.2.3.4", False, "u1", "uploader-id"))
        r = self.read(ip="1.2.3.4R#u1")
        self.assertEqual((r["ip"], r["readonly"], r["unique_id"]), ("1.2.3.4", True, "u1"))

    def test_empty_string(self):
        r = self.read(ip="")
        self.assertEqual((r["ip"], r["readonly"], r["user_id"]), ("", False, "uploader-id"))
        self.assertNotIn("unique_id", r)

    def test_readonly_flag_kept(self):
        r = self.read(ip="R#u1")
        self.assertEqual((r["ip"], r["readonly"], r["unique_id"], r["user_id"]), ("", True, "u1", "uploader-id"))
        r = self.read(ip="R")
        self.assertEqual((r["ip"], r["readonly"]), ("", True))
        self.assertNotIn("unique_id", r)

    def test_unique_id_kept(self):
        r = self.read(ip="#u1")
        self.assertEqual((r["ip"], r["readonly"], r["unique_id"], r["user_id"]), ("", False, "u1", "uploader-id"))

    def test_unique_id_with_hash(self):
        r = self.read(ip="R#src::a#b")
        self.assertEqual((r["ip"], r["readonly"], r["unique_id"]), ("", True, "src::a#b"))

    def test_anonymous_redacted(self):
        r = self.read(ip="0-0-0-0#u1")
        self.assertEqual((r["ip"], r["readonly"], r["unique_id"], r["user_id"]),
                         ("0.0.0.0", False, "u1", "anonymous:uploader-id"))
        r = self.read(ip="0-0-0-0R#u1")
        self.assertEqual((r["ip"], r["readonly"], r["user_id"]), ("0.0.0.0", True, "anonymous:uploader-id"))
        r = self.read(ip="0-0-0-0")
        self.assertEqual((r["ip"], r["user_id"]), ("0.0.0.0", "anonymous:uploader-id"))

    def test_anonymous_full(self):
        r = self.read(ip="1-2-3-4R#u1")
        self.assertEqual((r["ip"], r["readonly"], r["user_id"]), ("1.2.3.4", True, "anonymous:uploader-id"))

    def test_redacted_signed_in_is_not_anonymous(self):
        for ip in ("", "R", "#u1", "R#u1", "1.2.3.4#u1"):
            with self.subTest(ip=ip):
                self.assertEqual(self.read(ip=ip)["user_id"], "uploader-id")

    def test_missing_or_none(self):
        r = self.read()
        self.assertEqual((r["ip"], r["readonly"], r["user_id"]), ("", False, "uploader-id"))
        self.assertNotIn("unique_id", r)
        r = self.read(ip=None)
        self.assertEqual((r["ip"], r["readonly"], r["user_id"]), ("", False, "uploader-id"))
        self.assertNotIn("unique_id", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
