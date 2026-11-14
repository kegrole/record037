"""Unit tests for tlsaudit.

Fixtures are generated from scratch in a temporary directory so the
verdicts depend only on the parsing/classification logic, never on any
pre-baked config file.

Run from the tests directory:  python -m unittest test_tlsaudit -v
or from the repo root:         python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tlsaudit.config import parse_config
from tlsaudit.parser import expand_cipherstring
from tlsaudit.rules import evaluate


MODERN_CFG = """\
TLSv1.2 = server
TLSv1.3 = server
CipherString = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
"""

LEGACY_SSL3_CFG = """\
SSLv3 = server
TLSv1 = server
TLSv1.2 = server
CipherString = DEFAULT
"""

WEAK_CFG = """\
TLSv1.2 = server
CipherString = RC4-SHA:DES-CBC3-SHA:EXP-RC4-MD5
"""

SECLEVEL0_CFG = """\
TLSv1.2 = server
CipherString = DEFAULT:@SECLEVEL=0
"""

ADD_REMOVE_CFG = """\
TLSv1.2 = server
CipherString = DEFAULT:!aNULL:+RC4-SHA
"""

NO_PFS_CFG = """\
TLSv1.2 = server
CipherString = AES128-SHA:AES256-SHA:AES128-SHA256
"""


def audit_text(text, name="fixture.cnf"):
    return evaluate(parse_config(text, path=name))


class FixtureTestCase(unittest.TestCase):
    """The seven acceptance criteria, each with freshly generated configs."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.fixtures = {
            "modern.cnf": MODERN_CFG,
            "legacy_ssl3.cnf": LEGACY_SSL3_CFG,
            "weak_ciphers.cnf": WEAK_CFG,
            "seclevel0.cnf": SECLEVEL0_CFG,
            "add_remove.cnf": ADD_REMOVE_CFG,
            "no_pfs.cnf": NO_PFS_CFG,
        }
        cls.reports = {}
        for name, text in cls.fixtures.items():
            path = os.path.join(cls.tmpdir.name, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            with open(path, "r", encoding="utf-8") as handle:
                cls.reports[name] = audit_text(handle.read(), name)

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def test_modern_config_has_zero_issues(self):
        report = self.reports["modern.cnf"]
        self.assertEqual(report.issues, [])
        self.assertEqual(report.enabled_protocols, ["TLSv1.2", "TLSv1.3"])

    def test_legacy_config_flags_sslv3(self):
        report = self.reports["legacy_ssl3.cnf"]
        protocol_issues = [i for i in report.issues if i.name == "deprecated_protocol"]
        self.assertTrue(protocol_issues, "expected at least one protocol issue")
        self.assertTrue(
            any("SSLv3" in issue.evidence for issue in protocol_issues),
            "SSLv3 must be named in the evidence",
        )

    def test_weak_ciphers_are_named_individually(self):
        report = self.reports["weak_ciphers.cnf"]
        weak = [i for i in report.issues if i.name == "weak_cipher"]
        evidence = "\n".join(issue.evidence for issue in weak)
        for suite in ("RC4-SHA", "DES-CBC3-SHA", "EXP-RC4-MD5"):
            self.assertIn(suite, evidence, f"{suite} must be named in a weak_cipher issue")

    def test_add_remove_semantics(self):
        report = self.reports["add_remove.cnf"]
        self.assertIn("RC4-SHA", report.enabled_ciphers)
        self.assertFalse(
            any(name.startswith("ADH-") for name in report.enabled_ciphers),
            "!aNULL must keep anonymous suites out of the enabled set",
        )

    def test_no_forward_secrecy_lists_responsible_suites(self):
        report = self.reports["no_pfs.cnf"]
        pfs = [i for i in report.issues if i.name == "no_forward_secrecy"]
        self.assertEqual(len(pfs), 1, "expected exactly one forward-secrecy issue")
        for suite in ("AES128-SHA", "AES256-SHA", "AES128-SHA256"):
            self.assertIn(suite, pfs[0].evidence)

    def test_seclevel_zero_is_parsed(self):
        report = self.reports["seclevel0.cnf"]
        self.assertEqual(report.seclevel, 0)

    def test_modern_config_has_aead(self):
        report = self.reports["modern.cnf"]
        self.assertTrue(report.aead_available)
        self.assertTrue(
            any(
                "GCM" in name or "CHACHA20" in name
                for name in report.enabled_ciphers
            ),
            "at least one enabled suite must be GCM or CHACHA20",
        )


class CipherStringSemanticsTest(unittest.TestCase):
    def test_default_baseline_excludes_weak_suites(self):
        enabled, seclevel = expand_cipherstring("DEFAULT")
        self.assertIsNone(seclevel)
        self.assertIn("ECDHE-RSA-AES128-GCM-SHA256", enabled)
        for weak in ("RC4-SHA", "DES-CBC3-SHA", "EXP-RC4-MD5", "NULL-SHA"):
            self.assertNotIn(weak, enabled)

    def test_minus_removes_and_later_add_restores(self):
        enabled, _ = expand_cipherstring("DEFAULT:-AES128-SHA")
        self.assertNotIn("AES128-SHA", enabled)
        enabled, _ = expand_cipherstring("DEFAULT:-AES128-SHA:+AES128-SHA")
        self.assertIn("AES128-SHA", enabled)

    def test_bang_kills_permanently(self):
        enabled, _ = expand_cipherstring("DEFAULT:!RC4:+RC4-SHA")
        self.assertNotIn("RC4-SHA", enabled)

    def test_comma_and_colon_separators_are_equivalent(self):
        colon, _ = expand_cipherstring("ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA")
        comma, _ = expand_cipherstring("ECDHE-RSA-AES128-GCM-SHA256,AES128-SHA")
        self.assertEqual(colon, comma)

    def test_seclevel_and_strength_directives(self):
        enabled, seclevel = expand_cipherstring(
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=2:@STRENGTH"
        )
        self.assertEqual(seclevel, 2)
        self.assertEqual(enabled[0], "ECDHE-RSA-AES256-GCM-SHA384")

    def test_seclevel_defaults_to_none(self):
        report = audit_text(MODERN_CFG)
        self.assertIsNone(report.seclevel)


if __name__ == "__main__":
    unittest.main()

