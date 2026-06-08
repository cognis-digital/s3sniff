"""Smoke tests for S3SNIFF. No network access."""
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from s3sniff import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Severity,
    analyze_acl,
    analyze_policy,
    analyze_listing,
    analyze_document,
    summarize,
)
from s3sniff.cli import main  # noqa: E402

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "buckets.json",
)


class TestMeta(unittest.TestCase):
    def test_name_version(self):
        self.assertEqual(TOOL_NAME, "s3sniff")
        self.assertTrue(TOOL_VERSION)


class TestAcl(unittest.TestCase):
    def test_public_read(self):
        acl = {"Grants": [
            {"Grantee": {"URI": _ALL_USERS}, "Permission": "READ"}
        ]}
        f = analyze_acl("b", acl)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule_id, "ACL_PUBLIC_READ")
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_public_write_is_critical(self):
        acl = {"Grants": [
            {"Grantee": {"URI": _ALL_USERS}, "Permission": "WRITE"}
        ]}
        f = analyze_acl("b", acl)
        self.assertEqual(f[0].rule_id, "ACL_PUBLIC_WRITE")
        self.assertEqual(f[0].severity, Severity.CRITICAL)

    def test_auth_users_grant(self):
        acl = {"Grants": [
            {"Grantee": {"URI": _AUTH_USERS}, "Permission": "READ"}
        ]}
        f = analyze_acl("b", acl)
        self.assertEqual(f[0].rule_id, "ACL_AUTHUSERS_GRANT")

    def test_private_acl_clean(self):
        acl = {"Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": "owner"},
             "Permission": "FULL_CONTROL"}
        ]}
        self.assertEqual(analyze_acl("b", acl), [])


class TestPolicy(unittest.TestCase):
    def test_public_write(self):
        pol = {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject"}
        ]}
        f = analyze_policy("b", pol)
        self.assertEqual(f[0].rule_id, "POLICY_PUBLIC_WRITE")
        self.assertEqual(f[0].severity, Severity.CRITICAL)

    def test_public_wildcard_action(self):
        pol = {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*"}
        ]}
        f = analyze_policy("b", pol)
        self.assertEqual(f[0].rule_id, "POLICY_PUBLIC_WILDCARD_ACTION")
        self.assertEqual(f[0].severity, Severity.CRITICAL)

    def test_public_read_high(self):
        pol = {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        ]}
        f = analyze_policy("b", pol)
        self.assertEqual(f[0].rule_id, "POLICY_PUBLIC_READ")
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_conditioned_read_lower(self):
        pol = {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
             "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}
        ]}
        f = analyze_policy("b", pol)
        self.assertEqual(f[0].severity, Severity.MEDIUM)

    def test_deny_ignored(self):
        pol = {"Statement": [
            {"Effect": "Deny", "Principal": "*", "Action": "s3:*"}
        ]}
        self.assertEqual(analyze_policy("b", pol), [])

    def test_scoped_principal_clean(self):
        pol = {"Statement": [
            {"Effect": "Allow",
             "Principal": {"AWS": "arn:aws:iam::111:root"},
             "Action": "s3:GetObject"}
        ]}
        self.assertEqual(analyze_policy("b", pol), [])


class TestListing(unittest.TestCase):
    def test_public_listing_and_sensitive(self):
        listing = {"public": True, "objects": [
            {"key": "db-backup.sql"}, {"key": "ok.png"}
        ]}
        f = analyze_listing("b", listing)
        ids = {x.rule_id for x in f}
        self.assertIn("LISTING_PUBLIC_ENUMERABLE", ids)
        self.assertIn("LISTING_SENSITIVE_OBJECT", ids)

    def test_private_listing_clean(self):
        self.assertEqual(
            analyze_listing("b", {"public": False, "objects": []}), []
        )


class TestSummaryAndDispatch(unittest.TestCase):
    def test_summarize(self):
        findings = analyze_document({
            "bucket": "b",
            "acl": {"Grants": [
                {"Grantee": {"URI": _ALL_USERS}, "Permission": "WRITE"}
            ]},
        })
        s = summarize(findings)
        self.assertEqual(s["highest_severity"], Severity.CRITICAL)
        self.assertEqual(s["total"], 1)

    def test_empty_summary(self):
        s = summarize([])
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["highest_severity"], Severity.INFO)


class TestCli(unittest.TestCase):
    def test_scan_demo_exit_findings(self):
        rc = main(["scan", _DEMO, "--format", "json"])
        self.assertEqual(rc, 2)

    def test_no_command_errors(self):
        rc = main([])
        self.assertEqual(rc, 1)

    def test_missing_file(self):
        rc = main(["scan", "does-not-exist-xyz.json"])
        self.assertEqual(rc, 1)

    def test_subprocess_json_well_formed(self):
        proc = subprocess.run(
            [sys.executable, "-m", "s3sniff", "scan", _DEMO,
             "--format", "json"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["tool"], "s3sniff")
        self.assertGreater(payload["summary"]["total"], 0)
        rule_ids = {f["rule_id"] for f in payload["findings"]}
        self.assertIn("POLICY_PUBLIC_WRITE", rule_ids)
        self.assertIn("LISTING_SENSITIVE_OBJECT", rule_ids)

    def test_clean_input_exit_zero(self):
        import tempfile
        clean = {"bucket": "safe", "acl": {"Grants": []},
                 "listing": {"public": False, "objects": []}}
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as fh:
            json.dump(clean, fh)
            path = fh.name
        try:
            self.assertEqual(main(["scan", path]), 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
