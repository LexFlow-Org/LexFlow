#!/usr/bin/env python3
"""Regression checks for OSV interval boundaries; no advisory network service."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("audit", Path(__file__).with_name("audit-npm-offline.py"))
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
SEMVER = Path(__file__).resolve().parent.parent / "client/node_modules/semver"


class IntervalTests(unittest.TestCase):
    def matches(self, versions, events, **kwargs):
        packages = [{"name": "example", "version": v, "path": f"node_modules/example-{i}"} for i, v in enumerate(versions)]
        advisory = {"id": "fixture", "affected": [{"package": {"name": "example", "ecosystem": "npm"},
                     "ranges": [{"type": "SEMVER", "events": events}]}], **kwargs}
        return AUDIT.run_matcher(packages, [advisory], SEMVER)

    def test_disjoint_release_branches_do_not_flag_patched_versions(self):
        result = self.matches(["1.2.0", "1.2.5", "1.9.0", "2.0.0", "2.0.2"],
                              [{"introduced": "1.2.0"}, {"fixed": "1.2.5"}, {"introduced": "2.0.0"}, {"fixed": "2.0.2"}])
        self.assertEqual([f["version"] for f in result["findings"]], ["1.2.0", "2.0.0"])

    def test_last_affected_inclusive_and_limit_exclusive(self):
        self.assertEqual(len(self.matches(["1.0.0"], [{"introduced": "0"}, {"last_affected": "1.0.0"}])["findings"]), 1)
        self.assertEqual(len(self.matches(["1.0.0"], [{"introduced": "0"}, {"limit": "1.0.0"}])["findings"]), 0)

    def test_prereleases_and_open_interval_use_semver_comparison(self):
        result = self.matches(["0.0.0-beta.1", "2.0.0-beta.1", "2.0.0", "3.0.0"], [{"introduced": "0"}, {"fixed": "2.0.0"}])
        self.assertEqual([f["version"] for f in result["findings"]], ["0.0.0-beta.1", "2.0.0-beta.1"])
        self.assertEqual(len(self.matches(["3.0.0+build.1"], [{"introduced": "2.0.0"}])["findings"]), 1)

    def test_withdrawn_advisories_are_excluded(self):
        self.assertEqual(self.matches(["1.0.0"], [{"introduced": "0"}], withdrawn="2026-01-01T00:00:00Z")["findings"], [])

    def test_unknown_boundaries_are_reported_not_silently_safe(self):
        self.assertEqual(len(self.matches(["1.0.0"], [{"introduced": "not-semver"}])["unsupported"]), 1)


if __name__ == "__main__":
    unittest.main()
