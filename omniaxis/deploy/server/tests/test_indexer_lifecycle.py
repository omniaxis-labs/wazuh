"""Unit tests for the indexer retention and snapshot bodies (no network).

    python3 -B -m unittest discover -s omniaxis/deploy/server/tests -p 'test_*.py'
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import indexer_lifecycle as lc  # noqa: E402


class Settings(unittest.TestCase):
    def test_defaults(self):
        s = lc.settings({})
        self.assertEqual(s.alert_days, 90)
        self.assertEqual(s.other_days, 30)
        self.assertEqual(s.snapshots_kept, 14)

    def test_reads_config_values(self):
        s = lc.settings(
            {"ALERT_INDEX_DAYS": "120", "OTHER_INDEX_DAYS": "7", "SNAPSHOTS_KEPT": "30"}
        )
        self.assertEqual((s.alert_days, s.other_days, s.snapshots_kept), (120, 7, 30))

    def test_refuses_nonsense(self):
        for env in (
            {"ALERT_INDEX_DAYS": "0"},
            {"ALERT_INDEX_DAYS": "ninety"},
            {"OTHER_INDEX_DAYS": "-1"},
            {"SNAPSHOTS_KEPT": "0"},
            {"ALERT_INDEX_DAYS": "5000"},
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                lc.settings(env)


class Bodies(unittest.TestCase):
    def setUp(self):
        self.s = lc.settings({})

    def test_alert_indices_are_deleted_after_the_alert_period(self):
        p = lc.ism_policies(self.s)["omniaxis-alerts"]["policy"]
        self.assertEqual(
            p["ism_template"], [{"index_patterns": ["wazuh-alerts-*"], "priority": 100}]
        )
        hot, delete = p["states"]
        self.assertEqual(hot["transitions"][0]["conditions"], {"min_index_age": "90d"})
        self.assertEqual(hot["transitions"][0]["state_name"], "delete")
        self.assertEqual(delete["actions"], [{"delete": {}}])

    def test_other_wazuh_indices_follow_the_shorter_period(self):
        p = lc.ism_policies(self.s)["omniaxis-other"]["policy"]
        self.assertEqual(
            p["ism_template"][0]["index_patterns"],
            ["wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"],
        )
        self.assertEqual(
            p["states"][0]["transitions"][0]["conditions"], {"min_index_age": "30d"}
        )

    def test_no_index_is_covered_twice(self):
        pats = [
            x
            for body in lc.ism_policies(self.s).values()
            for t in body["policy"]["ism_template"]
            for x in t["index_patterns"]
        ]
        self.assertEqual(len(pats), len(set(pats)))

    def test_snapshots_daily_of_wazuh_indices_only_keeping_the_set_number(self):
        b = lc.sm_policy(self.s)
        self.assertEqual(b["snapshot_config"]["repository"], lc.REPOSITORY)
        self.assertEqual(b["snapshot_config"]["indices"], "wazuh-*")
        self.assertFalse(b["snapshot_config"]["include_global_state"])
        self.assertEqual(b["creation"]["schedule"]["cron"]["timezone"], "UTC")
        self.assertEqual(b["deletion"]["condition"]["max_count"], 14)
        self.assertGreaterEqual(b["deletion"]["condition"]["min_count"], 1)

    def test_the_repository_lives_under_path_repo(self):
        r = lc.repository_body()
        self.assertEqual(r["type"], "fs")
        self.assertEqual(r["settings"]["location"], lc.SNAPSHOT_DIR)
        self.assertTrue(r["settings"]["compress"])


if __name__ == "__main__":
    unittest.main()
