import unittest
from datetime import datetime, timedelta

from browser_monitor import version_at_least, version_decreased
from software_monitor import is_approved, assess_software
from time_integrity_monitor import evaluate_time_change
from port_monitor import _port_from_address, _purpose
from detector import is_administrator_password_event, _rule_for_log
from packet_monitor import classify_packet_rate, summarize_connections
from hardware_monitor import _driver_changes, _missing_driver_changes


class EndpointRuleTests(unittest.TestCase):
    def test_time_change_thresholds(self):
        now = datetime.now()
        self.assertEqual(evaluate_time_change(now, now - timedelta(seconds=20))["event_type"], "SYSTEM_CLOCK_BACKDATED")
        self.assertEqual(evaluate_time_change(now, now - timedelta(seconds=20))["severity"], "MEDIUM")
        self.assertEqual(evaluate_time_change(now, now - timedelta(seconds=60))["severity"], "HIGH")
        self.assertEqual(evaluate_time_change(now, now - timedelta(minutes=5))["event_type"], "SYSTEM_CLOCK_BACKDATED")
        self.assertEqual(evaluate_time_change(now, now - timedelta(minutes=5))["severity"], "CRITICAL")
        self.assertEqual(evaluate_time_change(now, now + timedelta(minutes=1))["event_type"], "SYSTEM_TIME_CHANGED")

    def test_software_allowlist(self):
        item = {"name":"Google Chrome", "publisher":"Google", "version":"1"}
        self.assertTrue(is_approved(item, {"approved_software":[{"name":"Google Chrome","publisher":"Google","allowed_versions":[]}]}))
        self.assertFalse(is_approved(item, {"approved_software":[]}))

    def test_empty_allowlist_baselines_then_only_flags_new_software(self):
        item = {"name":"Google Chrome", "publisher":"Google", "version":"1"}
        empty = {"approved_software": []}
        self.assertEqual(assess_software(item, empty, False, False), "BASELINED")
        self.assertEqual(assess_software(item, empty, True, True), "KNOWN")
        self.assertEqual(assess_software(item, empty, True, False), "NEW_SINCE_BASELINE")

    def test_browser_status_never_assumes_unknown_is_outdated(self):
        self.assertEqual(version_at_least("1.2", ""), "UNKNOWN")
        self.assertEqual(version_at_least("1.2", "1.3"), "OUTDATED")
        self.assertEqual(version_at_least("1.3", "1.3"), "CURRENT")
        self.assertTrue(version_decreased("130.2", "120.0"))
        self.assertFalse(version_decreased("120.0", "130.2"))

    def test_port_inventory_explains_known_and_unknown_listeners(self):
        self.assertEqual(_port_from_address("[::]:443"), 443)
        self.assertIn("HTTPS web service", _purpose(443, "web.exe", "9"))
        self.assertIn("cannot determine", _purpose(9999, "app.exe", "10"))

    def test_administrator_password_change_is_critical(self):
        event = {"event_id": 4724, "event_type": "Password Reset", "username": "SYSTEM", "message": "Target Account Name: Administrator", "raw_event": ""}
        self.assertTrue(is_administrator_password_event(event))
        self.assertEqual(_rule_for_log(event), ("ADMINISTRATOR_PASSWORD_CHANGED", "CRITICAL"))
        non_admin = dict(event, message="Target Account Name: regular-user")
        self.assertFalse(is_administrator_password_event(non_admin))
        self.assertEqual(_rule_for_log(non_admin), ("Password Reset", "HIGH"))

    def test_packet_rate_thresholds(self):
        self.assertEqual(classify_packet_rate(10), "PASS")
        self.assertEqual(classify_packet_rate(1000), "HIGH")
        self.assertEqual(classify_packet_rate(10000), "CRITICAL")
        summary = summarize_connections([{"ProcessName":"browser", "PID":1, "RemoteAddress":"8.8.8.8", "RemotePort":443}])
        self.assertIn("browser", summary)
        self.assertIn("8.8.8.8:443", summary)

    def test_hardware_change_only_after_baseline_and_unsigned_is_high(self):
        old = {"driver_version": "1", "driver_date": "2026-01-01", "is_signed": "True"}
        same = dict(old)
        self.assertEqual(_driver_changes(old, same), [])
        changed = dict(old, driver_version="2", is_signed="False")
        changes = _driver_changes(old, changed)
        self.assertEqual({item["severity"] for item in changes}, {"MEDIUM", "HIGH"})

    def test_missing_driver_is_detected_once_after_a_baseline(self):
        previous = [{"device_id":"A", "device_name":"USB driver", "driver_version":"1", "missing_count":0}]
        changes = _missing_driver_changes(previous, set(), "2026-09-28 12:00:00")
        self.assertEqual(changes[0]["change_type"], "DRIVER_OR_DEVICE_REMOVED")
        self.assertEqual(changes[0]["severity"], "CRITICAL")
        self.assertEqual(_missing_driver_changes([{**previous[0], "missing_count":1}], set(), "now"), [])

if __name__ == "__main__": unittest.main()
