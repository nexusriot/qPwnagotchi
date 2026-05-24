import unittest

from pwnman.pwnman.fleet import parse_probe, _fmt_uptime, _first_float


class FmtUptimeTest(unittest.TestCase):
    def test_minutes(self):
        self.assertEqual(_fmt_uptime(300), "5m")

    def test_hours(self):
        self.assertEqual(_fmt_uptime(3 * 3600 + 120), "3h 2m")

    def test_days(self):
        self.assertEqual(_fmt_uptime(86400 + 3600 + 60), "1d 1h 1m")


class FirstFloatTest(unittest.TestCase):
    def test_extracts(self):
        self.assertEqual(_first_float("temp=46.2'C"), 46.2)
        self.assertEqual(_first_float("58123"), 58123.0)
        self.assertIsNone(_first_float("no numbers here"))


class ParseProbeTest(unittest.TestCase):
    def test_full_vcgencmd(self):
        raw = (
            "<<<HOST\npwny\n"
            "<<<UPTIME\n123456.78 9999.0\n"
            "<<<TEMP\ntemp=46.2'C\n46234\n"
            "<<<MEM\n312 924\n"
            "<<<HS\n7\n"
            "<<<SVC\nactive\n"
            "<<<END\n"
        )
        out = parse_probe(raw)
        self.assertEqual(out["hostname"], "pwny")
        self.assertEqual(out["uptime"], "1d 10h 17m")
        self.assertAlmostEqual(out["cpu_temp"], 46.2)
        self.assertEqual(out["mem_used_mb"], 312)
        self.assertEqual(out["mem_total_mb"], 924)
        self.assertEqual(out["handshakes"], 7)
        self.assertEqual(out["service_active"], "active")

    def test_thermal_zone_millidegrees(self):
        raw = "<<<HOST\nb\n<<<TEMP\n58123\n<<<SVC\nfailed\n<<<END\n"
        out = parse_probe(raw)
        self.assertAlmostEqual(out["cpu_temp"], 58.123)
        self.assertEqual(out["service_active"], "failed")

    def test_missing_fields_omitted(self):
        out = parse_probe("<<<HOST\nx\n<<<UPTIME\n<<<MEM\n<<<HS\n0\n<<<SVC\n<<<END\n")
        self.assertEqual(out["hostname"], "x")
        self.assertNotIn("uptime", out)
        self.assertNotIn("cpu_temp", out)
        self.assertNotIn("mem_used_mb", out)
        self.assertEqual(out["handshakes"], 0)
        self.assertEqual(out["service_active"], "unknown")

    def test_garbage_is_safe(self):
        out = parse_probe("totally unrelated output\nno markers\n")
        self.assertEqual(out["hostname"], "")
        self.assertEqual(out["service_active"], "unknown")


if __name__ == "__main__":
    unittest.main()
