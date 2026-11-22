import tempfile
import time
import unittest
from pathlib import Path

from pwnman.pwnman import metrics_store as ms
from pwnman.pwnman import plugin_catalog as pc
from pwnman.pwnman.chart import fmt_time, split_segments
from pwnman.pwnman.fleet import DeviceStatus


_APP = None


def st(name="d", **kw):
    kw.setdefault("online", True)
    return DeviceStatus(name=name, host="h", **kw)


class MetricsStoreTest(unittest.TestCase):
    def setUp(self):
        self.s = ms.MetricsStore(Path(tempfile.mkdtemp()) / "m.db", min_interval=20)

    def test_record_query_roundtrip(self):
        t = 1_000_000.0
        self.assertTrue(self.s.record(st(cpu_temp=45.5, mem_used_mb=300, mem_total_mb=1000,
                                         handshakes=3, ai_epoch=7, battery=80.0, load="0.52 0.4 0.3"), ts=t))
        (row,) = self.s.query("d", t - 1, t + 1)
        self.assertEqual((row.cpu_temp, row.mem_pct, row.handshakes, row.epoch, row.battery, row.load1),
                         (45.5, 30.0, 3, 7, 80.0, 0.52))
        self.assertTrue(row.online)

    def test_throttle_per_device(self):
        t = 1_000_000.0
        self.assertTrue(self.s.record(st("a"), ts=t))
        self.assertFalse(self.s.record(st("a"), ts=t + 5))        # same device, too soon
        self.assertTrue(self.s.record(st("b"), ts=t + 5))         # other device unaffected
        self.assertTrue(self.s.record(st("a"), ts=t + 21))
        self.assertEqual(self.s.devices(), ["a", "b"])
        self.assertEqual(self.s.count(), 3)

    def test_prune_and_clear(self):
        now = 10_000_000.0
        self.s.record(st(), ts=now - 40 * 86400)
        self.s.record(st(), ts=now - 100)
        self.assertEqual(self.s.prune(now), 1)
        self.assertEqual(self.s.count(), 1)
        self.assertEqual(self.s.clear("d"), 1)
        self.assertEqual(self.s.count(), 0)

    def test_offline_samples_excluded_from_series_but_count_for_availability(self):
        t = 1_000_000.0
        for i, on in enumerate([True, False, True, True]):
            self.s.record(st(online=on, cpu_temp=40 + i), ts=t + i * 60)
        rows = self.s.query("d", 0)
        self.assertEqual([v for _t, v in ms.series(rows, "cpu_temp")], [40.0, 42.0, 43.0])
        self.assertEqual(ms.availability(rows), 75.0)
        self.assertIsNone(ms.availability([]))

    def test_handshake_gain_ignores_resets(self):
        rows = [ms.Sample(i, "d", True, handshakes=h) for i, h in enumerate([3, 5, 9, 2, 4])]
        self.assertEqual(ms.handshake_gain(rows), 2 + 4 + 2 + 2)   # reset to 2 counts as +2

    def test_csv_export(self):
        t = time.time()
        self.s.record(st(cpu_temp=50.0), ts=t)
        out = Path(tempfile.mkdtemp()) / "x.csv"
        self.assertEqual(self.s.export_csv(str(out), "d"), 1)
        lines = out.read_text().splitlines()
        self.assertTrue(lines[0].startswith("time,device,online,cpu_temp"))
        self.assertIn(",d,1,50.0", lines[1])

    def test_downsample_and_stats(self):
        pts = [(float(i), float(i % 10)) for i in range(1000)]
        d = ms.downsample(pts, 100)
        self.assertEqual(len(d), 100)
        self.assertEqual((d[0][0], d[-1][0]), (0.0, 999.0))
        self.assertEqual(ms.downsample(pts[:5], 100), pts[:5])
        s = ms.stats([(0, 1.0), (1, 3.0)])
        self.assertEqual((s["min"], s["max"], s["avg"], s["last"]), (1.0, 3.0, 2.0, 3.0))
        self.assertIsNone(ms.stats([]))

    def test_nice_ticks(self):
        t = ms.nice_ticks(0, 100, 5)
        self.assertEqual((t[0], t[-1]), (0, 100))
        self.assertTrue(all(b > a for a, b in zip(t, t[1:], strict=False)))
        self.assertGreaterEqual(len(ms.nice_ticks(5, 5)), 2)       # degenerate range
        t = ms.nice_ticks(41.3, 47.9, 4)
        self.assertLessEqual(t[0], 41.3)
        self.assertGreaterEqual(t[-1], 47.9)


class ChartHelpersTest(unittest.TestCase):
    def test_gaps_split_lines(self):
        pts = [(0, 1), (60, 1), (120, 1), (10_000, 2), (10_060, 2)]
        segs = split_segments(pts)
        self.assertEqual([len(s) for s in segs], [3, 2])
        self.assertEqual(split_segments([]), [])
        self.assertEqual(len(split_segments([(1, 1)])), 1)

    def test_fresh_chart_paints_without_data(self):
        # Regression: t0 == t1 == 0 raised ZeroDivisionError inside paintEvent,
        # which Qt turns into abort().
        global _APP
        from PyQt6 import QtWidgets
        _APP = QtWidgets.QApplication.instance() or QtWidgets.QApplication(["t"])  # keep a reference
        from pwnman.pwnman.chart import LineChart
        c = LineChart("x")
        c.resize(300, 150)
        self.assertFalse(c.grab().toImage().isNull())

    def test_time_labels(self):
        self.assertRegex(fmt_time(time.time(), 3600), r"^\d\d:\d\d$")
        self.assertRegex(fmt_time(time.time(), 7 * 86400), r"^\d\d-\d\d \d\d:\d\d$")


class PluginCatalogTest(unittest.TestCase):
    def test_merge_sources(self):
        rows = pc.merge_catalog(
            {"grid", "gps"}, {"grid": True, "ghost": False},
            [{"name": "grid", "version": "1.0.1", "status": "enabled"},
             {"name": "gps", "version": "1.0.0", "status": "installed, update 1.1.0 available"},
             {"name": "memtemp", "version": "2.0", "status": "available"}])
        by = {r.name: r for r in rows}
        self.assertEqual([r.name for r in rows], sorted(by, key=str.lower))
        self.assertTrue(by["grid"].installed and by["grid"].enabled and by["grid"].in_config)
        self.assertTrue(by["gps"].update_available)
        self.assertEqual(by["gps"].latest, "1.1.0")
        self.assertFalse(by["memtemp"].installed)                    # "available" = in the catalog only
        self.assertTrue(by["ghost"].in_config and not by["ghost"].installed)

    def test_status_interpretation(self):
        self.assertEqual(pc.interpret_status("enabled")[0], True)
        self.assertEqual(pc.interpret_status("not installed")[0], False)
        self.assertEqual(pc.interpret_status("upgradable (2.1)")[1:], (True, "2.1"))
        self.assertEqual(pc.interpret_status("")[:2], (False, False))

    def test_filters_and_summary(self):
        a = pc.PluginRow("alpha", installed=True, enabled=True)
        b = pc.PluginRow("beta", installed=True, update_available=True, status="update 2.0")
        c = pc.PluginRow("gamma")
        rows = [a, b, c]
        sel = lambda text="", which="All": [r.name for r in rows if pc.matches(r, text, which)]  # noqa: E731
        self.assertEqual(sel(), ["alpha", "beta", "gamma"])
        self.assertEqual(sel(which="Enabled"), ["alpha"])
        self.assertEqual(sel(which="Updates available"), ["beta"])
        self.assertEqual(sel(which="Not installed"), ["gamma"])
        self.assertEqual(sel("ALP"), ["alpha"])
        self.assertEqual(sel("update"), ["beta"])                    # searches status text too
        self.assertIn("3 plugin(s): 2 installed, 1 enabled, 1 update(s)", pc.summary(rows))


class ThemeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt6 import QtWidgets
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(["t"])

    def setUp(self):
        import os
        os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp()
        from PyQt6 import QtCore
        QtCore.QSettings("qPwnagotchi", "qPwnagotchi").clear()

    def lightness(self):
        from PyQt6 import QtGui
        return self.app.palette().color(QtGui.QPalette.ColorRole.Window).lightness()

    def test_dark_and_light_apply(self):
        from pwnman.pwnman import theme
        self.assertTrue(theme.apply(self.app, "dark"))
        self.assertLess(self.lightness(), 80)
        self.assertFalse(theme.apply(self.app, "light"))
        self.assertGreater(self.lightness(), 200)

    def test_system_follows_os_and_restores_original(self):
        from unittest import mock

        from pwnman.pwnman import theme
        with mock.patch.object(theme, "system_is_dark", return_value=True):
            self.assertTrue(theme.apply(self.app, "system"))
            self.assertLess(self.lightness(), 80)
        with mock.patch.object(theme, "system_is_dark", return_value=False):
            self.assertFalse(theme.apply(self.app, "system"))

    def test_mode_persistence_and_validation(self):
        from pwnman.pwnman import theme
        self.assertEqual(theme.get_mode(), "system")
        theme.apply(self.app, "dark", persist=True)
        self.assertEqual(theme.get_mode(), "dark")
        theme.apply(self.app, "bogus")                               # falls back, no crash
        theme.apply(self.app, "light", persist=True)
        theme.apply(self.app, "light")

    def test_contrast_of_text_on_base(self):
        from PyQt6 import QtGui

        from pwnman.pwnman import theme
        R = QtGui.QPalette.ColorRole
        for pal in (theme.dark_palette(), theme.light_palette()):
            fg, bg = pal.color(R.Text).lightness(), pal.color(R.Base).lightness()
            self.assertGreater(abs(fg - bg), 150)                     # readable
            for role in (R.WindowText, R.ButtonText):
                self.assertGreater(abs(pal.color(role).lightness() - pal.color(R.Window if role == R.WindowText else R.Button).lightness()), 120)

    def test_status_and_series_colors_follow_theme(self):
        from PyQt6 import QtWidgets

        from pwnman.pwnman import theme
        w = QtWidgets.QWidget()
        theme.apply(self.app, "dark")
        dark_ok, dark_s = theme.status_color("ok", w), theme.series_color(0, w)
        theme.apply(self.app, "light")
        light_ok, light_s = theme.status_color("ok", w), theme.series_color(0, w)
        self.assertGreater(dark_ok.lightness(), light_ok.lightness())
        self.assertGreater(dark_s.lightness(), light_s.lightness())

    def test_chart_renders_in_both_themes(self):
        from PyQt6 import QtGui

        from pwnman.pwnman import theme
        from pwnman.pwnman.chart import LineChart
        now = time.time()
        pts = [(now - 3600 + i * 60, 40 + (i % 7)) for i in range(60)]
        shots = {}
        for mode in ("dark", "light"):
            theme.apply(self.app, mode)
            c = LineChart("CPU", "°C")
            c.resize(400, 200)
            c.set_data(pts, now - 3600, now, "now 40")
            img = c.grab().toImage()
            self.assertFalse(img.isNull())
            shots[mode] = img.pixelColor(5, 5).lightness()     # plot background
            empty = LineChart("x")
            empty.resize(300, 150)
            empty.set_data([], now - 10, now)
            empty.grab()                                       # "no data" path must not raise
        self.assertLess(shots["dark"], 80)
        self.assertGreater(shots["light"], 200)
        theme.apply(self.app, "light")
        QtGui.QGuiApplication.processEvents()


if __name__ == "__main__":
    unittest.main()
