import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import paramiko

from pwnman.pwnman import alerts, config_tools, discovery, fleet, logs_model
from pwnman.pwnman.known_hosts import HostKeyError, KnownHosts, StrictPolicy, fingerprint
from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman.plugins_toml import extract_enabled_from_toml, set_plugin_enabled_in_toml
from pwnman.pwnman.profile_store import ProfileStore


class KnownHostsTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.kh = KnownHosts(Path(self.d) / "kh")
        self.key = paramiko.ECDSAKey.generate()
        self.key2 = paramiko.ECDSAKey.generate()

    def test_trust_and_lookup(self):
        self.assertEqual(self.kh.known_fingerprint("h", 22), "")
        self.kh.trust("h", 22, self.key)
        self.assertEqual(self.kh.known_fingerprint("h", 22), fingerprint(self.key))
        self.assertTrue(fingerprint(self.key).startswith("SHA256:"))

    def test_nonstandard_port_is_separate(self):
        self.kh.trust("h", 2222, self.key)
        self.assertEqual(self.kh.known_fingerprint("h", 22), "")
        self.assertEqual(self.kh.known_fingerprint("h", 2222), fingerprint(self.key))

    def test_replace(self):
        self.kh.trust("h", 22, self.key)
        self.kh.trust("h", 22, self.key2, replace=True)
        self.assertEqual(self.kh.known_fingerprint("h", 22), fingerprint(self.key2))

    def test_file_is_private(self):
        self.kh.trust("h", 22, self.key)
        if os.name == "posix":
            self.assertEqual(oct(self.kh.path.stat().st_mode & 0o777), "0o600")

    def test_strict_policy_rejects_unknown(self):
        with self.assertRaises(HostKeyError) as cm:
            StrictPolicy().missing_host_key(None, "h", self.key)
        self.assertEqual((cm.exception.kind, cm.exception.host, cm.exception.port), ("unknown", "h", 22))
        with self.assertRaises(HostKeyError) as cm:
            StrictPolicy().missing_host_key(None, "[h]:2222", self.key)
        self.assertEqual((cm.exception.host, cm.exception.port), ("h", 2222))


class FakeSecrets:
    def __init__(self):
        self.d = {}

    def get(self, k):
        return self.d.get(k, "")

    def set(self, k, v):
        if v:
            self.d[k] = v
        else:
            self.d.pop(k, None)
        return True

    def delete(self, k):
        self.d.pop(k, None)


class ProfileSecretsTest(unittest.TestCase):
    def test_passwords_leave_the_json_file(self):
        d = Path(tempfile.mkdtemp())
        sec = FakeSecrets()
        st = ProfileStore(d / "p.json", secrets=sec)
        st.upsert(ConnectionProfile(name="a", host="h", password="pw1", lcd_pass="lp"))
        st.save()
        raw = (d / "p.json").read_text()
        self.assertNotIn("pw1", raw)
        self.assertNotIn('"lp"', raw)
        st2 = ProfileStore(d / "p.json", secrets=sec)
        self.assertEqual(st2.get("a").password, "pw1")
        self.assertEqual(st2.get("a").lcd_pass, "lp")

    def test_legacy_plaintext_is_migrated_on_save(self):
        d = Path(tempfile.mkdtemp())
        ProfileStore(d / "p.json").upsert(ConnectionProfile(name="a", password="old"))
        st = ProfileStore(d / "p.json")
        st.upsert(ConnectionProfile(name="a", password="old"))
        st.save()
        sec = FakeSecrets()
        st = ProfileStore(d / "p.json", secrets=sec)
        self.assertEqual(st.get("a").password, "old")
        st.save()
        self.assertNotIn("old", (d / "p.json").read_text())
        self.assertEqual(sec.get("a:ssh"), "old")

    def test_delete_removes_secret(self):
        d = Path(tempfile.mkdtemp())
        sec = FakeSecrets()
        st = ProfileStore(d / "p.json", secrets=sec)
        st.upsert(ConnectionProfile(name="a", password="pw"))
        st.save()
        st.delete("a")
        self.assertEqual(sec.get("a:ssh"), "")

    def test_auto_connect_roundtrips(self):
        d = Path(tempfile.mkdtemp())
        st = ProfileStore(d / "p.json")
        st.upsert(ConnectionProfile(name="a", auto_connect=True))
        st.save()
        self.assertTrue(ProfileStore(d / "p.json").get("a").auto_connect)


class SessionBackoffTest(unittest.TestCase):
    def test_backoff(self):
        from pwnman.pwnman.session import backoff_delay
        self.assertEqual([backoff_delay(i) for i in (1, 2, 3, 4)], [2, 4, 8, 16])
        self.assertEqual(backoff_delay(20), 60)


class AlertsTest(unittest.TestCase):
    def st(self, **kw):
        return fleet.DeviceStatus(name="d", host="h", **kw)

    def test_offline_needs_consecutive_misses_and_prior_online(self):
        e = alerts.AlertEngine(offline_after=2)
        self.assertEqual(e.update(self.st(online=False)), [])      # first sight: silent
        e = alerts.AlertEngine(offline_after=2)
        e.update(self.st(online=True))
        self.assertEqual(e.update(self.st(online=False)), [])      # one miss: debounce
        a = e.update(self.st(online=False))
        self.assertEqual([x.kind for x in a], ["offline"])
        self.assertEqual(e.update(self.st(online=False)), [])      # no repeat
        self.assertEqual([x.kind for x in e.update(self.st(online=True))], ["online"])

    def test_handshake_increase_only(self):
        e = alerts.AlertEngine()
        e.update(self.st(online=True, handshakes=3))
        self.assertEqual(e.update(self.st(online=True, handshakes=3)), [])
        a = e.update(self.st(online=True, handshakes=5))
        self.assertEqual(a[0].kind, "handshake")
        self.assertIn("+2", a[0].text)
        self.assertEqual(e.update(self.st(online=True, handshakes=1)), [])  # wipe: no alert

    def test_service_and_battery(self):
        e = alerts.AlertEngine()
        e.update(self.st(online=True, service_active="active", battery=50))
        self.assertEqual(e.update(self.st(online=True, service_active="failed", battery=50))[0].kind, "service")
        self.assertEqual(e.update(self.st(online=True, service_active="failed", battery=10))[0].kind, "battery")
        self.assertEqual([x for x in e.update(self.st(online=True, service_active="failed", battery=9))
                          if x.kind == "battery"], [])  # once


class DiscoveryTest(unittest.TestCase):
    def test_scan_hosts_uses_probe(self):
        up = {"10.0.0.2", "10.0.0.9"}
        got = discovery.scan_hosts(["10.0.0.1", "10.0.0.2", "10.0.0.9"],
                                   probe=lambda h, p, t: h in up)
        self.assertEqual(sorted(got), ["10.0.0.2", "10.0.0.9"])

    def test_subnet_hosts(self):
        self.assertEqual(len(discovery.subnet_hosts("192.168.1.0/24")), 254)
        self.assertEqual(len(discovery.subnet_hosts("10.0.0.0/8", limit=10)), 10)

    def test_discover_known_hosts(self):
        with mock.patch.object(discovery, "mdns_browse", return_value=[]):
            f = discovery.discover(probe=lambda h, p, t: h == "10.0.0.2")
        self.assertEqual([(x.host, x.source) for x in f], [("10.0.0.2", "known")])


class LogsModelTest(unittest.TestCase):
    def test_levels(self):
        L = logs_model
        self.assertEqual(L.line_level("[12:00] [WARNING] x"), "WARNING")
        self.assertTrue(L.matches("[ERROR] boom", "WARNING"))
        self.assertFalse(L.matches("[INFO] hi", "WARNING"))
        self.assertTrue(L.matches("plain line", "INFO"))
        self.assertFalse(L.matches("plain line", "ERROR"))
        self.assertTrue(L.matches("[INFO] Hello World", "DEBUG", "hello"))
        self.assertFalse(L.matches("[INFO] Hello", "DEBUG", "nope"))

    def test_buffer_bounded(self):
        b = logs_model.LogBuffer(maxlen=3)
        for i in range(10):
            b.add(f"[INFO] {i}")
        self.assertEqual(list(b.lines), ["[INFO] 7", "[INFO] 8", "[INFO] 9"])


class ConfigToolsTest(unittest.TestCase):
    def test_check_toml(self):
        self.assertIsNone(config_tools.check_toml('a = 1\n[t]\nb = "x"\n'))
        p = config_tools.check_toml("a = 1\nthis is bad\n")
        self.assertIsNotNone(p)
        self.assertEqual(p.line, 2)

    def test_diff(self):
        d = config_tools.make_diff("a=1\nb=2\n", "a=1\nb=3\nc=4\n")
        self.assertEqual(config_tools.diff_summary(d), (2, 1))
        self.assertEqual(config_tools.make_diff("x\n", "x\n"), "")

    def test_collision_suffix_is_a_valid_backup(self):
        self.assertTrue(config_tools._is_backup_of(
            "/etc/p/config.toml.bak.20240101-000000-2", "/etc/p/config.toml"))

    def test_backup_path_guard(self):
        b = config_tools.Backup("/etc/p/config.toml.bak.20240101-000000", "20240101-000000")
        self.assertTrue(config_tools._is_backup_of(b.path, "/etc/p/config.toml"))
        for evil in ("/etc/passwd", "/etc/p/config.toml.bak.20240101-000000/../../x",
                     "/etc/p/config.toml.bak.zzz"):
            self.assertFalse(config_tools._is_backup_of(evil, "/etc/p/config.toml"))
        with self.assertRaises(ValueError):
            config_tools.delete_backups(None, "/etc/p/config.toml",
                                        [config_tools.Backup("/etc/passwd", "x")])


class TomlkitPathTest(unittest.TestCase):
    def test_preserves_layout_comments_and_unrelated_values(self):
        t = ('# top\nmain.name = "x"\nmain.plugins.grid.enabled = true   # keep\n'
             'main.plugins.gps.enabled = false\n\n[ui.web]\nenabled = true\n')
        out = set_plugin_enabled_in_toml(t, "grid", False)
        self.assertIn("main.plugins.grid.enabled = false   # keep", out)
        self.assertIn("# top", out)
        self.assertEqual(out.replace("= false   # keep", "= true   # keep"), t)

    def test_inline_table_style_is_handled(self):
        t = 'main.plugins = { grid = { enabled = true } }\n'
        out = set_plugin_enabled_in_toml(t, "grid", False)
        import tomllib
        self.assertIs(tomllib.loads(out)["main"]["plugins"]["grid"]["enabled"], False)

    def test_invalid_toml_falls_back_to_text_edit(self):
        t = "main.plugins.grid.enabled = true\nthis is not toml\n"
        out = set_plugin_enabled_in_toml(t, "grid", False)
        self.assertEqual(extract_enabled_from_toml(out), {"grid": False})
        self.assertIn("this is not toml", out)


class RestSessionTest(unittest.TestCase):
    P = ConnectionProfile(name="d", host="h", lcd_url="http://h:8080/")

    def setUp(self):
        fleet._api_path_cache.clear()

    def test_falls_back_to_second_path_and_caches(self):
        calls = []

        def fake(url, profile, timeout):
            calls.append(url)
            if url.endswith("/api/session"):
                raise urllib.error.HTTPError(url, 404, "nf", {}, None)
            return {"epoch": 3}
        with mock.patch.object(fleet, "_get_json", fake):
            self.assertEqual(fleet._fetch_rest_session(self.P, 1)["epoch"], 3)
            n = len(calls)
            fleet._fetch_rest_session(self.P, 1)
        self.assertEqual(calls[n:], ["http://h:8080/api/v1/session"])  # cached path first

    def test_401_is_not_swallowed(self):
        def fake(url, profile, timeout):
            raise urllib.error.HTTPError(url, 401, "no", {}, None)
        with mock.patch.object(fleet, "_get_json", fake):
            with self.assertRaises(urllib.error.HTTPError):
                fleet._fetch_rest_session(self.P, 1)

    def test_extract_variants(self):
        d = fleet._extract_ai({"advertisement": {"name": "n", "face": "f"}, "peers": [1, 2],
                               "state": {"handshakes": 4, "epoch": 9}, "mode": "AUTO", "uptime": 3725})
        self.assertEqual((d["remote_name"], d["face"], d["peers"], d["handshakes"], d["ai_epoch"]),
                         ("n", "f", 2, 4, 9))
        self.assertEqual(d["rest_uptime"], "1h 2m")
        self.assertEqual(fleet._extract_ai({}), {})


class FleetBackoffTest(unittest.TestCase):
    def test_should_probe(self):
        from pwnman.pwnman.fleet_tab import should_probe
        self.assertTrue(all(should_probe(f, c) for f in (0, 1, 2) for c in range(1, 6)))
        self.assertFalse(should_probe(3, 1))
        self.assertTrue(should_probe(3, 2))
        self.assertEqual(sum(should_probe(30, c) for c in range(1, 33)), 2)  # every 16th


class PtyTest(unittest.TestCase):
    def test_screen_renders_and_resizes(self):
        from pwnman.pwnman.pty_terminal import TermScreen
        t = TermScreen(20, 5)
        t.feed(b"hello\r\n\x1b[31mred\x1b[0m")
        self.assertEqual(t.text().splitlines()[0], "hello")
        self.assertEqual(t.screen.buffer[1][0].fg, "red")
        t.resize(40, 10)
        self.assertEqual(t.size, (40, 10))

    def test_key_bytes(self):
        from PyQt6 import QtCore
        from pwnman.pwnman.pty_terminal import key_bytes
        K, M = QtCore.Qt.Key, QtCore.Qt.KeyboardModifier
        self.assertEqual(key_bytes(K.Key_C, M.ControlModifier, "\x03"), b"\x03")
        self.assertEqual(key_bytes(K.Key_Up, M.NoModifier, ""), b"\x1b[A")
        self.assertEqual(key_bytes(K.Key_Return, M.NoModifier, "\r"), b"\r")
        self.assertEqual(key_bytes(K.Key_A, M.NoModifier, "é"), "é".encode())
        self.assertEqual(key_bytes(K.Key_B, M.AltModifier, "b"), b"\x1bb")
        self.assertIsNone(key_bytes(K.Key_Shift, M.NoModifier, ""))


if __name__ == "__main__":
    unittest.main()
