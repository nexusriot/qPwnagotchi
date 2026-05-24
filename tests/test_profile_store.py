import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman import profile_store
from pwnman.pwnman.profile_store import ProfileStore

POSIX = not sys.platform.startswith("win")


class ProfileStoreCrudTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "profiles.json"

    def tearDown(self):
        self.tmp.cleanup()

    def store(self):
        return ProfileStore(path=self.path)

    def test_empty_when_missing(self):
        s = self.store()
        self.assertEqual(s.names(), [])
        self.assertEqual(s.active_name, "")
        self.assertIsNone(s.active())

    def test_upsert_inserts_then_updates(self):
        s = self.store()
        s.upsert(ConnectionProfile(name="a", host="1.1.1.1"))
        self.assertEqual(s.names(), ["a"])
        s.upsert(ConnectionProfile(name="a", host="2.2.2.2"))
        self.assertEqual(s.names(), ["a"])
        self.assertEqual(s.get("a").host, "2.2.2.2")

    def test_delete_reassigns_active(self):
        s = self.store()
        s.upsert(ConnectionProfile(name="a"))
        s.upsert(ConnectionProfile(name="b"))
        s.active_name = "a"
        s.delete("a")
        self.assertEqual(s.names(), ["b"])
        self.assertEqual(s.active_name, "b")

    def test_delete_last_clears_active(self):
        s = self.store()
        s.upsert(ConnectionProfile(name="a"))
        s.active_name = "a"
        s.delete("a")
        self.assertEqual(s.active_name, "")

    def test_replace_all_validates_active(self):
        s = self.store()
        s.replace_all([ConnectionProfile(name="x")], active="nope")
        self.assertEqual(s.active_name, "x")
        s.replace_all([], active="anything")
        self.assertEqual(s.active_name, "")

    def test_persistence_roundtrip(self):
        s = self.store()
        s.upsert(ConnectionProfile(name="dev1", host="10.0.0.2", password="raspberry"))
        s.upsert(ConnectionProfile(name="dev2", host="10.0.0.3", port=2222))
        s.active_name = "dev2"
        s.save()

        s2 = self.store()
        self.assertEqual(s2.names(), ["dev1", "dev2"])
        self.assertEqual(s2.active_name, "dev2")
        self.assertEqual(s2.get("dev1").password, "raspberry")
        self.assertEqual(s2.get("dev2").port, 2222)

    def test_corrupt_file_degrades_gracefully(self):
        self.path.write_text("{ this is not json", encoding="utf-8")
        s = self.store()
        self.assertEqual(s.names(), [])
        self.assertEqual(s.active_name, "")

    def test_active_dropped_if_profile_missing(self):
        self.path.write_text(
            '{"version":1,"active":"ghost","profiles":[{"name":"real"}]}',
            encoding="utf-8",
        )
        s = self.store()
        self.assertEqual(s.names(), ["real"])
        self.assertEqual(s.active_name, "")

    def test_save_is_atomic_no_temp_left(self):
        s = self.store()
        s.upsert(ConnectionProfile(name="a"))
        s.save()
        leftovers = [p.name for p in self.path.parent.iterdir() if p.name != "profiles.json"]
        self.assertEqual(leftovers, [])

    @unittest.skipUnless(POSIX, "POSIX file permissions only")
    def test_saved_file_is_owner_only(self):
        s = self.store()
        s.upsert(ConnectionProfile(name="a", password="secret"))
        s.save()
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)


class ConfigDirTest(unittest.TestCase):
    def _tmpdir(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def _config_dir_with(self, platform, env):
        tmp = self._tmpdir()
        resolved = {k: v.replace("<TMP>", tmp) for k, v in env.items()}
        with mock.patch.object(profile_store.sys, "platform", platform), \
             mock.patch.dict(os.environ, resolved, clear=False):
            d = profile_store.config_dir()
        return Path(d), tmp

    def test_linux_uses_xdg_config_home(self):
        d, tmp = self._config_dir_with("linux", {"XDG_CONFIG_HOME": "<TMP>"})
        self.assertEqual(d, Path(tmp) / "qPwnagotchi")
        self.assertTrue(d.is_dir())

    def test_linux_falls_back_to_dot_config(self):
        home = self._tmpdir()
        with mock.patch.object(profile_store.sys, "platform", "linux"), \
             mock.patch.dict(os.environ, {}, clear=False), \
             mock.patch.object(profile_store.Path, "home", staticmethod(lambda: Path(home))):
            os.environ.pop("XDG_CONFIG_HOME", None)
            d = profile_store.config_dir()
        self.assertEqual(d, Path(home) / ".config" / "qPwnagotchi")
        self.assertTrue(d.is_dir())

    def test_windows_uses_appdata(self):
        d, tmp = self._config_dir_with("win32", {"APPDATA": "<TMP>"})
        self.assertEqual(d, Path(tmp) / "qPwnagotchi")
        self.assertTrue(d.is_dir())

    def test_macos_uses_application_support(self):
        home = self._tmpdir()
        with mock.patch.object(profile_store.sys, "platform", "darwin"), \
             mock.patch.object(profile_store.Path, "home", staticmethod(lambda: Path(home))):
            d = profile_store.config_dir()
        self.assertEqual(
            d, Path(home) / "Library" / "Application Support" / "qPwnagotchi"
        )
        self.assertTrue(d.is_dir())

    @unittest.skipUnless(POSIX, "POSIX file permissions only")
    def test_dir_is_owner_only_on_posix(self):
        d, _ = self._config_dir_with("linux", {"XDG_CONFIG_HOME": "<TMP>"})
        mode = stat.S_IMODE(os.stat(d).st_mode)
        self.assertEqual(mode, 0o700)


if __name__ == "__main__":
    unittest.main()
