import unittest

try:
    from pwnman.pwnman.ui_main import (
        parse_plugins_from_ls,
        extract_enabled_from_toml,
        set_plugin_enabled_in_toml,
        quote_bash,
    )
    IMPORT_ERR = None
except Exception as e:  # PyQt6/WebEngine unavailable in this environment
    IMPORT_ERR = e


@unittest.skipIf(IMPORT_ERR is not None, f"ui_main import failed: {IMPORT_ERR}")
class ParsePluginsTest(unittest.TestCase):
    def test_filters_py_files_and_dunder(self):
        out = "total 8\ngrid.py\nfoo.py\n__init__.py\nREADME.md\n"
        self.assertEqual(parse_plugins_from_ls(out), ["foo", "grid"])

    def test_dedup_and_sorted(self):
        self.assertEqual(parse_plugins_from_ls("b.py\na.py\nb.py\n"), ["a", "b"])

    def test_empty(self):
        self.assertEqual(parse_plugins_from_ls(""), [])


@unittest.skipIf(IMPORT_ERR is not None, f"ui_main import failed: {IMPORT_ERR}")
class ExtractEnabledTest(unittest.TestCase):
    def test_dotted_form(self):
        toml = "main.plugins.grid.enabled = true\nmain.plugins.gps.enabled = false\n"
        self.assertEqual(
            extract_enabled_from_toml(toml), {"grid": True, "gps": False}
        )

    def test_table_form(self):
        toml = "[main.plugins.webcfg]\nenabled = true\nfoo = 1\n"
        self.assertEqual(extract_enabled_from_toml(toml), {"webcfg": True})

    def test_none_found(self):
        self.assertEqual(extract_enabled_from_toml("unrelated = 1\n"), {})


@unittest.skipIf(IMPORT_ERR is not None, f"ui_main import failed: {IMPORT_ERR}")
class SetEnabledTest(unittest.TestCase):
    def test_flips_dotted_value(self):
        toml = "main.plugins.grid.enabled = false\n"
        out = set_plugin_enabled_in_toml(toml, "grid", True)
        self.assertIn("main.plugins.grid.enabled = true", out)
        self.assertNotIn("= false", out)

    def test_flips_table_value(self):
        toml = "[main.plugins.grid]\nenabled = false\n"
        out = set_plugin_enabled_in_toml(toml, "grid", True)
        self.assertEqual(extract_enabled_from_toml(out), {"grid": True})

    def test_adds_enabled_into_existing_table_without_key(self):
        toml = "[main.plugins.grid]\nfoo = 1\n"
        out = set_plugin_enabled_in_toml(toml, "grid", True)
        self.assertEqual(extract_enabled_from_toml(out).get("grid"), True)

    def test_appends_block_when_absent(self):
        out = set_plugin_enabled_in_toml("main.name = 'x'\n", "newp", True)
        self.assertIn("[main.plugins.newp]", out)
        self.assertEqual(extract_enabled_from_toml(out).get("newp"), True)

    def test_roundtrip_toggle(self):
        toml = "main.plugins.p.enabled = true\n"
        off = set_plugin_enabled_in_toml(toml, "p", False)
        self.assertEqual(extract_enabled_from_toml(off), {"p": False})
        on = set_plugin_enabled_in_toml(off, "p", True)
        self.assertEqual(extract_enabled_from_toml(on), {"p": True})


@unittest.skipIf(IMPORT_ERR is not None, f"ui_main import failed: {IMPORT_ERR}")
class QuoteBashTest(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(quote_bash("echo hi"), "'echo hi'")

    def test_escapes_single_quotes(self):
        self.assertEqual(quote_bash("it's"), "'it'\"'\"'s'")


if __name__ == "__main__":
    unittest.main()
