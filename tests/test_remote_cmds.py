import shlex
import subprocess
import unittest

from pwnman.pwnman import remote_cmds as rc

HOSTILE = ["a b", "x'y", "$(touch /tmp/pwned)", "`id`", "; rm -rf /", "é ü", "a\nb"]


def tokens(cmd):
    return shlex.split(cmd.replace("||", " ; "), posix=True)


class QuotingTest(unittest.TestCase):
    def test_list_dir_and_tail_quote_paths(self):
        for h in HOSTILE:
            self.assertIn(h, shlex.split(rc.list_dir(h).split("2>")[0]))
            self.assertIn(h, shlex.split(rc.tail_log(5, h).split("2>")[0]))

    def test_service_name_validated(self):
        for bad in ("a b", "x;y", "$(id)", ""):
            with self.assertRaises(ValueError):
                rc.service_action("start", bad)
        with self.assertRaises(ValueError):
            rc.service_action("rm", "ssh")
        self.assertIn("systemctl restart pwnagotchi", rc.service_action("restart", "pwnagotchi"))

    def test_handshake_names_must_be_basenames(self):
        for bad in (["../etc/passwd"], ["a/b.pcap"], [""], [".."], []):
            with self.assertRaises(ValueError):
                rc.delete_handshakes(bad)
            with self.assertRaises(ValueError):
                rc.stage_for_download(bad, "/tmp/x")
        cmd = rc.delete_handshakes(["we ird'name.pcap"])
        self.assertIn("/root/handshakes/we ird'name.pcap", shlex.split(cmd))

    def test_real_shell_does_not_execute_injection(self):
        # Run the builder's output through a real shell with echo substituted.
        for h in HOSTILE:
            cmd = rc.list_dir(h).replace("ls -1", "printf '%s\\n'").split("2>")[0]
            out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True).stdout
            self.assertEqual(out.rstrip("\n"), h)

    def test_plugin_cli_args_validated(self):
        self.assertEqual(rc.plugin_cli("install", "grid"), "sudo -n pwnagotchi plugins install grid 2>&1")
        for bad in ("a b", "x;id", "$(id)"):
            with self.assertRaises(ValueError):
                rc.plugin_cli("install", bad)
        with self.assertRaises(ValueError):
            rc.plugin_cli("format")

    def test_mode(self):
        self.assertIn("/root/.pwnagotchi-manual", rc.mode_set("MANUAL"))
        with self.assertRaises(ValueError):
            rc.mode_set("X")


class ParsersTest(unittest.TestCase):
    def test_parse_handshakes(self):
        out = "b.pcap\t100\t1700000100.5\na.pcap\t50\t1700000000.0\ngarbage\nbad\tx\ty\n"
        rows = rc.parse_handshakes(out)
        self.assertEqual([r["name"] for r in rows], ["b.pcap", "a.pcap"])  # newest first
        self.assertEqual(rows[0]["size"], 100)
        self.assertEqual(rows[0]["mtime"], 1700000100)

    def test_parse_plugin_list(self):
        out = ("+------+--------+---------+\n| Name | Version | Status |\n+------+--------+---------+\n"
               "| grid | 1.0.1  | enabled |\n| gps  | 1.0    | installed |\n")
        rows = rc.parse_plugin_list(out)
        self.assertEqual([r["name"] for r in rows], ["grid", "gps"])
        self.assertEqual(rows[0]["version"], "1.0.1")
        self.assertEqual(rows[1]["status"], "installed")

    def test_parse_battery(self):
        self.assertEqual(rc.parse_battery("pisugar:87.5"), 87.5)
        self.assertEqual(rc.parse_battery("battery:42"), 42.0)
        self.assertIsNone(rc.parse_battery("none"))


if __name__ == "__main__":
    unittest.main()
