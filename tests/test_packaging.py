"""Tests for the Debian packaging glue.

These tests guard the two pieces a .deb release depends on:

  1. packaging/debian/control.in — must have the placeholders that
     build-deb.sh substitutes, plus the mandatory Debian control fields.

  2. scripts/build-deb.sh — given a stub "binary" in dist/, must produce a
     well-formed .deb whose control metadata matches what we asked for.
     Skipped if `dpkg-deb` is not installed (e.g. non-Debian host).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTROL_IN = REPO / "packaging" / "debian" / "control.in"
DESKTOP = REPO / "packaging" / "qpwnagotchi.desktop"
BUILD_DEB = REPO / "scripts" / "build-deb.sh"


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


class ControlTemplateTest(unittest.TestCase):
    """Static checks on control.in."""

    def setUp(self) -> None:
        self.text = CONTROL_IN.read_text()

    def test_has_all_placeholders(self):
        # build-deb.sh substitutes exactly these three.
        for ph in ("@VERSION@", "@ARCH@", "@SIZE@"):
            self.assertIn(ph, self.text, f"missing placeholder {ph}")

    def test_required_debian_fields_present(self):
        for field in (
            "Package:",
            "Version:",
            "Architecture:",
            "Maintainer:",
            "Description:",
            "Depends:",
        ):
            self.assertRegex(self.text, rf"(?m)^{re.escape(field)}")

    def test_package_name_matches_binary(self):
        # The .deb name and the /usr/bin entry must agree.
        m = re.search(r"(?m)^Package:\s*(\S+)\s*$", self.text)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "qpwnagotchi")

    def test_qt_runtime_deps_listed(self):
        # PyInstaller bundles Python but not the system Qt deps; verify
        # we still pull them in so the GUI starts on a clean Debian.
        deps_line = re.search(r"(?m)^Depends:\s*(.+)$", self.text).group(1)
        for lib in ("libxkbcommon0", "libfontconfig1", "libgl1", "libegl1"):
            self.assertIn(lib, deps_line, f"missing dep: {lib}")

    def test_substitution_yields_no_placeholders_left(self):
        rendered = (
            self.text.replace("@VERSION@", "1.2.3")
            .replace("@ARCH@", "amd64")
            .replace("@SIZE@", "1234")
        )
        self.assertNotIn("@", rendered.replace("@gmail.com", ""),
                         "stray @ placeholder after substitution")
        # And the substituted values actually appear.
        self.assertRegex(rendered, r"(?m)^Version:\s*1\.2\.3\s*$")
        self.assertRegex(rendered, r"(?m)^Architecture:\s*amd64\s*$")
        self.assertRegex(rendered, r"(?m)^Installed-Size:\s*1234\s*$")


class DesktopFileTest(unittest.TestCase):
    def test_exec_points_at_installed_binary(self):
        text = DESKTOP.read_text()
        self.assertRegex(text, r"(?m)^Exec=qpwnagotchi\s*$")
        self.assertRegex(text, r"(?m)^Type=Application\s*$")


@unittest.skipUnless(_have("dpkg-deb") and _have("bash"),
                     "dpkg-deb not available")
class BuildDebIntegrationTest(unittest.TestCase):
    """End-to-end: build-deb.sh on a fake binary should produce a real .deb.

    We never invoke PyInstaller — too slow and an unrelated dep. Instead we
    drop a tiny ELF-ish file into dist/ with the exact name build-deb.sh
    expects, then run it.
    """

    def setUp(self) -> None:
        # Stage a self-contained copy of the repo's packaging machinery in a
        # temp dir so the real dist/ isn't polluted by tests.
        self.tmp = Path(tempfile.mkdtemp(prefix="qpwn-debtest-"))
        for rel in ("scripts", "packaging"):
            shutil.copytree(REPO / rel, self.tmp / rel)
        shutil.copy2(REPO / "README.md", self.tmp / "README.md")
        (self.tmp / "dist").mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, version: str = "1.2.3", arch: str = "amd64") -> Path:
        bin_name = f"qpwnagotchi-{version}-{arch}"
        # A non-empty file is enough — build-deb.sh only `install`s it.
        (self.tmp / "dist" / bin_name).write_bytes(b"#!/bin/sh\necho stub\n")
        (self.tmp / "dist" / bin_name).chmod(0o755)

        env = os.environ.copy()
        env.update({"VERSION": version, "ARCH": arch, "APP_NAME": "qpwnagotchi"})
        subprocess.run(
            ["bash", str(self.tmp / "scripts" / "build-deb.sh")],
            cwd=str(self.tmp),
            env=env,
            check=True,
            capture_output=True,
        )
        deb = self.tmp / "dist" / f"qpwnagotchi_{version}_{arch}.deb"
        self.assertTrue(deb.exists(), f"{deb} not produced")
        return deb

    def test_produces_valid_deb_with_expected_metadata(self):
        deb = self._run(version="1.2.3", arch="amd64")

        # dpkg-deb -f reads the control file from the package.
        out = subprocess.check_output(
            ["dpkg-deb", "-f", str(deb),
             "Package", "Version", "Architecture", "Depends"],
            text=True,
        )
        fields = dict(
            line.split(": ", 1) for line in out.strip().splitlines() if ": " in line
        )
        self.assertEqual(fields["Package"], "qpwnagotchi")
        self.assertEqual(fields["Version"], "1.2.3")
        self.assertEqual(fields["Architecture"], "amd64")
        self.assertIn("libxkbcommon0", fields["Depends"])

    def test_payload_layout(self):
        deb = self._run(version="0.1.0", arch="arm64")

        listing = subprocess.check_output(
            ["dpkg-deb", "-c", str(deb)], text=True
        )
        # Binary, .desktop entry, and bundled README all land in canonical
        # FHS paths.
        self.assertIn("./usr/bin/qpwnagotchi", listing)
        self.assertIn("./usr/share/applications/qpwnagotchi.desktop", listing)
        self.assertIn("./usr/share/doc/qpwnagotchi/README.md", listing)

    def test_fails_clearly_when_binary_missing(self):
        # No file in dist/ -> the script must exit non-zero (not silently
        # produce an empty .deb).
        env = os.environ.copy()
        env.update({"VERSION": "9.9.9", "ARCH": "amd64"})
        proc = subprocess.run(
            ["bash", str(self.tmp / "scripts" / "build-deb.sh")],
            cwd=str(self.tmp),
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not found", proc.stderr)


if __name__ == "__main__":
    unittest.main()
