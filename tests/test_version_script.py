"""Unit tests for scripts/version.sh.

The script must emit a Debian-policy-valid upstream-version string in every
case (must start with a digit, no whitespace, no leading 'v'). We exercise:
  - exact tag      -> "X.Y.Z"
  - dirty worktree -> "0.1.0+git<sha>.dirty"
  - clean untagged -> "0.1.0+git<sha>"
  - missing git    -> "0.1.0"
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
SCRIPT = REPO / "scripts" / "version.sh"

# Debian policy: upstream_version must start with a digit and contain only
# [A-Za-z0-9.+~-]. We also forbid whitespace.
DEB_VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9.+~-]*$")


def _run_script(cwd: Path, env: dict | None = None) -> str:
    """Run version.sh as if from `cwd` and return its stdout, stripped.

    The script does `cd "$(dirname "$0")/.."` first, so calling it from a
    fake repo means we need to *copy* the script into that repo. Tests do
    that in their setUp.
    """
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    out = subprocess.run(
        ["bash", str(cwd / "scripts" / "version.sh")],
        cwd=str(cwd),
        env=full_env,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def _git(cwd: Path, *args: str) -> None:
    env = os.environ.copy()
    # Make commits reproducible & possible without a user gitconfig.
    env.update(
        {
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
        }
    )
    subprocess.run(["git", *args], cwd=str(cwd), env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class VersionScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="qpwn-vertest-"))
        # Mirror the script into a fake repo root so its `cd ..` lands here.
        (self.tmp / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.tmp / "scripts" / "version.sh")
        (self.tmp / "scripts" / "version.sh").chmod(0o755)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


    def _init_repo_with_commit(self) -> None:
        _git(self.tmp, "init", "-q", "-b", "main")
        (self.tmp / "f.txt").write_text("hi\n")
        _git(self.tmp, "add", "f.txt")
        _git(self.tmp, "commit", "-q", "-m", "init")

    def _short_sha(self) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.tmp), "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip()


    def test_no_git_returns_fallback(self):
        # No .git directory at all.
        self.assertEqual(_run_script(self.tmp), "0.1.0")

    def test_untagged_clean_uses_short_sha(self):
        self._init_repo_with_commit()
        sha = self._short_sha()
        self.assertEqual(_run_script(self.tmp), f"0.1.0+git{sha}")

    def test_untagged_dirty_appends_dirty(self):
        self._init_repo_with_commit()
        # Modify a tracked file -> dirty worktree.
        (self.tmp / "f.txt").write_text("changed\n")
        sha = self._short_sha()
        self.assertEqual(_run_script(self.tmp), f"0.1.0+git{sha}.dirty")

    def test_staged_changes_also_count_as_dirty(self):
        # `git diff --cached` matters too. Stage a new file.
        self._init_repo_with_commit()
        (self.tmp / "g.txt").write_text("staged\n")
        _git(self.tmp, "add", "g.txt")
        sha = self._short_sha()
        self.assertEqual(_run_script(self.tmp), f"0.1.0+git{sha}.dirty")

    def test_exact_tag_strips_v_prefix(self):
        self._init_repo_with_commit()
        _git(self.tmp, "tag", "v1.2.3")
        self.assertEqual(_run_script(self.tmp), "1.2.3")

    def test_exact_tag_without_v_kept_as_is(self):
        self._init_repo_with_commit()
        _git(self.tmp, "tag", "2.0.0")
        self.assertEqual(_run_script(self.tmp), "2.0.0")

    def test_output_is_always_debian_valid(self):
        # Run all of the above states through and check the regex.
        self.assertRegex(_run_script(self.tmp), DEB_VERSION_RE)  # no-git

        self._init_repo_with_commit()
        self.assertRegex(_run_script(self.tmp), DEB_VERSION_RE)  # untagged

        (self.tmp / "f.txt").write_text("y\n")
        self.assertRegex(_run_script(self.tmp), DEB_VERSION_RE)  # dirty

        _git(self.tmp, "add", "-A")
        _git(self.tmp, "commit", "-q", "-m", "x")
        _git(self.tmp, "tag", "v0.9.1")
        self.assertRegex(_run_script(self.tmp), DEB_VERSION_RE)  # tagged


if __name__ == "__main__":
    unittest.main()
