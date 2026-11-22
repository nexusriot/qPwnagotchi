"""Qt-free helpers to read/write root-owned files on the device safely.

Why not a heredoc? The old implementation escaped ``$``/backslash/backtick
inside a *quoted* heredoc (where no expansion happens), which corrupted any
config containing those characters, and a line reading ``EOF`` truncated it.
Content now travels over SFTP as raw bytes; only quoted paths touch a shell.
"""
from __future__ import annotations

import uuid

from pwnman.pwnman.async_utils import quote_bash


def read_remote_text(ssh, path: str, timeout_sec: float = 20.0) -> str:
    """Read a (possibly root-only) text file. Raises on failure, never returns
    an empty string just because the read failed."""
    q = quote_bash(path)
    r = ssh.run(f"sudo -n cat {q} 2>/dev/null || cat {q}", timeout_sec=timeout_sec)
    if r.exit_status != 0:
        raise RuntimeError((r.stderr or "").strip() or f"Failed to read {path}")
    return r.stdout


def write_remote_text(ssh, path: str, text: str, backup: bool = True,
                      timeout_sec: float = 30.0) -> str:
    """Replace ``path`` with ``text`` (UTF-8), keeping its owner/mode.

    A timestamped ``.bak`` copy is made first; if the backup fails the file is
    left untouched. Returns the backup path ("" if none was needed).
    """
    tmp = f"/tmp/.qpwn-{uuid.uuid4().hex}.tmp"
    sftp = ssh.sftp()
    with sftp.open(tmp, "wb") as fh:
        try:
            fh.chmod(0o600)
        except Exception:  # noqa: BLE001 - best effort
            pass
        fh.write(text.encode("utf-8"))

    do_backup = "1" if backup else "0"
    script = f"""
P={quote_bash(path)}
T={quote_bash(tmp)}
S="$(date +%Y%m%d-%H%M%S)"
B="$P.bak.$S"
n=0
# never overwrite an existing backup taken within the same second
while [ -e "$B" ] || sudo -n test -e "$B" 2>/dev/null; do n=$((n+1)); B="$P.bak.$S-$n"; done
EXISTS=0
if [ -e "$P" ] || sudo -n test -e "$P" 2>/dev/null; then EXISTS=1; fi
if [ {do_backup} = 1 ] && [ "$EXISTS" = 1 ]; then
  if ! {{ sudo -n cp -a "$P" "$B" 2>/dev/null || cp -a "$P" "$B"; }}; then
    echo "backup failed; config NOT modified" >&2
    rm -f "$T"
    exit 3
  fi
  echo "BACKUP:$B"
fi
if {{ sudo -n cp "$T" "$P" 2>/dev/null || cp "$T" "$P"; }}; then rc=0; else rc=$?; fi
rm -f "$T"
exit $rc
"""
    r = ssh.run(f"bash -c {quote_bash(script)}", timeout_sec=timeout_sec)
    if r.exit_status != 0:
        raise RuntimeError((r.stderr or r.stdout).strip() or f"Failed to write {path}")
    for line in r.stdout.splitlines():
        if line.startswith("BACKUP:"):
            return line[len("BACKUP:"):]
    return ""
