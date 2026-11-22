# Changelog

## 0.4.0
### Added
- **Metrics history**: every Dashboard/Fleet sample (CPU temperature, battery, memory, load, handshakes, AI epoch, online/offline) is stored in a local SQLite database (30-day retention, throttled to one sample per device per 20 s). New **History** tab with per-device charts, range selector (1 h – 30 d), min/avg/max, availability %, handshakes gained, hover tooltips, gaps where the device was offline, CSV export and clear.
- **Plugin catalog**: the Plugins tab now merges the directory scan, `config.toml` and `pwnagotchi plugins list` into one searchable table (Version, Status, Update badge with target version), with filters (Installed / Enabled / Updates available / Not installed) and a summary line.
- **Light / dark / follow-system theme** (View → Theme, remembered). Charts, fleet status colours and the whole UI follow it; the system mode tracks OS changes live.
### Changed
- `ui_main.py` split from 1,651 to ~750 lines: Details, Services, Logs, Config (+ Backups dialog), Plugins, Power/Mode, LCD and About are now separate modules/widgets.
### Fixed
- A chart painted before it had data raised inside a Qt paint handler (process abort).
- Encrypted SSH keys: wrong/missing passphrase now gives a clear error; passphrase passed as bytes.
- Backups taken in the same second no longer overwrite each other; the backup list was always empty (bad glob).
- Transfer prompt "skip existing" now really skips; concurrent SFTP calls are serialised (hangs); thread cleanup race on window close.
### Tests
- 194 tests (134 unit + 60 end-to-end against the fake device), including history, plugin-catalog and theme coverage.

## 0.3.0
### Security / profiles
- SSH host-key verification (trust-on-first-use): unknown keys prompt with the SHA256 fingerprint, changed keys are refused with a warning and an explicit "Replace key". Stored in `known_hosts` (0600). Fleet probes never prompt; use the new **Trust host key…** button.
- Passwords (SSH and LCD) go to the OS keyring when one is available (plain 0600 JSON remains the fallback); existing profiles migrate on first save. Default `raspberry`/`changeme` field defaults are unchanged.
- Per-profile **Connect on launch**, `--profile NAME [--connect]` command line, window/tab/LCD preferences persisted.
### Session
- New `Session` object: liveness watchdog, auto-reconnect with exponential back-off (cancellable), streaming command channel.
- All remote shell commands built in `remote_cmds.py` (quoted, validated, unit-tested with hostile input).
- REST probe tries both `/api/session` and `/api/v1/session`.
### Pwnagotchi features
- **Dashboard** (native cards: name/face, mode, epoch/reward, handshakes, peers, uptime, CPU temp, load, memory, disk, IP, battery).
- **Handshake manager** (list/download/delete; no analysis or attack features).
- **Live log viewer** (follow, level filter, search, pause, copy/save).
- **Safer config editing**: TOML syntax check with cursor jump, diff-before-save, backups browser with one-click restore, parse-based/format-preserving plugin toggling (tomlkit).
- **Plugins**: install / update / upgrade through the `pwnagotchi plugins` CLI.
- **AUTO/MANUAL mode switch**.
- Fleet: probes on first show, per-device back-off, CSV export, Trust host key.
### Usability
- Real **PTY terminal** (pyte): colours, full-screen programs, resize, selection/copy/paste, Ctrl/Tab/arrow keys row. The old one-command box remains as "Quick cmd".
- Desktop **notifications** (tray): device offline/online, new handshakes, service stopped, low battery.
- **Device discovery** (mDNS + tether subnets, optional LAN scan).
- LCD tab: per-profile zoom/reload, self-signed certificate trust (pinned by fingerprint), safe auth prompt.
- Left navigation rail instead of 14 tabs; resizable console.
- File manager: overwrite/skip/cancel prompt, cancellable transfers, refuses non-UTF-8 edits, keeps CRLF.
### Build / quality
- CI workflow, `make lint` (ruff), `scripts/e2e-package.sh` (clean-machine .deb install + GUI boot), reproducible-build epoch, pip cache in Docker builds, `libatomic1` dependency.
- Thread safety: workers are joined on close and callbacks skip destroyed windows.

## 0.2.0
### Fixed
- Config save corrupted files containing `$`, `\\` or backticks (and truncated at a line `EOF`); it also replaced the root-owned file with a pi-owned one. Now written over SFTP + `sudo cp` preserving owner/mode, with a mandatory backup.
- Plugins "Apply" could overwrite the whole config with only plugin entries when the read failed; it now aborts. It also only touches plugins whose state changed, understands trailing `# comments`, and adds new plugins as root-level dotted keys (no more invalid-TOML `[main.plugins.x]` tables).
- Saving a profile while connected asked to disconnect; switching profiles kept the previous device's LCD URL/credentials.
- SSH terminal: `cd` never persisted; cwd quoting was injectable.
- SFTP: starts in the login user's home (was hardcoded `/home/pi`); a failed listing no longer leaves the pane and the working directory out of sync.
- Fleet: auto-refresh cleared the row selection; stale values shown for offline devices.
- SSH: encrypted private keys now work (password field = passphrase); stderr-heavy commands could deadlock; SFTP channel creation race; connection leak on failed connect; keepalive + real `connected` state; reboot/shutdown handle the dropped link correctly.
### Added
- Hermetic build system (Docker): linux amd64/arm64 binary + `.deb` + `.rpm`, Windows portable zip + NSIS installer, `make dist-all`.
- Hermetic E2E suite (`make e2e`) with a fake Pwnagotchi; `qpwnagotchi --version`.
- `pwnman/pwnman/version.py` as the single version source.
