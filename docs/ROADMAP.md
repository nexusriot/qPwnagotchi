# qPwnagotchi — improvement plan

> **Status (0.4.0):** also done since 0.3: `ui_main.py` split, metrics history, plugin catalog, light/dark theme.
>
> **Status (0.3.0):** Phases 0–4 are implemented (see CHANGELOG). Intentionally *not* done: default-credential removal (kept `raspberry`/`changeme` by request), signing/licence, Android port, onedir Linux package, optional lazy WebEngine. Remaining ideas are listed at the end.

Scope: the PyQt6 desktop app (`pwnman/pwnman/`). The pasted list targets an
Android client (Keystore, ViewModel, widgets, tiles). Items are mapped to their
desktop equivalent below; purely-Android items (home-screen widget, quick-settings
tile, foreground service) are parked under "Android port" at the end.

Guiding rules (carry over from the project's stance):
- No offensive features (no cracking, deauth, attack toggles). Handshake manager = list/download/delete only.
- Keep logic Qt-free in testable modules (pattern already used by `plugins_toml.py`, `remote_config.py`, `fleet.py`).
- Every feature ships with unit tests, plus an e2e test against the fake device (`docker/e2e/target`), extended as needed.

Effort: S ≤ 1 day, M 2–4 days, L ≈ 1–2 weeks.

---

## Phase 0 — Foundations (do first; everything else builds on it) · M

| # | Work | Details |
|---|------|---------|
| 0.1 | **Persistent session object** | Extract the shared `SSHClient` + connect/disconnect/reconnect state from `MainWindow` into `session.py` (`Session(QObject)`: `state` signal `disconnected/connecting/connected/reconnecting`, `error` signal). Tabs depend on `Session`, not `MainWindow._connected`. Desktop analogue of the Android ViewModel/Service. |
| 0.2 | **Auto-reconnect** | Exponential back-off (2→60 s) when the transport dies (`SSHClient.connected` already reflects transport state) or after a reboot we triggered; status-bar indicator + "Cancel". Optional per-profile "auto-connect on launch". |
| 0.3 | **Command runner with streaming** | Add `SSHClient.stream(cmd, on_data, stop_event)` (own channel, line callbacks) — required by live logs and PTY. Keep `run()` for one-shots. |
| 0.4 | **Move all remote shell construction into one module** (`remote_cmds.py`) | Each command built with `quote_bash` and unit-tested. Fixes the remaining unquoted interpolations: `cfg_path` in `on_plugins_refresh`'s `ls -1 {d}`, `on_logs`'s `tail`, `_svc` (`name` from a combo, safe, but unify). Test with hostile paths (spaces, `$()`, `'`). |
| 0.5 | **Resolve API path** | `fleet.py` uses `/api/v1/session`; some Pwnagotchi builds expose `/api/session`. Probe both (cache per profile), log which worked; add fake-device routes for both and an e2e test. Needed by the dashboard. |
| 0.6 | **Settings module** | `QSettings`-backed app settings (window geometry, last tab, LCD zoom/reload per profile) — currently reset every launch. |

## Phase 1 — Security & profiles · M

1. **Host-key verification (TOFU)** — replace `AutoAddPolicy` with a custom `MissingHostKeyPolicy` backed by `~/.config/qPwnagotchi/known_hosts`. First connect: dialog showing SHA256 fingerprint → accept/reject (remember). Changed key: blocking warning with old/new fingerprints, no silent override ("Replace key" is an explicit action). Fleet probes must *not* prompt: they fail with "host key unknown/changed" and a "Trust…" action in the Fleet tab. Tests: policy unit tests with fake keys; e2e: connect, rotate target host key (restart container sshd with new key), expect refusal.
2. **Credential storage** — move passwords out of `profiles.json` into the OS keyring (`keyring` package: libsecret / Windows Credential Manager / macOS Keychain); JSON keeps only a `password_ref`. Fallback to current 0600 file with a visible warning when no backend (headless Linux). One-time migration of existing profiles. **Remove the hardcoded defaults** `raspberry` / `changeme` from the UI (empty by default); LCD creds likewise.
3. **Quick-connect / auto-connect** — tray-less equivalent: "Connect on launch" per profile, `Ctrl+1..9` profile hotkeys, `--profile NAME [--connect]` CLI flag.
4. Key handling polish: key-file picker remembers directory; ssh-agent use is already enabled; show "passphrase" hint when the key is encrypted (label changes when a key path is set).

## Phase 2 — Pwnagotchi dashboard & operations · L

1. **Dashboard tab** (new first tab; LCD stays one click away). Pure data layer `device_status.py` merges: REST session JSON (name, face, epoch, handshakes, peers/friends, uptime, mode if present) + SSH probe (CPU temp, load, mem, disk, IP) + battery (PiSugar via `echo "get battery" | nc -q0 127.0.0.1 8423`, or `/sys/class/power_supply`, UPS HAT where available — each optional, hidden when absent). Rendered as cards; refresh timer (reuse the Fleet probe so there is one implementation). Replaces raw `uname -a` as the default Status view (raw view stays behind a "Details" button).
2. **Handshake manager** (new tab or promoted from Export): list `/root/handshakes/*.pcap` (+`.22000` if present) with size/mtime via `sudo stat`/`find -printf`; multi-select **download** (reuse transfer engine), **delete** (confirm, `sudo rm`, show count), "Open folder locally", "Export archive" (existing tar flow). Optional per-file metadata parsed from the filename (`ESSID_BSSID.pcap`). Hard rule: no cracking/inspection-for-attack features.
3. **Live log viewer** — builds on 0.3: `tail -F /var/log/pwnagotchi.log` (fallback `journalctl -fu pwnagotchi`) streamed to a bounded `QPlainTextEdit`; level filter (INFO/WARN/ERROR/DEBUG via regex on `[LEVEL]`), search box with highlight, Pause/Resume (buffer while paused), Clear, Copy/Save-as. Stops on tab hide/disconnect. e2e: fake device appends lines on a timer; assert filter + pause semantics.
4. **Safer config editing**:
   - TOML syntax check before save (`tomllib` — stdlib on 3.11+, add `tomli` for 3.10) with line/column error marker; allow "Save anyway" only after confirm.
   - Diff view (`difflib.unified_diff`) vs. the version loaded, shown in a confirm dialog.
   - **Backups tab/dialog**: list `config.toml.bak.*` (already created by `write_remote_text`), preview, one-click restore (itself backs up first), delete old ones, optional retention (keep N).
   - Replace regex plugin editing with a **format-preserving TOML editor** (`tomlkit`) — keeps comments, handles dotted and table styles, removes the heuristics in `plugins_toml.py` (keep its tests as the contract; run them against the new implementation).
5. **Plugin install/update** — wrap the device CLI: `pwnagotchi plugins list|install|update|upgrade|enable|disable` (detect availability; fall back to the current directory scan). Table gains Version / Update-available columns; Install/Update/Upgrade-all buttons with live output pane; long-running → streaming runner.
6. **Mode switch (AUTO/MANUAL)** — pwnagotchi toggles via `touch /root/.pwnagotchi-auto|manual` and a service restart (verify per image; make the command configurable per profile). Confirm dialog, show resulting state on the dashboard.
7. **Fleet** upgrades: initial probe on first show (table is empty for 30 s today), per-device retry/back-off, "Trust host key…" action, export table as CSV.

## Phase 3 — Usability · L

1. **Real terminal** — interactive PTY: `invoke_shell(term="xterm-256color")` on its own channel, VT100/xterm emulation via `pyte` rendered in a custom `QWidget` (colors, cursor, scrollback, resize → `resize_pty`, copy/paste, Ctrl+Shift+C/V, bracketed paste). Support `top`, `nano`, `htop`. Keep the current command-line tab as "Quick command" for scripted use. Biggest single item; spike `pyte` fidelity first (2 days) before committing.
2. **Notifications** — `QSystemTrayIcon` + desktop notifications: device went offline/online, handshake count increased, service stopped, battery low. Rules per device in Fleet; debounce; "do not disturb". Needs the tray icon (also gives minimize-to-tray + quick connect menu).
3. **Auto-discovery** — "Scan…" in the profile dialog: mDNS (`zeroconf`, `_ssh._tcp`, hostname patterns `pwnagotchi.local`), plus probe of well-known tether subnets (`10.0.0.2` USB, `192.168.44.44` BT) and the local /24 on port 22 (fast, concurrent, opt-in). Results → "Add as profile".
4. **LCD tab** — per-profile auto-reload & zoom persistence (0.6); keep user's scroll on reload (JS reload without losing state) or use the websocket/`/ui` image endpoint instead of full-page reload to remove flicker; handle self-signed HTTPS (`QWebEnginePage.certificateError` → per-host "trust this certificate" stored with its fingerprint); basic-auth prompt falls back to a dialog instead of using stored creds blindly.
5. **UI redesign** — replace 11 tabs with a left navigation rail (Dashboard · Terminal · Files · Logs · Config · Plugins · Handshakes · Fleet · Power) + a collapsible console dock; unify styling (Fusion + light/dark follow-system), HiDPI audit, keyboard shortcuts, strings centralized for i18n (`tr()`), accessibility names. Small-screen mode for the uConsole's 1280×720 (this app already targets it).
6. **File manager** polish: overwrite/skip/rename prompt, resume and cancel for transfers, per-file progress, preserve CRLF/encoding in the editor (currently decodes with `errors="replace"`, which can corrupt non-UTF-8 files on save — fix by detecting and refusing/offering latin-1).

## Phase 4 — Quality, CI, release · M

1. **CI** (GitHub Actions): job 1 `make test` (matrix py3.10–3.13, offscreen), job 2 `make e2e` (docker), job 3 tag → `make dist-all` → upload artifacts + `SHA256SUMS`. Cache buildx layers.
2. **Package smoke test** — write `scripts/e2e-package.sh` (referenced by `make e2e-package`): clean `debian:bookworm-slim` + `fedora` containers, install built `.deb`/`.rpm`, run `qpwnagotchi --version` and boot GUI offscreen for N seconds. Windows: run the exe `--version` under Wine in the build container.
3. **Release hygiene** — add LICENSE (RPM `License:` currently "Unspecified"), changelog discipline, tag-driven versioning (already supported), reproducible build flags (`SOURCE_DATE_EPOCH`), optional code signing for the Windows installer / `.deb` repo.
4. **Static quality** — `ruff` + `mypy --strict` on the Qt-free modules; pre-commit; remove dead code (`resources.py` unused helpers, duplicate spec files `app.spec`/`qpwnagotchi.spec` are gitignored leftovers).
5. **Thread-safety audit** — `run_in_thread` threads are parented to widgets (closing the window mid-operation can destroy a running `QThread`); keep a registry and join on close. `FileManagerWidget` transfers should be cancellable.

## Android port (separate project, for the pasted items that have no desktop analogue)

If an Android client is actually planned, it should be its own repo that reuses the *protocol knowledge* from this one, not the code:
- Port `plugins_toml`/`remote_config`/probe-script semantics (and test vectors from `tests/`) to Kotlin (`TomlPlugins`, `ShellQuote` with the same hostile-input cases listed in 0.4).
- Profiles in `EncryptedSharedPreferences`/Keystore, no default password; TOFU host-key fingerprints (Phase 1.1 behaviour); ViewModel/foreground-service session with Disconnect action and auto-reconnect (Phase 0.1–0.2).
- Dashboard, handshake manager, live logs, safe config editing, plugin management, mode switch = Phase 2 specs; PTY terminal with Ctrl/Tab row; widget/tile, notifications, mDNS/tether-subnet discovery, Material 3 bottom-nav redesign, `strings.xml`.
- The **fake Pwnagotchi container** from `make e2e` is directly reusable as the instrumented-test backend.

---

## Suggested order & milestones

| Milestone | Contents | Result |
|-----------|----------|--------|
| **0.3** | Phase 0 + Phase 1.1–1.2 | Session/reconnect, quoting module, TOFU, keyring |
| **0.4** | 2.1 dashboard, 2.2 handshakes, 2.3 live logs | Daily-driver value |
| **0.5** | 2.4 safe config, 2.5 plugins, 2.6 mode, Fleet upgrades | Safer administration |
| **0.6** | 3.1 PTY terminal, 3.2 notifications, 3.3 discovery | Power-user features |
| **0.7** | 3.4–3.6 + UI redesign | Polish |
| **1.0** | Phase 4 complete (CI, signed releases, license) | Stable release |

Dependencies: 0.3 (streaming) → live logs, plugin output, PTY; 0.1 (session) → reconnect, notifications, tray; 0.5 (API path) → dashboard; 1.1 (TOFU) → Fleet "Trust" action.

## Risks / open questions
- **Pwnagotchi variants** (evilsocket vs. jayofelony vs. Raspberry Pi OS Bookworm images) differ in API paths, plugin CLI and mode files — verify each against a real device before hard-coding; make commands per-profile overridable.
- **PTY terminal fidelity** (`pyte` is not a full xterm) — spike first; fallback is embedding the system terminal.
- **Keyring on headless Linux/uConsole** may have no backend → needs a graceful plaintext fallback with warning.
- **Bundle size** (~200 MB due to QtWebEngine): consider making the LCD web view optional/lazy (separate module, `QWebEngine` imported only when the tab is used) and an `--onedir` Linux package for faster startup.
