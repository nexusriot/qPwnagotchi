"""LCD tab: embedded view of the device's web UI."""
from __future__ import annotations

from typing import Callable

from PyQt6 import QtCore, QtWebEngineWidgets, QtWidgets

from pwnman.pwnman import settings as app_settings

PLACEHOLDER_HTML = """
<html><body style="background:#000;color:#cfd8dc;font-family:monospace;padding:24px;
  display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;">
  <div style="font-size:44px;font-weight:800;margin-bottom:12px;">Connected</div>
  <div style="font-size:22px;line-height:1.35;opacity:0.9;text-align:center;">
    Open the LCD web URL to start streaming.</div>
</body></html>"""
BLANK_HTML = "<html><body style='background:#000;'></body></html>"


class LcdTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, profile_name: Callable[[], str] = lambda: "default", parent=None):
        super().__init__(parent)
        self._profile_name = profile_name
        self._connected = False
        outer = QtWidgets.QVBoxLayout(self)
        bar = QtWidgets.QHBoxLayout()

        self.url = QtWidgets.QLineEdit("http://10.0.0.2:8080/")
        self.user = QtWidgets.QLineEdit("changeme")
        self.password = QtWidgets.QLineEdit("changeme")
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.btn_open = QtWidgets.QPushButton("Open Web LCD")
        self.btn_reload = QtWidgets.QPushButton("Reload")
        self.btn_close = QtWidgets.QPushButton("Close Web LCD")
        self.auto_reload = QtWidgets.QCheckBox("Auto reload")
        self.auto_reload.setChecked(True)
        self.reload_sec = QtWidgets.QSpinBox()
        self.reload_sec.setRange(1, 120)
        self.reload_sec.setValue(5)
        self.zoom = QtWidgets.QDoubleSpinBox()
        self.zoom.setRange(0.2, 2.0)
        self.zoom.setSingleStep(0.1)
        self.zoom.setValue(0.5)
        self.zoom.setSuffix("x")

        for w in (QtWidgets.QLabel("URL:"), self.url, QtWidgets.QLabel("User:"), self.user,
                  QtWidgets.QLabel("Pass:"), self.password, self.btn_open, self.btn_reload,
                  self.btn_close, self.auto_reload, QtWidgets.QLabel("sec:"), self.reload_sec,
                  QtWidgets.QLabel("Zoom:"), self.zoom):
            bar.addWidget(w, 1 if w is self.url else 0)
        outer.addLayout(bar)

        self.web = QtWebEngineWidgets.QWebEngineView()
        self.web.setAttribute(QtCore.Qt.WidgetAttribute.WA_OpaquePaintEvent, True)
        self.web.setStyleSheet("background: #000;")
        self.web.setMinimumHeight(260)
        outer.addWidget(self.web, 1)

        page = self.web.page()
        page.authenticationRequired.connect(self._on_auth_required)
        page.certificateError.connect(self._on_cert_error)

        self.btn_open.clicked.connect(self.open_web)
        self.btn_reload.clicked.connect(self.reload_now)
        self.btn_close.clicked.connect(self.close_web)
        self.zoom.valueChanged.connect(lambda v: self.web.setZoomFactor(float(v)))
        self.zoom.valueChanged.connect(lambda _v: self.save_prefs())
        self.reload_sec.valueChanged.connect(lambda _v: self.save_prefs())
        self.auto_reload.toggled.connect(lambda _v: self.save_prefs())

        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.auto_reload.stateChanged.connect(self._autoreload_changed)
        self.reload_sec.valueChanged.connect(self._autoreload_changed)
        self.web.loadFinished.connect(self.apply_zoom)
        QtCore.QTimer.singleShot(0, self._autoreload_changed)

    # ------------------------------------------------------------------ state
    def set_connected(self, ok: bool):
        self._connected = ok
        if ok:
            self._autoreload_changed()
            self.web.setHtml(PLACEHOLDER_HTML)
            self.apply_zoom()
        else:
            self._timer.stop()
            self.web.setHtml(BLANK_HTML)  # truly blank: no stale page

    def on_shown(self):
        """Reduce WebEngine flicker/glitch on tab switch."""
        self.apply_zoom()
        QtCore.QTimer.singleShot(50, self.web.repaint)

    def host(self) -> str:
        return QtCore.QUrl(self.url.text().strip()).host().lower()

    # --------------------------------------------------------------- actions
    def open_web(self):
        if not self._connected:
            self.log.emit("LCD Web: not connected — web view is disabled.")
            return
        url = self.url.text().strip()
        if not url:
            return
        self.log.emit(f"LCD Web: opening {url}")
        self.web.setUrl(QtCore.QUrl(url))
        self._autoreload_changed()

    def reload_now(self):
        if not self._connected:
            self.log.emit("LCD Web: not connected — reload skipped.")
            return
        if self.web.url().isValid():
            self.web.reload()
        else:
            self.open_web()
        self.apply_zoom()

    def close_web(self):
        self._timer.stop()  # stop the reload loop (checkbox state is kept)
        self.web.setUrl(QtCore.QUrl("about:blank"))
        if self._connected:
            self.web.setHtml(PLACEHOLDER_HTML)
            self.apply_zoom()
        else:
            self.web.setHtml(BLANK_HTML)
        self.log.emit("LCD Web: closed")

    def apply_zoom(self, _ok=True):
        self.web.setZoomFactor(float(self.zoom.value()))

    def _autoreload_changed(self, *_):
        if not self._connected:  # never auto-reload while disconnected
            self._timer.stop()
            return
        if self.auto_reload.isChecked():
            self._timer.start(int(self.reload_sec.value()) * 1000)
            self.log.emit(f"LCD Web auto reload: ON ({self.reload_sec.value()}s)")
        else:
            self._timer.stop()
            self.log.emit("LCD Web auto reload: OFF")

    def _tick(self):
        if not self._connected:
            return
        # avoid annoying reload while typing credentials/url
        if self.url.hasFocus() or self.user.hasFocus() or self.password.hasFocus():
            return
        if self.web.url().isValid():
            self.web.reload()
            self.apply_zoom()

    # ------------------------------------------------------- auth / certificates
    def _on_auth_required(self, url, authenticator):
        # Only auto-answer for the host configured in this profile; anything
        # else (a redirect, a different device) gets an explicit prompt.
        if url.host().lower() == self.host():
            authenticator.setUser(self.user.text())
            authenticator.setPassword(self.password.text())
            return
        user, ok = QtWidgets.QInputDialog.getText(self, "Authentication", f"User for {url.host()}:")
        if not ok:
            return
        pw, ok = QtWidgets.QInputDialog.getText(
            self, "Authentication", f"Password for {url.host()}:",
            QtWidgets.QLineEdit.EchoMode.Password)
        if ok:
            authenticator.setUser(user)
            authenticator.setPassword(pw)

    @staticmethod
    def trusted_certs() -> set:
        v = app_settings.get("lcd/trusted_certs", [])
        if isinstance(v, str):
            v = [v]
        return set(v or [])

    def _on_cert_error(self, error):
        """Self-signed web UI: trust per host+fingerprint, remembered."""
        from PyQt6 import QtNetwork
        chain = error.certificateChain()
        digest = ""
        if chain:
            digest = bytes(chain[0].digest(QtNetwork.QCryptographicHash.Algorithm.Sha256).toHex()).decode()
        key = f"{error.url().host().lower()}|{digest}"
        if digest and key in self.trusted_certs():
            error.acceptCertificate()
            return
        ans = QtWidgets.QMessageBox.question(
            self, "Untrusted certificate",
            f"{error.url().host()} presented a certificate that is not trusted:\n"
            f"{error.description()}\n\nSHA-256: {digest or '?'}\n\n"
            "Trust this exact certificate for this host from now on?")
        if ans == QtWidgets.QMessageBox.StandardButton.Yes and digest:
            app_settings.put("lcd/trusted_certs", sorted(self.trusted_certs() | {key}))
            error.acceptCertificate()
        else:
            error.rejectCertificate()

    # ----------------------------------------------------------- preferences
    def _pref_key(self, what: str) -> str:
        return f"lcd/{self._profile_name() or 'default'}/{what}"

    def load_prefs(self):
        for w in (self.zoom, self.reload_sec, self.auto_reload):
            w.blockSignals(True)
        self.zoom.setValue(float(app_settings.get(self._pref_key("zoom"), 0.5, float)))
        self.reload_sec.setValue(int(app_settings.get(self._pref_key("sec"), 5, int)))
        self.auto_reload.setChecked(bool(app_settings.get(self._pref_key("auto"), True, bool)))
        for w in (self.zoom, self.reload_sec, self.auto_reload):
            w.blockSignals(False)
        self.apply_zoom()

    def save_prefs(self):
        app_settings.put(self._pref_key("zoom"), float(self.zoom.value()))
        app_settings.put(self._pref_key("sec"), int(self.reload_sec.value()))
        app_settings.put(self._pref_key("auto"), bool(self.auto_reload.isChecked()))

    def dispose(self):
        """Destroy the web view/page deterministically (avoids exit-time crashes)."""
        self._timer.stop()
        self.web.page().deleteLater()
        self.web.deleteLater()
