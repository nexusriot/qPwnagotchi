"""Small dialogs: About."""
from __future__ import annotations

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman.resources import app_icon, icon_svg_path, find_icon_png
from pwnman.pwnman.version import __version__ as APP_VERSION

APP_HOME_URL = "https://github.com/evilsocket/pwnagotchi"


class AboutDialog(QtWidgets.QDialog):
    """About box showing the app icon, version, and credits."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About qPwnagotchi")
        self.setModal(True)
        self.setMinimumWidth(460)
        icon = app_icon()
        if not icon.isNull():
            self.setWindowIcon(icon)

        root = QtWidgets.QVBoxLayout(self)
        root.setSpacing(14)

        # Header: big icon + title block
        header = QtWidgets.QHBoxLayout()
        header.setSpacing(16)

        icon_label = QtWidgets.QLabel()
        icon_label.setFixedSize(128, 128)
        icon_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        pix = self._load_pixmap(128)
        if not pix.isNull():
            icon_label.setPixmap(pix)
        header.addWidget(icon_label, 0, QtCore.Qt.AlignmentFlag.AlignTop)

        title_box = QtWidgets.QVBoxLayout()
        title_box.setSpacing(2)

        name = QtWidgets.QLabel("qPwnagotchi")
        f = name.font()
        f.setPointSize(max(f.pointSize() + 8, 18))
        f.setBold(True)
        name.setFont(f)
        title_box.addWidget(name)

        ver = QtWidgets.QLabel(f"Version {APP_VERSION}")
        title_box.addWidget(ver)

        sub = QtWidgets.QLabel("Pwnagotchi Manager — manage your own Pwnagotchi over SSH.")
        sub.setWordWrap(True)
        title_box.addWidget(sub)

        title_box.addStretch(1)
        header.addLayout(title_box, 1)

        root.addLayout(header)

        # Details
        details = QtWidgets.QLabel(
            "<p>A small PyQt6 desktop app for remote administration of a "
            "Pwnagotchi you already own. Provides status, service control, "
            "log viewing, config editing, plugin toggles, an SFTP file "
            "manager, an embedded SSH terminal, and a fleet view.</p>"
            "<p>This tool intentionally does <b>not</b> provide features "
            "for offensive actions.</p>"
            f"<p>Pwnagotchi project: <a href='{APP_HOME_URL}'>{APP_HOME_URL}</a></p>"
        )
        details.setWordWrap(True)
        details.setTextFormat(QtCore.Qt.TextFormat.RichText)
        details.setOpenExternalLinks(True)
        details.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextBrowserInteraction
        )
        root.addWidget(details)

        # Buttons
        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Close
        )
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        btns.button(QtWidgets.QDialogButtonBox.StandardButton.Close).clicked.connect(
            self.accept
        )
        root.addWidget(btns)

    def _load_pixmap(self, size: int) -> QtGui.QPixmap:
        # Prefer the SVG so it stays crisp at any DPI.
        svg = icon_svg_path()
        if svg:
            pix = QtGui.QIcon(svg).pixmap(size, size)
            if not pix.isNull():
                return pix
        # Fall back to the best PNG we can find.
        png = find_icon_png(size) or find_icon_png(256) or find_icon_png(128)
        if png:
            return QtGui.QPixmap(png).scaled(
                size, size,
                QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                QtCore.Qt.TransformationMode.SmoothTransformation,
            )
        # Last resort: themed icon.
        themed = QtGui.QIcon.fromTheme("qpwnagotchi")
        if not themed.isNull():
            return themed.pixmap(size, size)
        return QtGui.QPixmap()
