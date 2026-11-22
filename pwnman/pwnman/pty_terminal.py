"""Interactive terminal: a real PTY shell channel rendered via pyte.

Handles full-screen programs (top, nano, htop), colours, resize, selection
and copy/paste. ``TermScreen`` is Qt-free and unit-testable.
"""
from __future__ import annotations

import threading
from typing import Optional

import pyte
from PyQt6 import QtCore, QtGui, QtWidgets

Qt = QtCore.Qt

_ANSI = {
    "black": "#000000", "red": "#cd3131", "green": "#0dbc79", "brown": "#e5e510",
    "blue": "#2472c8", "magenta": "#bc3fbc", "cyan": "#11a8cd", "white": "#e5e5e5",
    "brightblack": "#666666", "brightred": "#f14c4c", "brightgreen": "#23d18b",
    "brightbrown": "#f5f543", "brightblue": "#3b8eea", "brightmagenta": "#d670d6",
    "brightcyan": "#29b8db", "brightwhite": "#ffffff",
}
DEFAULT_FG, DEFAULT_BG = "#d4d4d4", "#1e1e1e"


class TermScreen:
    """pyte Screen + Stream with a bytes interface."""

    def __init__(self, cols: int = 80, rows: int = 24, history: int = 2000):
        self.screen = pyte.HistoryScreen(cols, rows, history=history, ratio=0.5)
        self.stream = pyte.ByteStream(self.screen)

    def feed(self, data: bytes) -> None:
        self.stream.feed(data)

    def resize(self, cols: int, rows: int) -> None:
        self.screen.resize(rows, cols)

    @property
    def size(self) -> tuple[int, int]:
        return self.screen.columns, self.screen.lines

    def text(self) -> str:
        return "\n".join(l.rstrip() for l in self.screen.display)

    def line_text(self, y: int) -> str:
        return self.screen.display[y]


def color_of(name: str, default: str) -> str:
    if not name or name == "default":
        return default
    if name in _ANSI:
        return _ANSI[name]
    if len(name) == 6:
        try:
            int(name, 16)
            return "#" + name
        except ValueError:
            pass
    return default


def key_bytes(key: int, mods, text: str) -> Optional[bytes]:
    """Map a Qt key press to terminal bytes (None = not handled)."""
    ctrl = bool(mods & Qt.KeyboardModifier.ControlModifier)
    alt = bool(mods & Qt.KeyboardModifier.AltModifier)
    special = {
        Qt.Key.Key_Return: b"\r", Qt.Key.Key_Enter: b"\r", Qt.Key.Key_Backspace: b"\x7f",
        Qt.Key.Key_Tab: b"\t", Qt.Key.Key_Backtab: b"\x1b[Z", Qt.Key.Key_Escape: b"\x1b",
        Qt.Key.Key_Up: b"\x1b[A", Qt.Key.Key_Down: b"\x1b[B",
        Qt.Key.Key_Right: b"\x1b[C", Qt.Key.Key_Left: b"\x1b[D",
        Qt.Key.Key_Home: b"\x1b[H", Qt.Key.Key_End: b"\x1b[F",
        Qt.Key.Key_PageUp: b"\x1b[5~", Qt.Key.Key_PageDown: b"\x1b[6~",
        Qt.Key.Key_Insert: b"\x1b[2~", Qt.Key.Key_Delete: b"\x1b[3~",
        Qt.Key.Key_F1: b"\x1bOP", Qt.Key.Key_F2: b"\x1bOQ", Qt.Key.Key_F3: b"\x1bOR",
        Qt.Key.Key_F4: b"\x1bOS", Qt.Key.Key_F5: b"\x1b[15~", Qt.Key.Key_F6: b"\x1b[17~",
        Qt.Key.Key_F7: b"\x1b[18~", Qt.Key.Key_F8: b"\x1b[19~", Qt.Key.Key_F9: b"\x1b[20~",
        Qt.Key.Key_F10: b"\x1b[21~", Qt.Key.Key_F11: b"\x1b[23~", Qt.Key.Key_F12: b"\x1b[24~",
    }
    if key in special:
        return (b"\x1b" + special[key]) if alt and key not in (Qt.Key.Key_Escape,) else special[key]
    if ctrl and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
        return bytes([key - Qt.Key.Key_A + 1])
    if ctrl and key == Qt.Key.Key_Space:
        return b"\x00"
    if ctrl and key == Qt.Key.Key_BracketLeft:
        return b"\x1b"
    if text and not ctrl:
        b = text.encode("utf-8")
        return (b"\x1b" + b) if alt else b
    return None


class TerminalView(QtWidgets.QWidget):
    """Grid renderer + keyboard/mouse handling for a TermScreen."""

    inputReady = QtCore.pyqtSignal(bytes)
    sizeChanged = QtCore.pyqtSignal(int, int)  # cols, rows

    def __init__(self, parent=None):
        super().__init__(parent)
        self.term = TermScreen()
        f = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        f.setPointSize(11)
        self.setFont(f)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_InputMethodEnabled, True)
        self.setCursor(Qt.CursorShape.IBeamCursor)
        self._sel: Optional[tuple[tuple[int, int], tuple[int, int]]] = None
        self._ctrl_latched = False
        self._recalc_metrics()

    # ---------------------------------------------------------------- layout
    def _recalc_metrics(self):
        fm = QtGui.QFontMetrics(self.font())
        self.cw = max(1, fm.horizontalAdvance("M"))
        self.ch = max(1, fm.height())
        self._ascent = fm.ascent()

    def sizeHint(self):
        return QtCore.QSize(self.cw * 80, self.ch * 24)

    def resizeEvent(self, ev):
        cols = max(10, self.width() // self.cw)
        rows = max(3, self.height() // self.ch)
        if (cols, rows) != self.term.size:
            self.term.resize(cols, rows)
            self.sizeChanged.emit(cols, rows)
        super().resizeEvent(ev)

    def feed(self, data: bytes):
        self.term.feed(data)
        self.update()

    def latch_ctrl(self, on: bool):
        self._ctrl_latched = on

    # ----------------------------------------------------------------- paint
    def paintEvent(self, ev):
        p = QtGui.QPainter(self)
        p.fillRect(self.rect(), QtGui.QColor(DEFAULT_BG))
        scr = self.term.screen
        font = self.font()
        bold = QtGui.QFont(font)
        bold.setBold(True)
        sel = self._norm_sel()
        for y in range(scr.lines):
            row = scr.buffer[y]
            x = 0
            while x < scr.columns:
                c = row[x]
                fg = color_of(c.fg, DEFAULT_FG)
                bg = color_of(c.bg, DEFAULT_BG)
                if c.reverse:
                    fg, bg = bg, fg
                if sel and self._in_sel(x, y, sel):
                    fg, bg = DEFAULT_BG, "#9cc2ff"
                rect = QtCore.QRect(x * self.cw, y * self.ch, self.cw, self.ch)
                if bg != DEFAULT_BG:
                    p.fillRect(rect, QtGui.QColor(bg))
                if c.data.strip():
                    p.setFont(bold if c.bold else font)
                    p.setPen(QtGui.QColor(fg))
                    p.drawText(x * self.cw, y * self.ch + self._ascent, c.data)
                if c.underscore:
                    p.setPen(QtGui.QColor(fg))
                    p.drawLine(rect.bottomLeft(), rect.bottomRight())
                x += 1
        if not scr.cursor.hidden and self.hasFocus():
            r = QtCore.QRect(scr.cursor.x * self.cw, scr.cursor.y * self.ch, self.cw, self.ch)
            p.fillRect(r, QtGui.QColor(255, 255, 255, 120))
        p.end()

    # ------------------------------------------------------------- selection
    def _cell(self, pos) -> tuple[int, int]:
        return (min(max(0, pos.x() // self.cw), self.term.screen.columns - 1),
                min(max(0, pos.y() // self.ch), self.term.screen.lines - 1))

    def _norm_sel(self):
        if not self._sel:
            return None
        a, b = self._sel
        return (a, b) if (a[1], a[0]) <= (b[1], b[0]) else (b, a)

    @staticmethod
    def _in_sel(x, y, sel) -> bool:
        (x0, y0), (x1, y1) = sel
        if y < y0 or y > y1:
            return False
        if y0 == y1:
            return x0 <= x <= x1
        if y == y0:
            return x >= x0
        if y == y1:
            return x <= x1
        return True

    def mousePressEvent(self, ev):
        self.setFocus()
        if ev.button() == Qt.MouseButton.LeftButton:
            c = self._cell(ev.position().toPoint())
            self._sel = (c, c)
            self.update()
        elif ev.button() == Qt.MouseButton.MiddleButton:
            self.paste(QtWidgets.QApplication.clipboard().text(QtGui.QClipboard.Mode.Selection))

    def mouseMoveEvent(self, ev):
        if self._sel and ev.buttons() & Qt.MouseButton.LeftButton:
            self._sel = (self._sel[0], self._cell(ev.position().toPoint()))
            self.update()

    def mouseReleaseEvent(self, ev):
        if self._sel and self._sel[0] == self._sel[1]:
            self._sel = None
        elif self._sel:
            QtWidgets.QApplication.clipboard().setText(
                self.selected_text(), QtGui.QClipboard.Mode.Selection)
        self.update()

    def selected_text(self) -> str:
        sel = self._norm_sel()
        if not sel:
            return ""
        (x0, y0), (x1, y1) = sel
        lines = []
        for y in range(y0, y1 + 1):
            t = self.term.line_text(y)
            a = x0 if y == y0 else 0
            b = x1 + 1 if y == y1 else len(t)
            lines.append(t[a:b].rstrip())
        return "\n".join(lines)

    def copy(self):
        txt = self.selected_text() or self.term.text()
        QtWidgets.QApplication.clipboard().setText(txt)

    def paste(self, text: str):
        if text:
            self.inputReady.emit(text.replace("\r\n", "\n").replace("\n", "\r").encode("utf-8"))

    # -------------------------------------------------------------- keyboard
    def focusNextPrevChild(self, nxt):  # let Tab reach the shell
        return False

    def keyPressEvent(self, ev):
        key, mods = ev.key(), ev.modifiers()
        ctrl_shift = (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
        if mods & ctrl_shift == ctrl_shift and key == Qt.Key.Key_C:
            self.copy()
            return
        if (mods & ctrl_shift == ctrl_shift and key == Qt.Key.Key_V) or \
                (mods & Qt.KeyboardModifier.ShiftModifier and key == Qt.Key.Key_Insert):
            self.paste(QtWidgets.QApplication.clipboard().text())
            return
        if self._ctrl_latched:
            mods |= Qt.KeyboardModifier.ControlModifier
            self._ctrl_latched = False
        data = key_bytes(key, mods, ev.text())
        if data is not None:
            self._sel = None
            self.inputReady.emit(data)
            ev.accept()
        else:
            super().keyPressEvent(ev)

    def inputMethodEvent(self, ev):
        if ev.commitString():
            self.inputReady.emit(ev.commitString().encode("utf-8"))


class PtyTerminalTab(QtWidgets.QWidget):
    """The tab: extra-keys row + TerminalView + channel pump thread."""

    _data = QtCore.pyqtSignal(bytes)
    _closed = QtCore.pyqtSignal()
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh_client, parent=None):
        super().__init__(parent)
        self.ssh = ssh_client
        self.chan = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        root = QtWidgets.QVBoxLayout(self)
        row = QtWidgets.QHBoxLayout()
        self.btn_start = QtWidgets.QPushButton("Reconnect shell")
        self.btn_ctrl = QtWidgets.QPushButton("Ctrl")
        self.btn_ctrl.setCheckable(True)
        row.addWidget(self.btn_start)
        row.addWidget(self.btn_ctrl)
        for label, data in (("Tab", b"\t"), ("Esc", b"\x1b"), ("↑", b"\x1b[A"), ("↓", b"\x1b[B"),
                            ("←", b"\x1b[D"), ("→", b"\x1b[C"), ("Ctrl-C", b"\x03"), ("Ctrl-D", b"\x04")):
            b = QtWidgets.QPushButton(label)
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            b.clicked.connect(lambda _=False, d=data: self.send(d))
            row.addWidget(b)
        row.addStretch(1)
        self.btn_copy = QtWidgets.QPushButton("Copy")
        self.btn_paste = QtWidgets.QPushButton("Paste")
        row.addWidget(self.btn_copy)
        row.addWidget(self.btn_paste)
        root.addLayout(row)
        self.view = TerminalView()
        root.addWidget(self.view, 1)

        self.view.inputReady.connect(self.send)
        self.view.sizeChanged.connect(self._resize)
        self._data.connect(self.view.feed)
        self._closed.connect(self._on_closed)
        self.btn_start.clicked.connect(self.start)
        self.btn_ctrl.toggled.connect(self.view.latch_ctrl)
        self.btn_copy.clicked.connect(self.view.copy)
        self.btn_paste.clicked.connect(lambda: self.view.paste(QtWidgets.QApplication.clipboard().text()))
        for b in (self.btn_start, self.btn_ctrl, self.btn_copy, self.btn_paste):
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)

    # ----------------------------------------------------------------- shell
    @property
    def running(self) -> bool:
        return self.chan is not None and self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running or not getattr(self.ssh, "connected", False):
            return
        cols, rows = self.view.term.size
        self._stop = threading.Event()
        stop = self._stop
        try:
            chan = self.ssh.open_shell(width=cols, height=rows)
        except Exception as e:  # noqa: BLE001
            self.log.emit(f"[ERROR] terminal: {e}")
            return
        self.chan = chan
        self.view.term = TermScreen(cols, rows)

        def pump():
            try:
                while not stop.is_set():
                    if chan.recv_ready():
                        d = chan.recv(65536)
                        if not d:
                            break
                        self._data.emit(d)
                    elif chan.closed or chan.exit_status_ready():
                        break
                    else:
                        stop.wait(0.02)
            except Exception:  # noqa: BLE001
                pass
            if not stop.is_set():
                self._closed.emit()

        self._thread = threading.Thread(target=pump, daemon=True)
        self._thread.start()
        self.view.setFocus()

    def stop(self):
        self._stop.set()
        if self.chan is not None:
            try:
                self.chan.close()
            except Exception:  # noqa: BLE001
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.chan = None
        self._thread = None

    def _on_closed(self):
        self.chan = None
        self.view.feed(b"\r\n[shell closed]\r\n")

    def send(self, data: bytes):
        if self.chan is None:
            return
        try:
            self.chan.send(data)
        except Exception:  # noqa: BLE001
            self._on_closed()

    def _resize(self, cols: int, rows: int):
        if self.chan is not None:
            try:
                self.chan.resize_pty(width=cols, height=rows)
            except Exception:  # noqa: BLE001
                pass
