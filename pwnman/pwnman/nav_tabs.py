"""Left navigation rail + stacked pages; API-compatible with QTabWidget."""
from __future__ import annotations

from PyQt6 import QtCore, QtWidgets


class NavTabs(QtWidgets.QWidget):
    currentChanged = QtCore.pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.nav = QtWidgets.QListWidget()
        self.nav.setFixedWidth(150)
        self.nav.setSpacing(1)
        self.nav.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.nav.setAccessibleName("Sections")
        self.stack = QtWidgets.QStackedWidget()
        lay.addWidget(self.nav)
        lay.addWidget(self.stack, 1)
        self.nav.currentRowChanged.connect(self._row)

    def _row(self, row: int):
        if row >= 0:
            self.stack.setCurrentIndex(row)
            self.currentChanged.emit(row)

    # QTabWidget-compatible surface
    def addTab(self, widget: QtWidgets.QWidget, label: str) -> int:
        self.stack.addWidget(widget)
        self.nav.addItem(label)
        return self.stack.count() - 1

    def count(self) -> int:
        return self.stack.count()

    def widget(self, i: int):
        return self.stack.widget(i)

    def tabText(self, i: int) -> str:
        it = self.nav.item(i)
        return it.text() if it else ""

    def currentIndex(self) -> int:
        return self.stack.currentIndex()

    def setCurrentIndex(self, i: int) -> None:
        self.nav.setCurrentRow(i)
