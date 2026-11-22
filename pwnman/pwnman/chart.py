"""A small dependency-free line chart (QPainter), theme-aware via palette()."""
from __future__ import annotations

import time
from statistics import median
from typing import Optional

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman.metrics_store import nice_ticks

ML, MR, MT, MB = 46, 12, 8, 22


def split_segments(points, gap_factor: float = 3.0, min_gap: float = 120.0):
    """Split at gaps (device offline / app closed) so no line crosses them."""
    if len(points) < 2:
        return [list(points)] if points else []
    dts = [b[0] - a[0] for a, b in zip(points, points[1:], strict=False)]
    limit = max(min_gap, gap_factor * median(dts))
    segs, cur = [], [points[0]]
    for prev, p in zip(points, points[1:], strict=False):
        if p[0] - prev[0] > limit:
            segs.append(cur)
            cur = []
        cur.append(p)
    segs.append(cur)
    return segs


def fmt_time(ts: float, span: float) -> str:
    return time.strftime("%H:%M" if span <= 86400 * 1.5 else "%m-%d %H:%M", time.localtime(ts))


class LineChart(QtWidgets.QWidget):
    def __init__(self, title: str, unit: str = "", color_index: int = 0,
                 fixed_range: Optional[tuple[float, float]] = None, decimals: int = 1, parent=None):
        super().__init__(parent)
        self.title, self.unit, self.color_index = title, unit, color_index
        self.fixed_range, self.decimals = fixed_range, decimals
        self.points: list[tuple[float, float]] = []
        now = time.time()
        self.t0, self.t1 = now - 3600, now  # sane range before the first set_data()
        self.setMinimumSize(260, 150)
        self.setMouseTracking(True)
        self._hover: Optional[tuple[float, float]] = None
        self.summary = ""

    def set_data(self, points, t0: float, t1: float, summary: str = ""):
        self.points, self.t0, self.t1, self.summary = list(points), t0, max(t1, t0 + 1), summary
        self._hover = None
        self.update()

    # ---------------------------------------------------------------- mapping
    def _y_range(self) -> tuple[float, float]:
        if self.fixed_range:
            return self.fixed_range
        if not self.points:
            return 0.0, 1.0
        lo = min(p[1] for p in self.points)
        hi = max(p[1] for p in self.points)
        pad = (hi - lo) * 0.1 or max(1.0, abs(hi) * 0.1)
        return lo - pad, hi + pad

    def _plot_rect(self) -> QtCore.QRectF:
        return QtCore.QRectF(ML, MT + 16, max(10, self.width() - ML - MR),
                             max(10, self.height() - MT - MB - 16))

    def _map(self, t: float, v: float, r: QtCore.QRectF, lo: float, hi: float):
        x = r.left() + (t - self.t0) / ((self.t1 - self.t0) or 1.0) * r.width()
        y = r.bottom() - (v - lo) / ((hi - lo) or 1) * r.height()
        return QtCore.QPointF(x, y)

    # ------------------------------------------------------------------ paint
    def paintEvent(self, _ev):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        pal = self.palette()
        R = QtGui.QPalette.ColorRole
        text, grid = pal.color(R.WindowText), pal.color(R.Mid)
        p.fillRect(self.rect(), pal.color(R.Base))
        p.setPen(text)
        f = p.font()
        f.setBold(True)
        p.setFont(f)
        p.drawText(QtCore.QRectF(ML, 2, self.width() - ML - MR, 16),
                   QtCore.Qt.AlignmentFlag.AlignLeft, self.title)
        f.setBold(False)
        f.setPointSizeF(max(7.0, f.pointSizeF() - 1))
        p.setFont(f)
        p.setPen(pal.color(R.PlaceholderText))
        p.drawText(QtCore.QRectF(ML, 2, self.width() - ML - MR, 16),
                   QtCore.Qt.AlignmentFlag.AlignRight, self.summary)

        r = self._plot_rect()
        lo, hi = self._y_range()
        ticks = [t for t in nice_ticks(lo, hi, 4) if lo <= t <= hi] or [lo, hi]
        p.setFont(f)
        for t in ticks:
            y = self._map(self.t0, t, r, lo, hi).y()
            p.setPen(QtGui.QPen(grid, 1, QtCore.Qt.PenStyle.DotLine))
            p.drawLine(QtCore.QPointF(r.left(), y), QtCore.QPointF(r.right(), y))
            p.setPen(text)
            p.drawText(QtCore.QRectF(0, y - 8, ML - 4, 16),
                       QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignVCenter,
                       f"{t:g}")
        span = self.t1 - self.t0
        for i in range(5):
            t = self.t0 + span * i / 4
            x = r.left() + r.width() * i / 4
            p.setPen(text)
            al = (QtCore.Qt.AlignmentFlag.AlignLeft if i == 0 else
                  QtCore.Qt.AlignmentFlag.AlignRight if i == 4 else QtCore.Qt.AlignmentFlag.AlignHCenter)
            box = QtCore.QRectF(x - (0 if i == 0 else 60 if i == 4 else 30), r.bottom() + 3, 60, 16)
            if i == 4:
                box.moveLeft(x - 60)
            p.drawText(box, al, fmt_time(t, span))
        p.setPen(QtGui.QPen(grid, 1))
        p.drawRect(r)

        if not self.points:
            p.setPen(pal.color(R.PlaceholderText))
            p.drawText(r, QtCore.Qt.AlignmentFlag.AlignCenter, "no data in this range")
            return

        col = _series_color(self)
        p.setClipRect(r.adjusted(-1, -1, 1, 1))
        p.setPen(QtGui.QPen(col, 2, QtCore.Qt.PenStyle.SolidLine, QtCore.Qt.PenCapStyle.RoundCap,
                            QtCore.Qt.PenJoinStyle.RoundJoin))
        for seg in split_segments(self.points):
            pts = [self._map(t, v, r, lo, hi) for t, v in seg]
            if len(pts) == 1:
                p.setBrush(col)
                p.drawEllipse(pts[0], 2.5, 2.5)
            else:
                p.drawPolyline(QtGui.QPolygonF(pts))
        if self._hover:
            hp = self._map(*self._hover, r, lo, hi)
            p.setClipping(False)
            p.setPen(QtGui.QPen(text, 1, QtCore.Qt.PenStyle.DashLine))
            p.drawLine(QtCore.QPointF(hp.x(), r.top()), QtCore.QPointF(hp.x(), r.bottom()))
            p.setBrush(col)
            p.drawEllipse(hp, 4, 4)

    # ------------------------------------------------------------------ hover
    def mouseMoveEvent(self, ev):
        if not self.points:
            return
        r = self._plot_rect()
        x = ev.position().x()
        if not (r.left() <= x <= r.right()):
            self._hover = None
            self.update()
            return
        t = self.t0 + (x - r.left()) / (r.width() or 1.0) * (self.t1 - self.t0)
        self._hover = min(self.points, key=lambda pt: abs(pt[0] - t))
        QtWidgets.QToolTip.showText(
            ev.globalPosition().toPoint(),
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._hover[0]))}\n"
            f"{self.title}: {self._hover[1]:.{self.decimals}f}{self.unit}", self)
        self.update()

    def leaveEvent(self, _ev):
        self._hover = None
        self.update()


def _series_color(w: QtWidgets.QWidget) -> QtGui.QColor:
    from pwnman.pwnman import theme
    return theme.series_color(w.color_index, w)
