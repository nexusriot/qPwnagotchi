from __future__ import annotations

from PyQt6 import QtCore, QtWidgets


class Worker(QtCore.QObject):
    finished = QtCore.pyqtSignal(object, object)  # (result, error)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    @QtCore.pyqtSlot()
    def run(self):
        try:
            self.finished.emit(self._fn(*self._args, **self._kwargs), None)
        except Exception as e:  # noqa: BLE001 - surfaced to the UI callback
            self.finished.emit(None, e)


def run_in_thread(parent: QtWidgets.QWidget, fn, cb, *args, **kwargs):
    thread = QtCore.QThread(parent)
    worker = Worker(fn, *args, **kwargs)
    worker.moveToThread(thread)

    def done(res, err):
        thread.quit()
        thread.wait(1000)
        worker.deleteLater()
        thread.deleteLater()
        cb(res, err)

    worker.finished.connect(done)
    thread.started.connect(worker.run)
    thread.start()
    return thread


def quote_bash(script: str) -> str:
    """Single-quote a string for safe use as one bash -lc argument."""
    return "'" + script.replace("'", "'\"'\"'") + "'"


# Alias kept for call sites that imported the export tab's name.
quote_sh = quote_bash
