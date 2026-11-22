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


_active: set = set()


def shutdown_threads(timeout_ms: int = 3000) -> None:
    """Wait for in-flight workers (call on window close). A QThread destroyed
    while running aborts the process, so closing mid-operation must join."""
    for t in list(_active):
        try:
            t.quit()
            t.wait(timeout_ms)
        except RuntimeError:  # already deleted
            pass


def _alive(obj) -> bool:
    try:
        from PyQt6 import sip
        return not sip.isdeleted(obj)
    except Exception:  # noqa: BLE001
        return True


def run_in_thread(parent: QtWidgets.QWidget, fn, cb, *args, **kwargs):
    # Deliberately NOT parented to the widget: destroying the window must not
    # destroy a QThread that is still running or about to deliver its result.
    thread = QtCore.QThread()
    worker = Worker(fn, *args, **kwargs)
    worker.moveToThread(thread)
    _active.add(thread)

    def done(res, err):
        thread.quit()  # ask the event loop to exit; cleanup happens on finished
        if _alive(parent):  # window may have been closed meanwhile
            cb(res, err)

    def cleanup():
        # Runs only once the thread has really stopped. Never block the GUI
        # thread with wait() here and never drop the QThread while it runs.
        _active.discard(thread)
        worker.deleteLater()
        thread.deleteLater()

    worker.finished.connect(done)
    thread.finished.connect(cleanup)
    thread.started.connect(worker.run)
    thread.start()
    return thread


def quote_bash(script: str) -> str:
    """Single-quote a string for safe use as one bash -lc argument."""
    return "'" + script.replace("'", "'\"'\"'") + "'"


def cd_command(path: str) -> str:
    """A bash ``cd`` that is safe for any path and still honours ``~``."""
    path = (path or "").strip() or "/"
    if path == "~":
        return 'cd "$HOME"'
    if path.startswith("~/"):
        return 'cd "$HOME"/' + quote_bash(path[2:])
    return "cd " + quote_bash(path)


# Alias kept for call sites that imported the export tab's name.
quote_sh = quote_bash
