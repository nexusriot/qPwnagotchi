import sys
from PyQt6 import QtGui, QtWidgets

from pwnman.pwnman.ui_main import MainWindow
from pwnman.pwnman.resources import app_icon


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("qPwnagotchi")
    app.setApplicationDisplayName("qPwnagotchi")
    app.setOrganizationName("qPwnagotchi")
    app.setDesktopFileName("qpwnagotchi")
    icon = app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
