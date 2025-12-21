import sys
from PyQt6 import QtWidgets

from pwnman.pwnman.ui_main import MainWindow


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
