import sys

from pwnman.pwnman.version import __version__


def main():
    # Handled before importing Qt so it works on headless machines and makes a
    # cheap smoke test for freshly built binaries / installed packages.
    if "--version" in sys.argv[1:] or "-V" in sys.argv[1:]:
        print(f"qpwnagotchi {__version__}")
        return 0

    import argparse
    ap = argparse.ArgumentParser(prog="qpwnagotchi")
    ap.add_argument("--profile", help="select this saved profile at startup")
    ap.add_argument("--connect", action="store_true", help="connect right away")
    ap.add_argument("--version", "-V", action="store_true")
    args, qt_args = ap.parse_known_args()
    sys.argv = [sys.argv[0]] + qt_args

    from PyQt6 import QtWidgets
    from pwnman.pwnman.ui_main import MainWindow
    from pwnman.pwnman.resources import app_icon

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("qPwnagotchi")
    app.setApplicationDisplayName("qPwnagotchi")
    app.setOrganizationName("qPwnagotchi")
    app.setDesktopFileName("qpwnagotchi")
    from pwnman.pwnman import theme
    theme.apply(app, theme.get_mode())
    theme.watch_system(app)
    icon = app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)
    w = MainWindow(profile=args.profile, connect=args.connect)
    w.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
