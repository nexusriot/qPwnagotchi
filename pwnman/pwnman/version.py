"""Single source of truth for the application version.

scripts/version.sh reads ``__version__`` from this file, so the GUI, the
PyInstaller binary and the .deb/.rpm/installer all agree.
"""
__version__ = "0.4.0"
