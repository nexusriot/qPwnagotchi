#!/usr/bin/env bash
# Build a single-file PyInstaller binary for the host (or container) arch.
#
# PyInstaller does NOT cross-compile; use `make linux-arm64` (docker + qemu)
# for other architectures.
#
# Output: dist/qpwnagotchi-<version>-<arch>
set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="${APP_NAME:-qpwnagotchi}"
VERSION="${VERSION:-$(./scripts/version.sh)}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"

VENV="${VENV:-.venv}"
PYI="$VENV/bin/pyinstaller"

if [ ! -x "$PYI" ]; then
    echo "PyInstaller not found in $VENV. Run 'make venv' first." >&2
    exit 1
fi

# Bundle the icons (resources.py looks in sys._MEIPASS/packaging) and the
# QtSvg plugin used for the SVG icon.
"$PYI" \
    --noconfirm \
    --clean \
    --onefile \
    --windowed \
    --name "${APP_NAME}" \
    --add-data "packaging/qpwnagotchi.svg:packaging" \
    --add-data "packaging/qpwnagotchi-256.png:packaging" \
    --add-data "packaging/qpwnagotchi-128.png:packaging" \
    --add-data "packaging/qpwnagotchi-64.png:packaging" \
    --add-data "packaging/qpwnagotchi-48.png:packaging" \
    --add-data "packaging/qpwnagotchi-32.png:packaging" \
    --add-data "packaging/qpwnagotchi-16.png:packaging" \
    --hidden-import PyQt6.QtSvg \
    --copy-metadata keyring \
    --collect-submodules keyring.backends \
    --hidden-import zeroconf \
    app.py

OUT="dist/${APP_NAME}-${VERSION#v}-${ARCH}"
mv -f "dist/${APP_NAME}" "$OUT"

echo
echo "Built: $OUT"
file "$OUT" || true
