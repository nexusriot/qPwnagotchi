#!/usr/bin/env bash
# Build a single-file PyInstaller binary for the host architecture.
#
# PyInstaller does NOT cross-compile. The output binary is for whichever
# arch this script runs on. To get a binary for uConsole (arm64/armhf),
# run this *on the uConsole*, or inside a matching docker/qemu container,
# e.g.:
#
#   docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src \
#       debian:bookworm bash -lc \
#       'apt-get update && apt-get install -y python3-venv python3-pip make && make build'
#
# Output: dist/qpwnagotchi-<version>-<arch>
set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="${APP_NAME:-qpwnagotchi}"
VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"

VENV="${VENV:-.venv}"
PYI="$VENV/bin/pyinstaller"

if [ ! -x "$PYI" ]; then
    echo "PyInstaller not found in $VENV. Run 'make venv' first." >&2
    exit 1
fi

# Build. --onefile makes one self-contained binary; --windowed hides the
# console window (irrelevant on Linux but matches existing app.spec).
"$PYI" \
    --noconfirm \
    --clean \
    --onefile \
    --windowed \
    --name "${APP_NAME}" \
    app.py

# Rename to include version + arch so multiple builds can coexist.
OUT="dist/${APP_NAME}-${VERSION}-${ARCH}"
mv -f "dist/${APP_NAME}" "$OUT"

echo
echo "Built: $OUT"
file "$OUT" || true
