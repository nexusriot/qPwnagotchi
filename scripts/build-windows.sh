#!/usr/bin/env bash
# Windows build, meant to run inside docker/Dockerfile.windows (wine + python
# + NSIS). Produces:
#   dist/qpwnagotchi-<ver>-windows-x64.zip       portable (onedir)
#   dist/qpwnagotchi-<ver>-windows-x64-setup.exe NSIS installer
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(./scripts/version.sh)}"
VERSION="${VERSION#v}"
# NSIS wants a strict numeric X.X.X.X product version.
NUMVER="$(echo "$VERSION" | sed -E 's/^([0-9]+)\.([0-9]+)\.([0-9]+).*/\1.\2.\3.0/')"

export WINEDEBUG=-all

# onedir (not onefile): QtWebEngine is ~300 MB; onefile would unpack it on
# every launch. ';' is the --add-data separator on Windows.
wine pyinstaller --noconfirm --clean --windowed --onedir \
    --name qpwnagotchi \
    --icon packaging/qpwnagotchi.ico \
    --add-data "packaging/qpwnagotchi.svg;packaging" \
    --add-data "packaging/qpwnagotchi-256.png;packaging" \
    --add-data "packaging/qpwnagotchi-128.png;packaging" \
    --add-data "packaging/qpwnagotchi-64.png;packaging" \
    --add-data "packaging/qpwnagotchi-48.png;packaging" \
    --add-data "packaging/qpwnagotchi-32.png;packaging" \
    --add-data "packaging/qpwnagotchi-16.png;packaging" \
    --hidden-import PyQt6.QtSvg \
    --copy-metadata keyring \
    --collect-submodules keyring.backends \
    --hidden-import zeroconf \
    app.py

test -f dist/qpwnagotchi/qpwnagotchi.exe

( cd dist && zip -qr "qpwnagotchi-${VERSION}-windows-x64.zip" qpwnagotchi )

makensis -V2 \
    -DVERSION="${VERSION}" -DNUMVERSION="${NUMVER}" \
    -DSRCDIR="$PWD/dist/qpwnagotchi" -DICON="$PWD/packaging/qpwnagotchi.ico" \
    -DOUTFILE="$PWD/dist/qpwnagotchi-${VERSION}-windows-x64-setup.exe" \
    packaging/windows/installer.nsi

rm -rf dist/qpwnagotchi build
ls -la dist
