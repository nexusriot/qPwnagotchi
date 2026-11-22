#!/usr/bin/env bash
# Install the freshly built amd64 .deb into a clean container and make sure the
# bundled binary actually starts (offscreen). Network is disabled at run time.
set -euo pipefail
cd "$(dirname "$0")/.."
DOCKER="${DOCKER:-docker}"
DEB="$(ls -t dist/qpwnagotchi_*_amd64.deb 2>/dev/null | head -n1)"
[ -n "$DEB" ] || { echo "no dist/*_amd64.deb; run 'make linux-amd64' first" >&2; exit 1; }

$DOCKER build -q -t qpwnagotchi-pkgtest -f docker/Dockerfile.pkgtest docker >/dev/null
$DOCKER run --rm --network none -v "$PWD/$DEB:/pkg/app.deb:ro" \
    -e QT_QPA_PLATFORM=offscreen \
    -e QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu --disable-dev-shm-usage" \
    --shm-size=512m qpwnagotchi-pkgtest bash -euc '
        dpkg -i /pkg/app.deb
        test -x /usr/bin/qpwnagotchi
        test -f /usr/share/applications/qpwnagotchi.desktop
        test -f /usr/share/icons/hicolor/256x256/apps/qpwnagotchi.png
        echo "--version: $(qpwnagotchi --version)"
        export HOME=/tmp/h XDG_CONFIG_HOME=/tmp/h/.config; mkdir -p $HOME
        # GUI must stay alive for 12s (exit 124 = still running = success)
        set +e; timeout 12 qpwnagotchi; rc=$?; set -e
        [ "$rc" = 124 ] || { echo "GUI exited early with rc=$rc"; exit 1; }
        echo "package smoke test OK"
        dpkg -r qpwnagotchi
        test ! -e /usr/bin/qpwnagotchi
    '
