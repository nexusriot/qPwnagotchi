#!/usr/bin/env bash
# Build a Debian package wrapping the PyInstaller binary produced by
# scripts/build.sh. Uses plain dpkg-deb so no extra build deps are needed.
#
# Output: dist/qpwnagotchi_<version>_<arch>.deb
#
# Works on: amd64 (desktop/laptop), arm64 (uConsole CM4/A06, RPi 4/5),
#           armhf (uConsole RPi older, RPi 3 32-bit), riscv64 (uConsole R-01).
# The .deb is arch-tagged for whatever the host produced.
set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="${APP_NAME:-qpwnagotchi}"
VERSION="${VERSION:-0.1.0}"
# Strip a leading "v" so 0.1.0 not v0.1.0 (Debian dislikes letters at the front).
VERSION="${VERSION#v}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"

BIN="dist/${APP_NAME}-${VERSION}-${ARCH}"
if [ ! -f "$BIN" ]; then
    echo "Binary $BIN not found. Run 'make build' first." >&2
    exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Layout
install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/doc/${APP_NAME}"

install -m 0755 "$BIN" "$STAGE/usr/bin/${APP_NAME}"
install -m 0644 packaging/qpwnagotchi.desktop "$STAGE/usr/share/applications/${APP_NAME}.desktop"
install -m 0644 README.md "$STAGE/usr/share/doc/${APP_NAME}/README.md"

# Icons: install into hicolor theme so the .desktop "Icon=qpwnagotchi" resolves.
for SIZE in 16 24 32 48 64 128 256 512; do
    SRC="packaging/qpwnagotchi-${SIZE}.png"
    if [ -f "$SRC" ]; then
        install -d "$STAGE/usr/share/icons/hicolor/${SIZE}x${SIZE}/apps"
        install -m 0644 "$SRC" \
            "$STAGE/usr/share/icons/hicolor/${SIZE}x${SIZE}/apps/${APP_NAME}.png"
    fi
done
if [ -f packaging/qpwnagotchi.svg ]; then
    install -d "$STAGE/usr/share/icons/hicolor/scalable/apps"
    install -m 0644 packaging/qpwnagotchi.svg \
        "$STAGE/usr/share/icons/hicolor/scalable/apps/${APP_NAME}.svg"
fi

# Refresh the icon cache after install/remove so the menu picks up the icon
# without requiring a logout. gtk-update-icon-cache is in libgtk-3-bin which
# is present on every Mint/Ubuntu desktop install.
install -d "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -q -f /usr/share/icons/hicolor || true
fi
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"
cp "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/postrm"

# control
INSTALLED_SIZE=$(du -sk "$STAGE/usr" | cut -f1)
sed -e "s/@VERSION@/${VERSION}/g" \
    -e "s/@ARCH@/${ARCH}/g" \
    -e "s/@SIZE@/${INSTALLED_SIZE}/g" \
    packaging/debian/control.in > "$STAGE/DEBIAN/control"

# Build
mkdir -p dist
DEB="dist/${APP_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB"

echo
echo "Built: $DEB"
dpkg-deb -I "$DEB" || true
