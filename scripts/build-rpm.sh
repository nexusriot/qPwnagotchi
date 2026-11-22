#!/usr/bin/env bash
# Build an RPM wrapping the PyInstaller binary from scripts/build.sh.
# Works on Debian-based hosts/containers too (needs the `rpm` package).
# Output: dist/qpwnagotchi-<version>-1.<rpmarch>.rpm
set -euo pipefail
cd "$(dirname "$0")/.."

APP_NAME="${APP_NAME:-qpwnagotchi}"
VERSION="${VERSION:-$(./scripts/version.sh)}"
VERSION="${VERSION#v}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"
case "$ARCH" in
    amd64|x86_64)  RPMARCH=x86_64 ;;
    arm64|aarch64) RPMARCH=aarch64 ;;
    armhf)         RPMARCH=armv7hl ;;
    *)             RPMARCH="$ARCH" ;;
esac
# RPM versions may not contain '-' (and '~'/'+' sort oddly); keep it simple.
RPMVERSION="${VERSION//-/_}"

BIN="$PWD/dist/${APP_NAME}-${VERSION}-${ARCH}"
[ -f "$BIN" ] || { echo "Binary $BIN not found. Run build.sh first." >&2; exit 1; }

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
sed -e "s|@RPMVERSION@|${RPMVERSION}|g" -e "s|@RPMARCH@|${RPMARCH}|g" \
    -e "s|@BIN@|${BIN}|g" -e "s|@SRC@|${PWD}|g" \
    packaging/rpm/qpwnagotchi.spec.in > "$TOP/SPECS/${APP_NAME}.spec"

rpmbuild -bb --target "${RPMARCH}-linux" \
    --define "_topdir $TOP" \
    --define "_binary_payload w9.gzdio" \
    --define "_build_id_links none" \
    "$TOP/SPECS/${APP_NAME}.spec"

mkdir -p dist
cp "$TOP"/RPMS/*/*.rpm dist/
echo; ls -la dist/*.rpm
rpm -qpi dist/*"${RPMARCH}.rpm" | head -12 || true
