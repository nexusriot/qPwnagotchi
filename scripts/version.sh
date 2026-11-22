#!/usr/bin/env bash
# Print a Debian/RPM-compatible version string.
# Base version = __version__ in pwnman/pwnman/version.py (fallback 0.1.0).
# - If HEAD has an exact tag like vX.Y.Z, use X.Y.Z.
# - Otherwise, "<base>+git<short-sha>" (plus ".dirty" if the worktree is dirty).
# - If git isn't available at all, "<base>".
set -eu

cd "$(dirname "$0")/.."

base=$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' pwnman/pwnman/version.py 2>/dev/null | head -n1)
base="${base:-0.1.0}"

if tag=$(git describe --tags --exact-match 2>/dev/null); then
    echo "${tag#v}"
    exit 0
fi

if sha=$(git rev-parse --short HEAD 2>/dev/null); then
    dirty=""
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
        dirty=".dirty"
    fi
    echo "${base}+git${sha}${dirty}"
    exit 0
fi

echo "${base}"
