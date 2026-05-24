#!/usr/bin/env bash
# Print a Debian-compatible version string.
# - If HEAD has an exact tag like vX.Y.Z, use X.Y.Z.
# - Otherwise, "0.1.0+git<short-sha>" (plus ".dirty" if the worktree is dirty).
# - If git isn't available at all, "0.1.0".
set -eu

cd "$(dirname "$0")/.."

if tag=$(git describe --tags --exact-match 2>/dev/null); then
    echo "${tag#v}"
    exit 0
fi

if sha=$(git rev-parse --short HEAD 2>/dev/null); then
    dirty=""
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
        dirty=".dirty"
    fi
    echo "0.1.0+git${sha}${dirty}"
    exit 0
fi

echo "0.1.0"
