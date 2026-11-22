#!/usr/bin/env bash
# Hermetic E2E: builds a fake Pwnagotchi (sshd + REST API) and a GUI test
# runner, wires them on an --internal Docker network (no internet, no host
# ports) and runs the whole pytest suite (unit + tests/e2e).
set -euo pipefail
cd "$(dirname "$0")/.."

DOCKER="${DOCKER:-docker}"
ID="qpwn-e2e-$$"
NET="$ID"
TARGET="$ID-target"
[ -n "${PYTEST_ARGS+x}" ] || PYTEST_ARGS="-v tests"

cleanup() {
    $DOCKER rm -f "$TARGET" >/dev/null 2>&1 || true
    $DOCKER network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo ">> building images"
$DOCKER build -q -t qpwnagotchi-e2e-target docker/e2e/target >/dev/null
$DOCKER build -q -t qpwnagotchi-e2e-runner -f docker/e2e/Dockerfile.runner . >/dev/null

echo ">> starting isolated network + fake device"
$DOCKER network create --internal "$NET" >/dev/null
$DOCKER run -d --name "$TARGET" --network "$NET" --network-alias target --hostname pwnagotchi-e2e \
    qpwnagotchi-e2e-target >/dev/null

echo ">> waiting for sshd"
for i in $(seq 1 40); do
    if $DOCKER exec "$TARGET" sh -c 'ss -ltn | grep -q ":22 " && ss -ltn | grep -q ":8080 "' 2>/dev/null; then
        break
    fi
    sleep 0.5
    [ "$i" = 40 ] && { $DOCKER logs "$TARGET"; echo "target did not come up" >&2; exit 1; }
done

echo ">> running tests"
set +e
# shellcheck disable=SC2086
$DOCKER run --rm --network "$NET" --shm-size=512m \
    -e E2E_HOST=target -e E2E_TARGET_CONTAINER="$TARGET" \
    qpwnagotchi-e2e-runner python -m pytest $PYTEST_ARGS
rc=$?
set -e
[ $rc -ne 0 ] && { echo ">> target logs:"; $DOCKER logs --tail 30 "$TARGET" 2>&1 || true; }
exit $rc
