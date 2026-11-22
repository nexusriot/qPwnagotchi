# qPwnagotchi — dev, build, package and test
#
# Dev:        make venv | run | test
# Host build: make build | deb | rpm
# Hermetic (Docker, no host toolchain needed):
#   make linux-amd64     binary + .deb + .rpm  (x86_64)
#   make linux-arm64     binary + .deb + .rpm  (aarch64, qemu-user emulation)
#   make windows         portable .zip + NSIS installer (Wine)
#   make dist-all        all of the above
#   make e2e             hermetic end-to-end functional test (fake Pwnagotchi over SSH)
#   make e2e-package     install the built amd64 .deb in a clean container and boot it
#
# arm64 on an x86 host needs binfmt/qemu registered once:
#   docker run --privileged --rm tonistiigi/binfmt --install arm64

PYTHON  ?= python3
VENV    ?= .venv
PIP     := $(VENV)/bin/pip
PY      := $(VENV)/bin/python

VERSION ?= $(shell ./scripts/version.sh 2>/dev/null || echo 0.2.0)
ARCH    := $(shell dpkg --print-architecture 2>/dev/null || uname -m)
DIST    ?= dist
DOCKER  ?= docker
SDE     ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

export VERSION ARCH
export APP_NAME := qpwnagotchi
export VENV

.PHONY: help all venv run test build deb rpm clean distclean \
        linux-amd64 linux-arm64 windows dist-all e2e e2e-package checksums lint

help:
	@sed -n '2,15p' Makefile
	@echo "Host arch: $(ARCH)   Version: $(VERSION)"

$(VENV)/bin/activate: requirements-dev.txt requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-dev.txt
	@touch $@

venv: $(VENV)/bin/activate

run: venv
	$(PY) app.py

test: venv
	QT_QPA_PLATFORM=offscreen $(PY) -m pytest -q tests --ignore=tests/e2e

build: venv
	./scripts/build.sh

deb: build
	./scripts/build-deb.sh

rpm: build
	./scripts/build-rpm.sh

all: deb

# amd64 builds on bookworm (glibc 2.36, runs on most distros). PyQt6's aarch64
# wheels are manylinux_2_39, so arm64 needs trixie (glibc 2.41) to build, and
# the resulting binary needs glibc >= 2.39 (Debian 13+, Ubuntu 24.04+).
define docker_build
	$(DOCKER) buildx build --platform $(1) --build-arg VERSION=$(VERSION) --build-arg SOURCE_DATE_EPOCH=$(SDE) \
	    $(3) --target artifacts --output type=local,dest=$(DIST) -f $(2) .
endef

linux-amd64:
	$(call docker_build,linux/amd64,docker/Dockerfile.linux,)

linux-arm64:
	@ls /proc/sys/fs/binfmt_misc/qemu-aarch64 >/dev/null 2>&1 || \
	  { echo "qemu-aarch64 binfmt not registered. Run once:"; \
	    echo "  docker run --privileged --rm tonistiigi/binfmt --install arm64"; exit 1; }
	$(call docker_build,linux/arm64,docker/Dockerfile.linux,--build-arg PYTHON_IMAGE=python:3.12-slim-trixie)

windows:
	$(call docker_build,linux/amd64,docker/Dockerfile.windows,)

dist-all: linux-amd64 linux-arm64 windows checksums

checksums:
	cd $(DIST) && sha256sum qpwnagotchi* > SHA256SUMS

e2e:
	./scripts/e2e.sh

e2e-package: linux-amd64
	./scripts/e2e-package.sh

clean:
	rm -rf build dist __pycache__ */__pycache__ */*/__pycache__ .pytest_cache
	find . -name '*.pyc' -delete

distclean: clean
	rm -rf $(VENV)

lint: venv
	$(PIP) install -q ruff
	$(VENV)/bin/ruff check pwnman tests app.py
