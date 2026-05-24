# qPwnagotchi — build & packaging
#
# Common targets:
#   make venv         create .venv and install requirements
#   make run          run the app from source
#   make test         run unit tests
#   make build        produce a single-file binary in dist/ for the host arch
#   make deb          produce a .deb in dist/ for the host arch
#   make all          build + deb
#   make clean        remove build/, dist/, *.spec leftovers, __pycache__
#
# Cross-compiling PyInstaller is not supported. To build for uConsole
# (arm64/armhf), run `make deb` *on* the uConsole (or in a matching
# qemu-user / docker buildx container). See scripts/build.sh for details.

PYTHON      ?= python3
VENV        ?= .venv
PIP         := $(VENV)/bin/pip
PY          := $(VENV)/bin/python
PYINSTALLER := $(VENV)/bin/pyinstaller

APP_NAME    := qpwnagotchi
# Version: prefer a real git tag (vX.Y.Z); otherwise fall back to
# 0.1.0+git<sha> so the result is a valid Debian version (must start
# with a digit). Override with `make VERSION=1.2.3 deb` for releases.
VERSION     := $(shell ./scripts/version.sh 2>/dev/null || echo 0.1.0)
ARCH        := $(shell dpkg --print-architecture 2>/dev/null || uname -m)

export APP_NAME VERSION ARCH

.PHONY: all venv run test build deb clean distclean help

help:
	@echo "Targets: venv run test build deb all clean distclean"
	@echo "Host arch: $(ARCH)   Version: $(VERSION)"

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

venv: $(VENV)/bin/activate

run: venv
	$(PY) app.py

test: venv
	$(PY) -m pytest -q tests

build: venv
	./scripts/build.sh

deb: build
	./scripts/build-deb.sh

all: deb

clean:
	rm -rf build dist __pycache__ */__pycache__ */*/__pycache__
	find . -name '*.pyc' -delete
	rm -f app.spec.bak

distclean: clean
	rm -rf $(VENV)
