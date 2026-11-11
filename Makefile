# Convenience wrapper around the CMake build.
#
# The real build is CMake; this file exists so the everyday commands are one
# word long (`make`, `make test`, `make run`, `make static`).  Everything it
# does can be reproduced with plain cmake, see README.md.
#
#   make            configure + build (Debug)
#   make release    configure + build optimized
#   make test       anonymity check, build, then run the unit tests
#   make run        build, then start the dashboard
#   make once       build, then print one snapshot
#   make static     portable binary with every feature (scripts/build-static.sh)
#   make doc        regenerate src/embedded.cpp from README.md + LICENSE
#   make check-doc  fail when it is stale (used by CI)
#   make bump       show the next version inferred from the commits
#   make bump-apply write it into CMakeLists.txt
#   make check-anonymity  refuse host names, DNs, UIDs and IPs that are not
#                         RFC 2606 / RFC 5737 examples (also in the push hook)
#   make hooks      install .githooks/ as this repository's hook path
#   make install    install to $(PREFIX)/bin  (default /usr/local)
#   make clean      remove build artefacts
#   make help       this list

BUILD_DIR   ?= build
BUILD_TYPE  ?= Debug
PREFIX      ?= /usr/local
JOBS        ?= $(shell nproc 2>/dev/null || echo 4)

# notcurses/libldap from Homebrew live outside the default search path.
BREW_PC := /home/linuxbrew/.linuxbrew/lib/pkgconfig
ifneq ($(wildcard $(BREW_PC)),)
export PKG_CONFIG_PATH := $(BREW_PC):$(PKG_CONFIG_PATH)
endif

# Ninja is faster and quieter when installed; Makefiles otherwise.
ifeq ($(shell command -v ninja 2>/dev/null),)
GENERATOR :=
# GNU make echoes every directory it enters; -s keeps `make` output readable.
BUILD_QUIET := -- -s
else
GENERATOR := -G Ninja
BUILD_QUIET :=
endif

CMAKE_FLAGS ?= -DSLAPTOP_WITH_TUI=ON -DSLAPTOP_WITH_LDAP=ON

# The test host ships OpenLDAP out of tree and no ldap.pc: point CMake at
# the matching headers and at the versioned soname automatically, so plain
# `make` works there too.
# Several OpenLDAP trees can coexist (the running libldap is built from the
# newest one): pick the highest version, not the first in glob order.
LDAP_HEADER := $(shell ls -1dv /opt/openldap-*/include/ldap.h 2>/dev/null | tail -1)
LDAP_RUNTIME_LIBRDIR := $(firstword $(wildcard /opt/openldap/lib/libldap.so.2))
ifneq ($(LDAP_HEADER),)
CMAKE_FLAGS += -DSLAPTOP_LDAP_ROOT=$(patsubst %/include/ldap.h,%,$(LDAP_HEADER))
endif
ifneq ($(LDAP_RUNTIME_LIBRDIR),)
CMAKE_FLAGS += -DSLAPTOP_LDAP_LIBDIR=$(dir $(LDAP_RUNTIME_LIBRDIR))
endif

.PHONY: all help check-anonymity hooks configure build release test check run once static install clean distclean doc check-doc bump bump-apply

all: build

help:
	@sed -n 's/^#   //p' Makefile

configure:
	@cmake -S . -B $(BUILD_DIR) $(GENERATOR) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) $(CMAKE_FLAGS)

# The embedded documentation and licence are generated from README.md and
# LICENSE: regenerating here keeps `slaptop --doc` in step with the sources.
doc:
	@python3 scripts/gen_embedded.py

check-doc:
	@python3 scripts/gen_embedded.py --check

# The version has a single home (project() in CMakeLists.txt); the level is
# inferred from the commits since the last bump (feat -> minor, fix -> patch).
check-anonymity:
	@python3 tools/check_anonymity.py

hooks:
	@git config core.hooksPath .githooks
	@echo "hooks installed: .githooks (pre-commit, pre-push)"

bump:
	@python3 scripts/bump_version.py

bump-apply:
	@python3 scripts/bump_version.py --apply

build: configure doc
	@cmake --build $(BUILD_DIR) -j $(JOBS) $(BUILD_QUIET)

release:
	@$(MAKE) --no-print-directory build BUILD_TYPE=Release BUILD_DIR=build-release

test: check-anonymity build
	@ctest --test-dir $(BUILD_DIR) --output-on-failure

check: test

run: build
	@$(BUILD_DIR)/slaptop --tui

once: build
	@$(BUILD_DIR)/slaptop --once

static:
	@scripts/build-static.sh

install: build
	@cmake --install $(BUILD_DIR) --prefix $(PREFIX)
	@echo "installed to $(PREFIX)/bin/slaptop"

clean:
	@rm -rf $(BUILD_DIR) build-release

distclean: clean
	@rm -rf build-static compile_commands.json
