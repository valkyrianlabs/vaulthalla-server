# ========== VAULTHALLA MAKEFILE ==========
# ⚒️  Forge build & deployment targets
# =========================================

.PHONY: \
	all \
	build \
	install \
	dev \
	test \
	run_test \
	run-test \
	proof \
	proof-selftest \
	clean-test \
	deb \
	release \
	doctor \
	uninstall \
	clean \
	clean-full \
	clean-package \
	purge-builds

dev test run_test run-test clean-test: export VH_BUILD_MODE=dev

# Default target: build
all: build

## 🔨 Build via Conan
build:
	@echo "🔧 Building Vaulthalla..."
	conan install . -r vaulthalla --build=missing
	conan build .

## 🛠️ Install system-wide
install:
	./bin/setup/install_guard.sh
	@echo "🛡️  Running install script..."
	./bin/install.sh

## 🛠️ Install in development mode
dev:
	./bin/uninstall.sh
	./bin/setup/install_guard.sh
	@echo "🛡️  Running install script..."
	./bin/install.sh

test:
	./bin/tests/uninstall.sh
	@echo "🛡️  Running integration tests install script..."
	./bin/tests/install.sh

run_test:
	./bin/tests/uninstall.sh
	@echo "🛡️  Running integration tests install script..."
	./bin/tests/install.sh --run

## Tier A proof as a private instance: per-run DB, private /tmp paths, reports in build-proof/proof-artifacts/.
## Leaves the dev install and the test DB alone (needs passwordless sudo).
proof:
	./bin/tests/run_proof.sh

proof-selftest:
	./bin/tests/run_proof_selftest.sh

clean-test:
	@echo "💣 Running integration tests uninstall script..."
	./bin/tests/uninstall.sh

deb:
	@echo "🔧 Local release rehearsal (vlr prepare + build-deb + validate in a throwaway worktree of HEAD)..."
	./bin/install_deb.sh

# Releases: `vlr cut patch|minor|major --push` bumps, commits and tags; the tag push starts release CI, which
# prepares, builds, publishes and records the release (see .claude/skills/vl-release). Nothing publishes from here.
release:
	@echo "Cut releases with: vlr cut patch|minor|major --push   (vlr status shows what would ship)"
	@vlr status

doctor:
	@echo "🔍 Running doctor script..."
	./bin/doctor.sh

## 🧼 Uninstall everything
uninstall:
	@echo "💣 Running uninstall script..."
	./bin/uninstall.sh
	./bin/tests/uninstall.sh

clean:
	./bin/clean.sh

clean-full purge-builds:
	./bin/clean.sh --full

clean-package:
	./bin/clean.sh --package
