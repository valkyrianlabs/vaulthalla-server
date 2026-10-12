# ========== VAULTHALLA MAKEFILE ==========
# ⚒️  Forge build & deployment targets
# =========================================

.PHONY: \
	all \
	build \
	install \
	dev \
	test \
	itest \
	itest-selftest \
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

dev: export VH_BUILD_MODE=dev

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

## Tests never install, never touch the dev install or a shared role/database: each run gets its own database (owned
## by the vh_harness role, from `sudo tools/harness/bootstrap.sh`, once), private /tmp paths and the build-itest/ build.
## DB-backed unit tests (vh_unit_tests) against a per-run database. Pass gtest args: make test ARGS="--gtest_filter=..."
test:
	./bin/tests/run_unit.sh -- $(ARGS)

## Tier A integration proofs (vh_integration_tests) as a private instance: per-run DB from the migrated template,
## private FUSE mount, reports in build-itest/proof-artifacts/.
itest:
	./bin/tests/run_proof.sh

itest-selftest:
	./bin/tests/run_proof_selftest.sh

# Old names of `itest`; the shared-environment run_test (install over /usr, rotate the vaulthalla_test role, truncate
# whatever DB it reached) no longer exists.
run_test run-test proof:
	@echo "note: '$@' is now 'make itest' (isolated: per-run DB, private paths, nothing installed)"
	@$(MAKE) --no-print-directory itest

proof-selftest:
	@$(MAKE) --no-print-directory itest-selftest

## Removes leftovers of interrupted isolated runs (their databases and unmounted /tmp/vhh_* dirs), nothing else.
clean-test:
	./bin/tests/clean_itest.sh

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

clean:
	./bin/clean.sh

clean-full purge-builds:
	./bin/clean.sh --full

clean-package:
	./bin/clean.sh --package
