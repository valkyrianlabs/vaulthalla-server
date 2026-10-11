fs = import('fs')

# ╭──────────────────────────────── VERSION HEADER ─────────────────────────────────╮

version_split = meson.project_version().split('.')
if version_split.length() < 3
    error('Project version must be in the format X.Y.Z (e.g., 0.9.2)')
endif

conf = configuration_data()
conf.set_quoted('VH_VERSION', meson.project_version())
conf.set_quoted('VH_VERSION_MAJOR', version_split[0])
conf.set_quoted('VH_VERSION_MINOR', version_split[1])
conf.set_quoted('VH_VERSION_PATCH', version_split[2])

vh_version_header = configure_file(
    output: 'version.h',
    configuration: conf,
    install: true,
    install_dir: get_option('includedir') / 'vaulthalla'
)


# ╭──────────────────────────────── PATH HEADER ─────────────────────────────────╮

repo_root = meson.project_source_root()
core_root = meson.current_source_dir()
config_dir = join_paths(get_option('sysconfdir'), meson.project_name())
log_dir = join_paths(get_option('localstatedir'), 'log', meson.project_name())
state_dir = join_paths(get_option('localstatedir'), 'lib', meson.project_name())
runtime_dir = join_paths('/run', meson.project_name())
data_dir = join_paths(get_option('prefix'), get_option('datadir'), meson.project_name())
psql_dir = join_paths(data_dir, 'psql')

conf = configuration_data()
conf.set_quoted('VH_MOUNT_PATH', join_paths('/mnt', meson.project_name()))
conf.set_quoted('VH_CONFIG_PATH', join_paths('/', config_dir, 'config.yaml'))
conf.set_quoted('VH_LOG_PATH', log_dir)
conf.set_quoted('VH_BACKING_PATH', state_dir)
conf.set_quoted('VH_RUNTIME_PATH', runtime_dir)
conf.set_quoted('VH_CACHE_PATH', '/.cache')
conf.set_quoted('VH_S3_GATEWAY_MULTIPART_PARTS_DIRNAME', '.8f3a9c1d6e2b4f70')
conf.set_quoted('VH_PSQL_SCHEMAS_PATH', psql_dir)
conf.set_quoted('VH_PSQL_TEST_SCHEMAS_PATH', join_paths(repo_root, 'deploy/psql'))
conf.set_quoted('VH_TEST_ENV_PATH', join_paths(repo_root, 'deploy/vaulthalla.env'))

vh_paths_header = configure_file(
    input: 'deploy/path/paths.h.in',
    output: 'paths.h',
    configuration: conf,
    install: true,
    install_dir: get_option('includedir') / 'vaulthalla'
)


# ╭──────────────────────────── DEFINE DEPENDENCIES ────────────────────────────╮

fmt_dep = dependency('fmt', required: true)
# apt.vaulthalla.sh's libpqxx-vh-dev: a static libpqxx SDK under its own pkg-config name (the .pc links libpqxx.a
# by path and the system libpq by SONAME), so neither Ubuntu's libpqxx-dev nor its headers can be picked up.
pqxx_dep = dependency('libpqxx-vh', version: '>=8.0.2', method: 'pkg-config', static: true, required: true)

deps = [
    dependency('fuse3', required: true),
    dependency('libsodium', required: true),
    dependency('libcurl', required: true),
    dependency('boost', modules: ['filesystem', 'system'], required: true),
    pqxx_dep,
    # apt.vaulthalla.sh's Chromium-tracking build (<milestone>.<branch>.<n>). The retired 2025.06.29 fork snapshot sorts
    # higher, so the upper bound is what keeps a stale host from building against (and depending on) it.
    dependency('pdfium', version: ['>=155.8059', '<1000'], required: true),
    dependency('libmagic', required: true),
    dependency('yaml-cpp', required: true),
    dependency('libjpeg', required: true),
    dependency('pugixml', required: true),
    dependency('uuid', required: true),
    dependency('threads', required: true),
    dependency('spdlog', required: true),
    dependency('libturbojpeg', required: true),
    dependency('tss2-esys', required: true),
    dependency('tss2-tctildr', required: true),
    dependency('tss2-rc', required: true),
    dependency('openssl', version: '>=3.0', required: true),
    dependency('zlib', required: true),
    fmt_dep
]

test_deps = deps + dependency('gtest', required: true, main: false)


# ╭───────────────────────────── CONVERTER HELPERS ─────────────────────────────╮

# Optional out-of-process preview converters (core/tools): their own targets and packages. The daemon never links
# OCCT, libav* or libseccomp; preview::derive::Runner finds the helpers at runtime (preview.derive.helper_dir).
subdir('tools')


# ╭────────────────────────────────   FILES   ──────────────────────────────────╮

inc         = include_directories('include', 'vendor', 'usage/include')
src         = join_paths(core_root, 'src')
tests_src   = join_paths(core_root, 'tests/unit')
main        = files(join_paths(core_root, 'main/main.cpp'))

sources = []
foreach f : run_command('sh', '-c', 'find "$1" -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp', src, check: true).stdout().strip().split('\n')
    sources += files(f)
endforeach

# The usage module's contract export uses the vendored nlohmann/json (header-only).
usage_inc = include_directories('usage/include', 'vendor')
usage_src = join_paths(core_root, 'usage/src')
main_usage = files(join_paths(core_root, 'main/usage.cpp'))

usage_sources = []
foreach f : run_command('sh', '-c', 'find "$1" -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp', usage_src, check: true).stdout().strip().split('\n')
    usage_sources += files(f)
endforeach


# ╭──────────────────────────────── LIBRARIES ───────────────────────────────────╮

# Precompiled headers only where nothing is optimized: GCC doesn't keep #pragma GCC diagnostic state in a PCH,
# which would undo compat/gcc_variant.hpp, and the warning it handles (-Wmaybe-uninitialized) needs optimization.
# Test objects are always -O0; the library only in -O0 builds (development, tests, PR CI).
core_pch = get_option('optimization') == '0' ? ['pch/vaulthalla_pch.hpp'] : []

# Unit-test objects are their own target, defined before libvaulthalla: ninja starts ready work in build.ninja order,
# and the test chunks are the longest single jobs, so starting them first keeps one of them from becoming the
# build's tail. They are always compiled at -O0 (the CI test configuration) whatever the buildtype, so an -O3
# build that includes tests doesn't spend optimization time on test code. vh_unit_tests links them whole (link_whole)
# so every gtest registration survives.
if get_option('build_unit_tests')
    unit_test_sources = []
    foreach f : run_command('sh', '-c', 'find "$1" -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp', tests_src, check: true).stdout().strip().split('\n')
        unit_test_sources += files(f)
    endforeach

    # A protocol-speaking fake converter for the preview::derive::Runner tests (never installed).
    fake_derive_helper = executable(
        'vh_fake_derive_helper',
        files(join_paths(core_root, 'tests/helpers/fake_derive_helper.cpp')),
        include_directories: include_directories('vendor'),
        install: false,
    )
    unit_test_helper_targets = [fake_derive_helper]
    cad_helper_path = ''
    if is_variable('preview_cad_helper')
        cad_helper_path = preview_cad_helper.full_path()
        unit_test_helper_targets += preview_cad_helper
    endif
    if is_variable('preview_media_helper')
        unit_test_helper_targets += preview_media_helper
    endif
    unit_test_defines = [
        '-DVH_TEST_FAKE_HELPER="' + fake_derive_helper.full_path() + '"',
        '-DVH_TEST_CAD_HELPER="' + cad_helper_path + '"',
        '-DVH_TEST_ASSETS_DIR="' + join_paths(core_root, 'test-assets') + '"',
    ]

    unit_test_objects = static_library(
        'vh_unit_test_objects',
        unit_test_sources,
        include_directories: inc,
        dependencies: test_deps,
        cpp_args: unit_test_defines,
        install: false,
        override_options: ['optimization=0'],
        cpp_pch: 'pch/vaulthalla_tests_pch.hpp',
    )
endif

lib_core = static_library(
    'vaulthalla',
    sources,
    cpp_pch: core_pch,
    include_directories: inc,
    dependencies: deps,
    install: true
)

lib_seed = static_library('vhseed', files(join_paths(core_root, 'seed/src/seed_db.cpp'),
                                         join_paths(core_root, 'seed/src/SqlDeployer.cpp')),
                          include_directories: include_directories('seed/include', 'include', 'vendor'),
                          dependencies: deps,
                          link_with: lib_core
)

lib_usage = static_library('vhusage',
                           usage_sources,
                           include_directories: usage_inc,
                           dependencies: fmt_dep,
                           install: true
)

lib_usage_native = static_library('vhusage-native',
                                  usage_sources,
                                  include_directories: usage_inc,
                                  dependencies: fmt_dep,
                                  native: true,
                                  install: false,
                                  override_options: ['unity=on', 'b_pch=true']
)


# ╭──────────────────────────────── DEPENDENCIES ────────────────────────────────╮

dep = declare_dependency(
    include_directories: inc,
    link_with: [lib_core, lib_seed, lib_usage],
    dependencies: deps
)


# ╭───────────────────────────────── EXECUTABLES ─────────────────────────────────╮

executable('vaulthalla-server', main,
           include_directories: inc,
           dependencies: dep,
           install: true
)

executable('vaulthalla-cli', files(join_paths(core_root, 'main/cli.cpp')),
           include_directories: include_directories('vendor'),
           dependencies: fmt_dep,
           install: true
)

vh_usage = executable('vh_usage', main_usage,
                      include_directories: usage_inc,
                      link_with: lib_usage_native,
                      native: true,
                      install: false
)


# ╭──────────────────────────────── MANPAGE GENERATION ───────────────────────────────╮

pandoc = find_program('pandoc', required: get_option('manpage'))

vh_md = custom_target('vh-md',
                      output: 'vh.md',
                      command: [vh_usage, '--out', '@OUTPUT@'],
                      build_by_default: true
)

# The server-owned contract (CLI books, ws command book, operation catalog): build/core/usage.json. The integration
# engine reads it; web/src/util/generated/wsContract.{json,ts} are generated from it (tools/contracts/ws_contract.py).
usage_json = custom_target('usage-json',
                           output: 'usage.json',
                           command: [vh_usage, '--json', '--out', '@OUTPUT@'],
                           build_by_default: true
)

if get_option('manpage')
    man1 = custom_target('vh-man',
                         input: vh_md,
                         output: 'vh.1',
                         command: [pandoc, '-s', '-t', 'man', '@INPUT@', '-o', '@OUTPUT@'],
                         install: true,
                         install_dir: get_option('mandir') / 'man1'
    )
endif


# ╭────────────────────────────────────── TESTS ────────────────────────────────────────╮

if get_option('build_unit_tests')
    configure_file(input: 'test-assets/sample.jpg', output: 'sample.jpg', copy: true)
    configure_file(input: 'test-assets/sample.pdf', output: 'sample.pdf', copy: true)
    configure_file(
        input: 'test-assets/Screenshot 2025-06-26 at 3.29.35\u202FPM.png',
        output: 'Screenshot 2025-06-26 at 3.29.35\u202FPM.png',
        copy: true
    )
endif

if get_option('build_unit_tests')
    unit_test_env = environment()
    unit_test_env.set('VH_PATH_TO_CONFIG', join_paths(repo_root, 'deploy/config/config.yaml'))

    vh_unit_tests = executable(
        'vh_unit_tests',
        link_whole: unit_test_objects,
        link_with: [lib_core, lib_seed, lib_usage],
        include_directories: inc,
        dependencies: test_deps,
        install: false,
    )

    # DB-backed suites make one run take several minutes (#123); 120s always timed out.
    test('vh_unit_tests', vh_unit_tests, env: unit_test_env, workdir: meson.current_build_dir(), timeout: 1800,
         depends: unit_test_helper_targets)
endif

# Drift: the committed web contract (web/src/util/generated/wsContract.{json,ts}) must be what this build's usage
# module generates. Fix with: python3 tools/contracts/ws_contract.py --write --vh-usage <build>/core/vh_usage
python3 = find_program('python3', required: false)
if python3.found()
    test('ws_contract_drift', python3,
         args: [join_paths(repo_root, 'tools/contracts/ws_contract.py'), '--check', '--usage-json', usage_json],
         depends: usage_json, timeout: 60)
endif

if get_option('integration_tests')
    # Filesystem probes for the integration harnesses (Tier A here, tools/harness too): one JSON request per line
    # as a given uid/gid. Single-threaded and free of daemon code on purpose.
    vh_fs_actor = executable(
        'vh_fs_actor',
        files(join_paths(core_root, 'tests/helpers/fs_actor.cpp')),
        include_directories: include_directories('vendor'),
        dependencies: dependency('openssl', version: '>=3.0', required: true),
        install: false,
    )

    cli_test_inc = include_directories(
        'tests/integrations/include',
        'usage/include',
        'include',
        'vendor'
    )

    cli_test_src = join_paths(core_root, 'tests/integrations/src')
    cli_test_sources = []

    foreach f : run_command('sh', '-c', 'find "$1" -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp', cli_test_src, check: true).stdout().strip().split('\n')
        cli_test_sources += files(f)
    endforeach

    vh_integration_tests = executable(
        'vh_integration_tests',
        cli_test_sources + join_paths(core_root, 'tests/integrations/main.cpp'),
        include_directories: cli_test_inc,
        link_with: [lib_core, lib_seed, lib_usage],
        dependencies: deps,
        cpp_args: ['-DVH_FS_ACTOR_DEFAULT="' + vh_fs_actor.full_path() + '"'],
        install: false,
    )

    # Not a meson test(): the harness runs only as a private instance (a per-run DB, private /tmp paths, root for the
    # FUSE RBAC proofs) and refuses anything else. Run it with `make proof` / bin/tests/run_proof.sh.
endif
