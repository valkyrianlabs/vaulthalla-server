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
# -Dinstance=NAME (`make dev` uses dev): an isolated instance beside a production install. Every compiled-in location,
# the service account, the service names and the CLI socket carry the name; the empty default is production, unchanged.
vh_instance = get_option('instance')
if vh_instance.underscorify() != vh_instance or vh_instance.to_lower() != vh_instance
    error('instance must be a short lowercase name of letters, digits and _ (e.g. dev), got: ' + vh_instance)
endif
vh_instance_name = vh_instance == '' ? meson.project_name() : meson.project_name() + '-' + vh_instance
config_dir = join_paths(get_option('sysconfdir'), vh_instance_name)
log_dir = join_paths(get_option('localstatedir'), 'log', vh_instance_name)
state_dir = join_paths(get_option('localstatedir'), 'lib', vh_instance_name)
runtime_dir = join_paths('/run', vh_instance_name)
mount_dir = vh_instance == '' ? join_paths('/mnt', meson.project_name()) : join_paths('/mnt', 'vh_' + vh_instance)
config_path = join_paths('/', config_dir, 'config.yaml')
data_dir = join_paths(get_option('prefix'), get_option('datadir'), meson.project_name())
psql_dir = join_paths(data_dir, 'psql')
# `vh setup/teardown`: deploy/lifecycle/main.py, installed by the root meson.build as <prefix>/lib/vaulthalla/lifecycle.
lifecycle_path = join_paths(get_option('prefix'), 'lib', meson.project_name(), 'lifecycle')

# macOS: /run, /mnt and /etc/<pkg> are not places a macOS install owns (/run and /mnt don't exist; the system volume is
# read-only). Data lives where it stays put whichever way Vaulthalla is installed (pkg, Homebrew, a future app); the
# defaults are proposed in roadmap #203 and are only compiled in, never read from config.yaml.
# The service account (Linux user and group; on macOS the record alias of the hidden _vaulthalla[_NAME] account), the
# service units/labels, and the port offset of an instance (production: 0; an instance: +100 on every listener).
vh_service_account = vh_instance_name
vh_systemd_unit = vh_instance_name + '.service'
vh_launchd_prefix = vh_instance == '' ? 'sh.vaulthalla' : 'sh.vaulthalla.' + vh_instance
vh_darwin_account = vh_instance == '' ? '_vaulthalla' : '_vaulthalla_' + vh_instance
vh_port_offset = vh_instance == '' ? 0 : 100
if host_machine.system() == 'darwin'
    support_dir = vh_instance == '' ? '/Library/Application Support/Vaulthalla' : '/Library/Application Support/Vaulthalla-' + vh_instance
    config_path = join_paths(support_dir, 'config.yaml')
    state_dir = join_paths(support_dir, 'state')
    log_dir = vh_instance == '' ? '/Library/Logs/Vaulthalla' : '/Library/Logs/Vaulthalla-' + vh_instance
    # Not /var/run: launchd has no RuntimeDirectory and the daemon (as _vaulthalla) can't create one there at boot.
    # A persistent, service-owned directory instead; the daemon rebinds a stale socket on start.
    runtime_dir = join_paths(support_dir, 'run')
    # The optional service-private FUSE mount: beside the backing state, never on top of it, and not under /Volumes
    # (it is internal, not a Finder volume; #199/#204).
    mount_dir = join_paths(support_dir, 'mount')
endif

# The compiled-in locations, for the root meson.build's service files (its own state_dir/log_dir are Linux's).
vh_state_dir = state_dir
vh_log_dir = log_dir
vh_runtime_dir = runtime_dir
vh_mount_dir = mount_dir
vh_config_path = config_path
vh_support_dir = host_machine.system() == 'darwin' ? support_dir : ''

conf = configuration_data()
conf.set_quoted('VH_MOUNT_PATH', mount_dir)
conf.set_quoted('VH_CONFIG_PATH', config_path)
conf.set_quoted('VH_LOG_PATH', log_dir)
conf.set_quoted('VH_BACKING_PATH', state_dir)
conf.set_quoted('VH_RUNTIME_PATH', runtime_dir)
conf.set_quoted('VH_LIFECYCLE_PATH', lifecycle_path)
conf.set_quoted('VH_CACHE_PATH', '/.cache')
conf.set_quoted('VH_INSTANCE', vh_instance)
conf.set_quoted('VH_SERVICE_ACCOUNT', vh_service_account)
conf.set_quoted('VH_SYSTEMD_UNIT', vh_systemd_unit)
if host_machine.system() == 'darwin'
    conf.set_quoted('VH_HINT_SERVICE_NAME', vh_launchd_prefix + '.server')
    conf.set_quoted('VH_HINT_SERVICE_STATUS', 'sudo launchctl print system/' + vh_launchd_prefix + '.server')
    conf.set_quoted('VH_HINT_SERVICE_LOG', 'sudo tail -n 50 "' + join_paths(log_dir, 'vaulthalla.log') + '"')
    conf.set_quoted('VH_HINT_CLI_ENROLL', 'sudo dseditgroup -o edit -a $USER -t user ' + vh_darwin_account)
else
    conf.set_quoted('VH_HINT_SERVICE_NAME', vh_systemd_unit)
    conf.set_quoted('VH_HINT_SERVICE_STATUS', 'systemctl status ' + vh_instance_name)
    conf.set_quoted('VH_HINT_SERVICE_LOG', 'journalctl -u ' + vh_instance_name + ' -n 50')
    conf.set_quoted('VH_HINT_CLI_ENROLL', 'sudo usermod -aG ' + vh_service_account + ' $USER')
endif
conf.set_quoted('VH_S3_GATEWAY_MULTIPART_PARTS_DIRNAME', '.8f3a9c1d6e2b4f70')
conf.set_quoted('VH_PSQL_SCHEMAS_PATH', psql_dir)
conf.set_quoted('VH_PSQL_TEST_SCHEMAS_PATH', join_paths(repo_root, 'deploy/psql'))

vh_paths_header = configure_file(
    input: 'deploy/path/paths.h.in',
    output: 'paths.h',
    configuration: conf,
    install: true,
    install_dir: get_option('includedir') / 'vaulthalla'
)


# ╭──────────────────────────── DEFINE DEPENDENCIES ────────────────────────────╮

host_os = host_machine.system()

fmt_dep = dependency('fmt', required: true)
# apt.vaulthalla.sh's libpqxx-vh-dev: a static libpqxx SDK under its own pkg-config name (the .pc links libpqxx.a
# by path and the system libpq by SONAME), so neither Ubuntu's libpqxx-dev nor its headers can be picked up.
pqxx_dep = dependency('libpqxx-vh', version: '>=8.0.2', method: 'pkg-config', static: true, required: true)

# The kernel FUSE bridge (core/src/fuse/{Bridge,Reply,Resolver,Service}.cpp): required on Linux, which the Debian
# package ships; off by default elsewhere (macOS serves vaults over HTTP/WS/CLI until a Finder backend is chosen).
fuse_dep = dependency('fuse3', required: get_option('fuse').enable_auto_if(host_os == 'linux').disable_auto_if(host_os != 'linux'))
fuse_bridge_sources = ['fuse/Bridge.cpp', 'fuse/Reply.cpp', 'fuse/Resolver.cpp', 'fuse/Service.cpp']

deps = [
    dependency('libsodium', required: true),
    dependency('libcurl', required: true),
    dependency('boost', modules: ['filesystem'], required: true),
    pqxx_dep,
    # apt.vaulthalla.sh's Chromium-tracking build (<milestone>.<branch>.<n>). The retired 2025.06.29 fork snapshot sorts
    # higher, so the upper bound is what keeps a stale host from building against (and depending on) it.
    dependency('pdfium', version: ['>=155.8059', '<1000'], required: true),
    dependency('libmagic', required: true),
    dependency('yaml-cpp', required: true),
    dependency('libjpeg', required: true),
    dependency('pugixml', required: true),
    dependency('threads', required: true),
    dependency('spdlog', required: true),
    dependency('libturbojpeg', required: true),
    dependency('openssl', version: '>=3.0', required: true),
    dependency('zlib', required: true),
    fmt_dep
]

if fuse_dep.found()
    if host_os == 'darwin'
        # macFUSE's libfuse3 defaults to its Darwin extensions (fuse_darwin_attr instead of struct stat); the vanilla
        # libfuse API keeps the bridge identical to Linux's. Weak-linked: macFUSE is an optional, operator-installed
        # integration, and the daemon must start and serve storage without it (platform::mount::fuseRuntimeAvailable).
        fuse_dep = declare_dependency(
            dependencies: fuse_dep.partial_dependency(compile_args: true, includes: true),
            compile_args: ['-DFUSE_DARWIN_ENABLE_EXTENSIONS=0'],
            link_args: ['-L' + fuse_dep.get_variable(pkgconfig: 'libdir'), '-Wl,-weak-lfuse3'],
        )
    endif
    deps += fuse_dep
endif

# Linux-only system libraries: libuuid (macOS has <uuid/uuid.h> in libSystem) and the TPM2 stack behind the TPM
# secret sealer (crypto/secrets/tpm/).
if host_os == 'linux'
    deps += [
        dependency('uuid', required: true),
        dependency('tss2-esys', required: true),
        dependency('tss2-tctildr', required: true),
        dependency('tss2-rc', required: true),
    ]
endif

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

# Platform-specific code lives under platform/<os>/ (and fuse/unbuilt/, the stand-in for a build without the kernel
# FUSE bridge); only the host's directory is compiled. Everything else is shared by every OS.
platform_src_prefixes = ['platform/', 'fuse/unbuilt/', 'protocols/http/upload/staging/']
sources = []
foreach f : run_command('sh', '-c', 'find "$1" -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp', src, check: true).stdout().strip().split('\n')
    rel = f.replace(src + '/', '')
    skip = not fuse_dep.found() and rel in fuse_bridge_sources
    foreach prefix : platform_src_prefixes
        skip = skip or rel.startswith(prefix)
    endforeach
    if not skip
        sources += files(f)
    endif
endforeach
platform_os_dir = host_os == 'darwin' ? 'darwin' : 'linux'
foreach f : run_command('sh', '-c', 'find "$1" -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp', src / 'platform' / platform_os_dir, check: false).stdout().strip().split('\n')
    if f != ''
        sources += files(f)
    endif
endforeach
if not fuse_dep.found()
    sources += files(src / 'fuse/unbuilt/Service.cpp')
endif

upload_staging = get_option('http_upload_staging')
if upload_staging == 'auto'
    upload_staging = host_os == 'linux' ? 'mount' : 'private'
endif
if upload_staging == 'mount' and not fuse_dep.found()
    error('-Dhttp_upload_staging=mount stages uploads through the FUSE mount and needs the kernel bridge (-Dfuse)')
endif
sources += files(src / 'protocols/http/upload/staging' / upload_staging / 'Staging.cpp')

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
    # Suites of the kernel FUSE bridge itself; without it (-Dfuse=disabled) there is nothing to test.
    fuse_bridge_tests = ['test_fuse_denial.cpp']
    foreach f : run_command('sh', '-c', 'find "$1" -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp', tests_src, check: true).stdout().strip().split('\n')
        if fuse_dep.found() or fs.name(f) not in fuse_bridge_tests
            unit_test_sources += files(f)
        endif
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

executable('vaulthalla-cli', files(join_paths(core_root, 'main/cli.cpp'), src / 'platform' / platform_os_dir / 'Fd.cpp'),
           include_directories: include_directories('vendor', 'include'),
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

    # Builds the migrated template database per-run test databases are cloned from, with the daemon's SqlDeployer.
    vh_migrate = executable(
        'vh_migrate',
        files(join_paths(core_root, 'tests/helpers/migrate.cpp')),
        include_directories: include_directories('include', 'vendor', '.'),
        link_with: [lib_core, lib_seed, lib_usage],
        dependencies: deps,
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
