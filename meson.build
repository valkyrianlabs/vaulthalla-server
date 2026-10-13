project('vaulthalla', 'cpp',
        version: '1.12.3',
        license: 'AGPL-3.0-or-later',
        meson_version: '>=1.3.0',
        default_options: [
            'warning_level=3',
            'werror=false',
            'cpp_std=c++23',
            'unity=on',
            'unity_size=9',
            'prefix=/usr',
            # Development, tests and PR CI build at -O0; release packages set optimization=3 explicitly (debian/rules).
            'buildtype=debug',
        ]
)

# Not a cpp_args default: with meson 1.3, a cpp_args default_option makes meson drop the CFLAGS/CXXFLAGS the
# environment provides (dpkg-buildflags), which left packaged binaries without -O and hardening flags.
add_project_arguments('-D_GLIBCXX_USE_CXX11_ABI=1', language: 'cpp')

fs = import('fs')

# See core/include/compat/gcc_variant.hpp: a GCC-only false positive inside libstdc++'s <variant> (via libpqxx) that
# has to be handled before any other header includes <variant>.
if meson.get_compiler('cpp').get_id() == 'gcc'
    add_project_arguments('-include', meson.project_source_root() / 'core/include/compat/gcc_variant.hpp',
                          language: 'cpp')
endif

subdir('core')

if get_option('install_data')
    project_name = meson.project_name()
    bindir = get_option('bindir')
    sysconf_dir = join_paths('/', get_option('sysconfdir'), project_name)
    state_dir = join_paths('/', get_option('localstatedir'), 'lib', project_name)
    log_dir = join_paths('/', get_option('localstatedir'), 'log', project_name)
    data_dir = get_option('datadir') / project_name
    doc_dir = get_option('datadir') / 'doc' / project_name
    libexec_dir = 'lib' / project_name

    if host_machine.system() == 'linux'
        install_emptydir(state_dir)
        install_emptydir(log_dir)
    endif

    # Packaged defaults live under /usr/share; postinst copies config.yaml into
    # /etc/vaulthalla only when it is missing (it is runtime-owned, not a conffile).
    install_data(
        'deploy/config/config.yaml',
        'deploy/config/config_template.yaml.in',
        install_dir: data_dir / 'config',
    )

    # Source installs only: opt in to installing the gitignored repo-root config.yaml
    # into /etc/vaulthalla. Package builds never set this, so a private local config
    # can never leak into a .deb.
    if get_option('install_local_config_override') and fs.exists(meson.project_source_root() / 'config.yaml')
        install_data(
            'config.yaml',
            install_dir: sysconf_dir,
        )
    endif

    install_subdir(
        'deploy/psql',
        install_dir: data_dir,
    )

    install_data(
        'deploy/nginx/vaulthalla.conf',
        install_dir: data_dir / 'nginx',
        rename: 'vaulthalla',
    )

    install_data(
        'deploy/lifecycle/main.py',
        install_dir: libexec_dir,
        rename: 'lifecycle',
        install_mode: 'rwxr-xr-x',
    )

    install_data(
        'LICENSE',
        'debian/copyright',
        install_dir: doc_dir,
    )

    # Linux: systemd units, the TPM udev rule and tmpfiles (unchanged).
    if host_machine.system() == 'linux'
        unit_conf = configuration_data()
        unit_conf.set('BINDIR', get_option('prefix') / bindir)

        foreach unit_template : [
            'vaulthalla.service',
            'vaulthalla-web.service',
            'vaulthalla-swtpm.service',
        ]
            unit_input = 'deploy/systemd' / (unit_template + '.in')
            configure_file(
                input: unit_input,
                output: unit_template,
                configuration: unit_conf,
                install: true,
                install_dir: get_option('systemd_system_unit_dir'),
            )
        endforeach

        install_data(
            'debian/vaulthalla.udev',
            install_dir: get_option('udev_rules_dir'),
            rename: '60-vaulthalla-tpm.rules',
        )

        install_data(
            'debian/tmpfiles.d/vaulthalla.conf',
            install_dir: get_option('tmpfiles_dir'),
        )
    endif

    # macOS: launchd instead of systemd/udev/tmpfiles (deploy/launchd). vaulthalla-provision creates the _vaulthalla
    # account, the private directories and the LaunchDaemons; the paths are the ones compiled into the daemon.
    if host_machine.system() == 'darwin'
        install_data(
            'deploy/launchd/sh.vaulthalla.server.plist.in',
            'deploy/launchd/sh.vaulthalla.web.plist.in',
            'deploy/launchd/sh.vaulthalla.postgres.plist.in',
            install_dir: data_dir / 'launchd',
        )
        install_data('tools/macos/pkg/uninstall.sh', install_dir: data_dir, install_mode: 'rwxr-xr-x')
        provision_conf = configuration_data()
        provision_conf.set('SUPPORT_DIR', '/Library/Application Support/Vaulthalla')
        provision_conf.set('STATE_DIR', vh_state_dir)
        provision_conf.set('RUN_DIR', vh_runtime_dir)
        provision_conf.set('MOUNT_DIR', vh_mount_dir)
        provision_conf.set('LOG_DIR', vh_log_dir)
        provision_conf.set('CONFIG_PATH', vh_config_path)
        provision_conf.set('SHARE_DIR', get_option('prefix') / data_dir)
        provision_conf.set('BINDIR', get_option('prefix') / bindir)
        provision_conf.set('WEB_DIR', get_option('prefix') / get_option('datadir') / 'vaulthalla-web')
        provision_conf.set('NODE', get_option('prefix') / 'libexec' / 'vaulthalla' / 'node' / 'bin' / 'node')
        # The package's private PostgreSQL (tools/macos/pkg/build-postgres.sh); a source install has none.
        provision_conf.set('PG_BIN', get_option('prefix') / 'libexec' / 'vaulthalla' / 'postgresql' / 'bin')
        configure_file(
            input: 'deploy/launchd/vaulthalla-provision.in',
            output: 'vaulthalla-provision',
            configuration: provision_conf,
            install: true,
            install_dir: libexec_dir,
            install_mode: 'rwxr-xr-x',
        )
    endif

    install_symlink(
        'vaulthalla',
        install_dir: bindir,
        pointing_to: 'vaulthalla-cli',
    )

    install_symlink(
        'vh',
        install_dir: bindir,
        pointing_to: 'vaulthalla-cli',
    )
endif
