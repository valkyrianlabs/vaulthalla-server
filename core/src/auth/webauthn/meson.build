# The WebAuthn relying-party verifier (#355, docs/dev/mfa-design.md section 4.1): its own static library over libcbor,
# OpenSSL 3, libsodium and the vendored nlohmann/json only, so it can be extracted as a vl-* library later (the
# vl-sigv4 model). core/meson.build links it into the daemon; with -Dfuzz=true the root meson.build builds only this
# directory and its libFuzzer targets (fuzz/). tools/contracts/test_webauthn_contract.py pins the boundary.
webauthn_inc = include_directories('../../../include', '../../../vendor')
webauthn_deps = [
    dependency('libcbor', version: '>=0.10', required: true),
    dependency('openssl', version: '>=3.0', required: true),
    dependency('libsodium', required: true),
]

webauthn_sources = []
foreach f : run_command('sh', '-c', 'find "$1" -maxdepth 1 -type f -name "*.cpp" | LC_ALL=C sort', 'find-cpp',
                        meson.current_source_dir(), check: true).stdout().strip().split('\n')
    webauthn_sources += files(f)
endforeach

# Under -Dfuzz=true the library itself carries libFuzzer's coverage instrumentation.
webauthn_lib = static_library(
    'vh_webauthn',
    webauthn_sources,
    include_directories: webauthn_inc,
    dependencies: webauthn_deps,
    cpp_args: get_option('fuzz') ? ['-fsanitize=fuzzer-no-link'] : [],
    install: false,
)

vh_webauthn_dep = declare_dependency(
    link_with: webauthn_lib,
    include_directories: webauthn_inc,
    dependencies: webauthn_deps,
)

if get_option('fuzz')
    subdir('fuzz')
endif
