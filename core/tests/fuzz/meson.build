# libFuzzer target for the VHF1 header parser and chunk walker (spec 02 §7), built only by -Dfuzz=true (see the
# top-level meson.build). It compiles the codec's own sources (OpenSSL and vl-keykit only), not libvaulthalla:
#   CC=clang CXX=clang++ meson setup build-fuzz -Dfuzz=true && meson compile -C build-fuzz vh_fuzz_vhf1
#   build-fuzz/core/tests/fuzz/vh_fuzz_vhf1 -max_total_time=600 <corpus dir>
vhf1_fuzz_src = meson.project_source_root() / 'core/src'
vhf1_fuzz_flags = ['-fsanitize=fuzzer', '-fno-sanitize-recover=all']
# vl-keykit (wiping, constant-time comparison, the locked secret type) builds against the vendored nlohmann, as in
# core/meson.build, which a fuzz build never reads.
meson.override_dependency('nlohmann_json',
    declare_dependency(include_directories: include_directories('../../vendor'), version: '3.12.0'))
executable('vh_fuzz_vhf1',
           files('fuzz_vhf1.cpp',
                 vhf1_fuzz_src / 'crypto/vhf1/Aead.cpp', vhf1_fuzz_src / 'crypto/vhf1/Format.cpp',
                 vhf1_fuzz_src / 'crypto/vhf1/Key.cpp', vhf1_fuzz_src / 'crypto/vhf1/Reader.cpp',
                 vhf1_fuzz_src / 'crypto/vhf1/Writer.cpp'),
           include_directories: include_directories('../../include'),
           dependencies: [dependency('openssl', version: '>=3.0'),
                          dependency('vl-keykit', version: '>=0.2.0', fallback: ['vl-keykit', 'vl_keykit_dep'])],
           cpp_args: vhf1_fuzz_flags,
           link_args: vhf1_fuzz_flags,
           install: false,
)
