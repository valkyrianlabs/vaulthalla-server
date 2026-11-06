# libFuzzer target for the VHF1 header parser and chunk walker (spec 02 §7), built only by -Dfuzz=true (see the
# top-level meson.build). It compiles the codec's own sources (OpenSSL and libsodium only), not libvaulthalla:
#   CC=clang CXX=clang++ meson setup build-fuzz -Dfuzz=true && meson compile -C build-fuzz vh_fuzz_vhf1
#   build-fuzz/core/tests/fuzz/vh_fuzz_vhf1 -max_total_time=600 <corpus dir>
vhf1_fuzz_src = meson.project_source_root() / 'core/src'
vhf1_fuzz_flags = ['-fsanitize=fuzzer', '-fno-sanitize-recover=all']
executable('vh_fuzz_vhf1',
           files('fuzz_vhf1.cpp',
                 vhf1_fuzz_src / 'crypto/vhf1/Format.cpp', vhf1_fuzz_src / 'crypto/vhf1/Reader.cpp',
                 vhf1_fuzz_src / 'crypto/vhf1/Writer.cpp', vhf1_fuzz_src / 'crypto/SecretKey.cpp',
                 vhf1_fuzz_src / 'crypto/SecretBytes.cpp',
                 vhf1_fuzz_src / 'crypto/util/Gcm.cpp'),
           include_directories: include_directories('../../include'),
           dependencies: [dependency('openssl', version: '>=3.0'), dependency('libsodium')],
           cpp_args: vhf1_fuzz_flags,
           link_args: vhf1_fuzz_flags,
           install: false,
)
