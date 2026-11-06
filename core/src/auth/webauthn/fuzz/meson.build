# libFuzzer targets for the strict parsers (design section 11, decision D5): clang only, -Dfuzz=true (see the root
# meson.build), normally with -Db_sanitize=address,undefined. Seed corpora are committed under corpus/<target>/ and
# replayed by the unit tests on every build (WebAuthnFuzzCorpus). Run: tools/dev/fuzz-webauthn.sh.
foreach target : ['cbor_cose', 'authenticator_data', 'client_data']
    executable(
        'fuzz_webauthn_' + target,
        'fuzz_' + target + '.cpp',
        dependencies: vh_webauthn_dep,
        cpp_args: ['-fsanitize=fuzzer-no-link'],
        link_args: ['-fsanitize=fuzzer'],
        install: false,
    )
endforeach
