# Out-of-process preview converters ("helpers"). Separate executables from optional Debian packages
# (vaulthalla-preview-cad, vaulthalla-preview-media), spawned by preview::derive::Runner. The daemon never links
# OCCT, libav* or libseccomp: everything here is its own target.
#
# Shared with the helper subdirectories (names fixed: preview-media/meson.build uses them too):
#   helper_dir            <prefix>/lib/vaulthalla/helpers (preview.derive.helper_dir defaults to /usr/lib/...)
#   helper_inc            core/tools + core/vendor: include "common/protocol.hpp", <nlohmann/json.hpp>
#   seccomp_dep           libseccomp (every helper links it through helper_common_lib)
#   helper_common_lib     protocol + Landlock/seccomp sandbox (core/tools/common)
#   helper_sanitize       override_options for every helper target: never sanitized (see below)
#   preview_cad_helper    the CAD helper executable (set only when built)
#   preview_media_helper  the media helper executable (set by preview-media/meson.build when built)

helper_dir = get_option('prefix') / 'lib' / meson.project_name() / 'helpers'
helper_inc = include_directories('.', '../vendor')

preview_cad_option = get_option('preview_cad')
preview_media_option = get_option('preview_media')
preview_media_present = fs.exists(meson.current_source_dir() / 'preview-media' / 'meson.build')

if preview_media_option.enabled() and not preview_media_present
    error('preview_media is enabled but core/tools/preview-media/meson.build is missing')
endif

# A helper never parses hostile input without its seccomp filter, so libseccomp is required for any helper.
seccomp_dep = dependency(
    'libseccomp',
    required: preview_cad_option.enabled() or (preview_media_present and preview_media_option.enabled()),
)

# Helpers are never sanitized, not even in a -Db_sanitize build (`make test`): they run under the Runner's RLIMIT_AS
# cap and their own seccomp filter, where an ASan/UBSan runtime can't reserve its shadow memory ("ReserveShadowMemoryRange
# failed"), so a sanitized helper aborts before main and every helper test fails. `helper_sanitize` goes on each helper
# target and on the library they link (a sanitized static library can't link into an unsanitized executable).
helper_sanitize = ['b_sanitize=none']

helper_common_lib = disabler()
if seccomp_dep.found()
    helper_common_lib = static_library(
        'vh_helper_common',
        files('common/protocol.cpp', 'common/sandbox.cpp'),
        include_directories: helper_inc,
        dependencies: seccomp_dep,
        override_options: helper_sanitize,
        install: false,
    )
    if not preview_cad_option.disabled()
        subdir('preview-cad')
    endif
    # preview-media/meson.build checks its own libav* dependencies against the preview_media option.
    if preview_media_present and not preview_media_option.disabled()
        subdir('preview-media')
    endif
else
    message('preview helpers: libseccomp not found, no converter helper is built')
endif
