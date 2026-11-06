# vaulthalla-preview-media: probe / poster / transcode / hls / capabilities over the range-pull protocol.
# Optional (meson feature `preview_media`); the daemon never links libav*.

preview_media_opt = get_option('preview_media')
media_deps = [
    dependency('libavformat', required: preview_media_opt),
    dependency('libavcodec', required: preview_media_opt),
    dependency('libavutil', required: preview_media_opt),
    dependency('libswscale', required: preview_media_opt),
    dependency('libswresample', required: preview_media_opt),
]

media_found = seccomp_dep.found()
foreach d : media_deps
    media_found = media_found and d.found()
endforeach

if media_found
    preview_media_helper = executable(
        'vaulthalla-preview-media',
        files(
            'Capabilities.cpp',
            'Encode.cpp',
            'Ffmpeg.cpp',
            'Hardware.cpp',
            'Poster.cpp',
            'Probe.cpp',
            'main.cpp',
        ),
        include_directories: helper_inc,
        link_with: helper_common_lib,
        dependencies: media_deps + [seccomp_dep],
        override_options: helper_sanitize,
        install: true,
        install_dir: helper_dir,
    )
endif
