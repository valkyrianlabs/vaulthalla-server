# vaulthalla-preview-cad: STEP/STP -> GLB with Open CASCADE (Debian: libocct-*-dev 7.6). Located without CMake
# (the package build has no cmake): headers under <includedir>/opencascade, one shared library per toolkit.
cpp = meson.get_compiler('cpp')

occt_include_dir = get_option('prefix') / get_option('includedir') / 'opencascade'
occt_toolkits = [
    'TKernel', 'TKMath', 'TKG3d', 'TKBRep', 'TKTopAlgo', 'TKMesh', 'TKXSBase', 'TKSTEP', 'TKXDESTEP',
    'TKLCAF', 'TKCDF', 'TKXCAF', 'TKRWMesh',
]

occt_found = fs.is_dir(occt_include_dir)
occt_libs = []
foreach toolkit : occt_toolkits
    lib = cpp.find_library(toolkit, required: false)
    occt_found = occt_found and lib.found()
    occt_libs += lib
endforeach

if occt_found
    occt_inc = include_directories(occt_include_dir, is_system: true)
    occt_found = cpp.has_header('STEPCAFControl_Reader.hxx', include_directories: occt_inc) and \
                 cpp.has_header('RWGltf_CafWriter.hxx', include_directories: occt_inc)
endif

if occt_found
    occt_dep = declare_dependency(include_directories: occt_inc, dependencies: occt_libs)

    preview_cad_helper = executable(
        'vaulthalla-preview-cad',
        files('main.cpp', 'convert_step.cpp'),
        include_directories: helper_inc,
        link_with: helper_common_lib,
        dependencies: [seccomp_dep, occt_dep],
        override_options: helper_sanitize,
        install: true,
        install_dir: helper_dir,
    )
elif preview_cad_option.enabled()
    error('preview_cad is enabled but Open CASCADE (libocct-data-exchange-dev, libocct-modeling-algorithms-dev, ' +
          'libocct-ocaf-dev, libocct-foundation-dev, libocct-modeling-data-dev) was not found')
else
    message('preview_cad: Open CASCADE not found, vaulthalla-preview-cad is not built')
endif
