
common_sources = files('connection.cpp')

libspdmcpp_config_h = configure_file(
    input: '../config.h.in',
    output: 'config.h',
    configuration: conf_data,
    install: true,
    install_dir: get_option('includedir') / 'spdmcpp',
)

libspdmcpp_config_h_dep = declare_dependency(
    include_directories: include_directories('.'),
    sources: libspdmcpp_config_h,
)

install_subdir('headers_public/spdmcpp', install_dir: get_option('includedir'))

incdir_pub = include_directories('headers_public')

incdir = include_directories('headers_public', 'headers', '..')

libspdmcpp_requester = library(
    'spdmcpp_requester',
    [common_sources],
    version: meson.project_version(),
    soversion: meson.project_version(),
    include_directories: incdir,
    dependencies: [crypto_deps, libspdmcpp_config_h_dep],
    install: true,
)
libspdmcpp_requester_dep = declare_dependency(
    link_with: libspdmcpp_requester,
    include_directories: incdir_pub,
    dependencies: [crypto_deps, libspdmcpp_config_h_dep],
)
meson.override_dependency('spdmcpp_requester', libspdmcpp_requester_dep)
meson.override_dependency('libspdmcpp_requester', libspdmcpp_requester_dep)

# The D-Bus responder shares the application's io_context and Asio objects. Keep
# threading layouts and RTTI-based service lookup consistent across the DSO.
responder_cpp_args = [
    '-UBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_ASIO_HAS_THREADS',
    '-UBOOST_NO_RTTI',
    '-UBOOST_NO_TYPEID',
    '-UBOOST_ASIO_NO_TYPEID',
    '-frtti',
]
responder_threads_dep = dependency('threads')

libspdmcpp_dbus_responder = library(
    'spdmcpp_dbus_responder',
    files('../spdmd/dbus_impl_responder.cpp'),
    version: meson.project_version(),
    soversion: meson.project_version(),
    include_directories: incdir,
    cpp_args: responder_cpp_args,
    dependencies: [
        libspdmcpp_requester_dep,
        sdbusplus,
        phosphor_dbus_interfaces,
        responder_threads_dep,
    ],
    install: true,
)
# Common dependency for the SPDM requester and D-Bus responder libraries.
libspdmcpp_dep = declare_dependency(
    link_with: libspdmcpp_dbus_responder,
    include_directories: incdir_pub,
    compile_args: responder_cpp_args,
    dependencies: [
        libspdmcpp_requester_dep,
        sdbusplus,
        phosphor_dbus_interfaces,
        responder_threads_dep,
    ],
)
meson.override_dependency('spdmcpp_dbus_responder', libspdmcpp_dep)
meson.override_dependency('libspdmcpp_dbus_responder', libspdmcpp_dep)

pkgconfig = import('pkgconfig')

pkgconfig.generate(
    libraries: libspdmcpp_requester,
    libraries_private: [mbedcrypto_dep, mbedx509_dep],
    name: 'libspdmcpp_requester',
    filebase: 'libspdmcpp_requester',
    description: 'SPDM C++ requester library',
    version: meson.project_version(),
    subdirs: '.',
)

pkgconfig.generate(
    libraries: libspdmcpp_dbus_responder,
    requires: ['libspdmcpp_requester', sdbusplus, phosphor_dbus_interfaces],
    extra_cflags: responder_cpp_args,
    name: 'libspdmcpp_dbus_responder',
    filebase: 'libspdmcpp_dbus_responder',
    description: 'SPDM C++ D-Bus responder library',
    version: meson.project_version(),
    subdirs: '.',
)

if get_option('tests').enabled()
    subdir('tests')
endif
