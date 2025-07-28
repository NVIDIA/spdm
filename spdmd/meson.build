spdmd_headers = ['.', '..', '../libspdmcpp/headers_public', '../common_headers']

sources = [
    'spdmd.cpp',
    'dbus_impl_responder.cpp',
    'mctp_endpoint_discovery.cpp',
    'spdmd_app_context.cpp',
]

executable(
    'spdmd',
    sources,
    implicit_include_directories: false,
    include_directories: include_directories(spdmd_headers),
    link_with: libspdmcpp_requester,
    dependencies: [
        conf_h_dep,
        CLI11_dep,
        phosphor_dbus_interfaces,
        sdbusplus,
        crypto_deps,
        nlohmann_json,
        libspdmcpp_requester_dep,
    ],
    install: true,
)

if get_option('systemd').enabled()
    systemd_system_unit_dir = dependency('systemd').get_variable(
        pkgconfig: 'systemdsystemunitdir',
    )

    fs.copyfile(
        'service_files/spdmd.service',
        install: true,
        install_dir: systemd_system_unit_dir,
    )
endif

if get_option('tests').enabled()
    subdir('tests')
endif
