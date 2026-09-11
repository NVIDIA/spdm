spdmd_headers = ['.', '..', '../libspdmcpp/headers_public', '../common_headers']

# Composite attestation: vendor-neutral composite core + optional backend
# libraries.
composite_attestation = get_option('composite-attestation')
attester_backend = get_option('attester-backend')

attester_extra_link = []
attester_extra_deps = []
attester_cpp_args = []

if composite_attestation.enabled()
    subdir('composite')
    attester_extra_link += [composite_lib]
    attester_extra_deps += [composite_dep]
    attester_cpp_args += ['-DENABLE_COMPOSITE_ATTESTATION']

    if attester_backend == 'mock'
        subdir('mock_attester')
        attester_extra_link += [mock_attester_lib]
        attester_extra_deps += [mock_attester_dep]
        attester_cpp_args += ['-DATTESTER_BACKEND_MOCK']
    endif
endif

sources = [
    'spdmd.cpp',
    'dbus_impl_responder.cpp',
    'mctp_endpoint_discovery.cpp',
    'spdmd_app_context.cpp',
]

if composite_attestation.enabled()
    sources += [
        'dbus_impl_composite.cpp',
    ]
endif

executable(
    'spdmd',
    sources,
    implicit_include_directories: false,
    include_directories: include_directories(spdmd_headers),
    link_with: [libspdmcpp_requester] + attester_extra_link,
    dependencies: [
        conf_h_dep,
        CLI11_dep,
        phosphor_dbus_interfaces,
        sdbusplus,
        crypto_deps,
        nlohmann_json,
        libspdmcpp_requester_dep,
    ] + attester_extra_deps,
    cpp_args: attester_cpp_args,
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
