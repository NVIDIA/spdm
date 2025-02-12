# Standard tests that don't need additional implementation files
standard_tests = [
  'mctp_endpoint_discovery_test'
]

# Special tests that need specific source files
special_tests = {
  'spdmd_app_context_watchdog_test': ['spdmd_app_context_test.cpp', '../spdmd_app_context.cpp'],
}

test_config_h = configuration_data()
test_config_h.set('FETCH_SERIALNUMBER_FROM_RESPONDER', '0')
test_config_h.set('SPDM_JSON_CONF_FILE_NAME', '""')

# Generate config.h for the tests
configure_file(
  output: 'config.h',
  configuration: test_config_h
)

# Build and register standard tests
foreach t : standard_tests
    test(t,
        executable('spdmd_' + t.underscorify(),
            t + '.cpp',
            implicit_include_directories: false,
            include_directories: [
              '../',         # Add the parent directory
              '.',           # Add current directory (for config.h)
              '../..',       # Add project root
            ],
            dependencies: [
                gtest,
                gmock,
                sdbusplus,
                phosphor_dbus_interfaces,
                CLI11_dep,
                crypto_deps,
                nlohmann_json,
                libspdmcpp_requester_dep
            ]
        ),
        workdir: meson.current_source_dir()
    )
endforeach

# Build and register special tests
foreach test_name, sources : special_tests
    test(test_name.underscorify(),
        executable(
            test_name,
            sources,
            implicit_include_directories: false,
            include_directories: [
              '../',         # Add the parent directory
              '.',           # Add current directory (for config.h)
              '../..',       # Add project root
            ],
            dependencies: [
                gtest,
                gmock,
                sdbusplus,
                phosphor_dbus_interfaces,
                CLI11_dep,
                crypto_deps,
                nlohmann_json,
                libspdmcpp_requester_dep
            ],
            cpp_args: ['-DUSE_DEFAULT_DBUS']
        ),
        workdir: meson.current_source_dir()
    )
endforeach

