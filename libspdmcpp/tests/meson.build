tests = [
    'helpers_test',
    'hash_test',
    'packet_basic_test',
    'connection_test',
    'context_test',
    'log_test',
    'enum_test',
    'flag_test',
    'endianness_test',
    'transport_test',
    'event_test',
    'retstat_test',
    'signature_test',
]

foreach t : tests
    test(
        t,
        executable(
            'libspdmcpp_' + t.underscorify(),
            t + '.cpp',
            implicit_include_directories: false,
            include_directories: incdir,
            # link_args : dynamic_linker,
            dependencies: [libspdmcpp_requester_dep, crypto_deps, gtest, gmock],
        ),
        workdir: meson.current_source_dir(),
    )
endforeach
