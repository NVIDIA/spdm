# SPDX-License-Identifier: Apache-2.0
#
# Mock attester unit tests. Built only when attester-backend=mock.

mock_attester_tests = {
    'eat_builder_test': files('eat_builder_test.cpp'),
    'mock_attester_test': files('mock_attester_test.cpp'),
    # CompositeOrchestrator is vendor-neutral but the end-to-end test
    # exercises it against MockAttester, so it lives here.
    'composite_orchestrator_test': files('composite_orchestrator_test.cpp'),
}

foreach test_name, test_sources : mock_attester_tests
    test(
        test_name,
        executable(
            'spdmd_' + test_name,
            test_sources,
            implicit_include_directories: false,
            include_directories: include_directories(
                '..',          # tests/ (for composite/cbor_test_util.hpp)
                '../..',       # spdmd/ (for "mock_attester/..." & "composite/...")
                '../../..',    # project root
            ),
            dependencies: [
                gtest,
                gmock,
                mock_attester_dep,
                composite_dep,
            ],
        ),
        workdir: meson.current_source_dir(),
    )
endforeach
