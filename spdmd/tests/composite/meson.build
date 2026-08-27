# SPDX-License-Identifier: Apache-2.0
#
# Vendor-neutral composite attestation unit tests. These exercise the
# producer core (deterministic CBOR, Claims-Sets, digests, env.* plan,
# bundle assembly) and need no attester backend.

composite_unit_tests = {
    'cbor_det_test': files('cbor_det_test.cpp'),
    'claims_set_builder_test': files('claims_set_builder_test.cpp'),
    'submodule_digest_test': files('submodule_digest_test.cpp'),
    'collection_plan_test': files('collection_plan_test.cpp'),
    'bundle_assembler_test': files('bundle_assembler_test.cpp'),
    'evidence_builder_test': files('evidence_builder_test.cpp'),
    'evidence_pattern_test': files('evidence_pattern_test.cpp'),
}

foreach test_name, test_sources : composite_unit_tests
    test(
        test_name,
        executable(
            'spdmd_' + test_name,
            test_sources,
            implicit_include_directories: false,
            include_directories: include_directories(
                '.',       # cbor_test_util.hpp
                '../..',   # spdmd/  (for "composite/...")
            ),
            dependencies: [
                gtest,
                gmock,
                composite_dep,
            ],
        ),
        workdir: meson.current_source_dir(),
    )
endforeach
