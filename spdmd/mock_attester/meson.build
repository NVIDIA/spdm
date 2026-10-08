# SPDX-License-Identifier: Apache-2.0
#
# MockAttester subproject — software-only PlatformAttester backend.
#
# Compiled only when meson option attester-backend=mock is selected.
# Produces a static library with the composite EAT/COSE_Sign1 builder and
# the MockAttester implementation. Depends on the vendor-neutral composite
# core for the deterministic CBOR writer and shared types.

mock_attester_sources = files(
    'eat_builder.cpp',
    'mock_attester.cpp',
)

mock_attester_inc = include_directories('.', '..')

mock_attester_lib = static_library(
    'mock_attester',
    mock_attester_sources,
    implicit_include_directories: false,
    include_directories: mock_attester_inc,
    dependencies: [
        crypto_deps,    # mbedcrypto + mbedx509
        composite_dep,  # cbor_det + composite types
    ],
    cpp_args: ['-DATTESTER_BACKEND_MOCK'],
)

mock_attester_dep = declare_dependency(
    include_directories: mock_attester_inc,
    link_with: mock_attester_lib,
    dependencies: [crypto_deps, composite_dep],
    compile_args: ['-DATTESTER_BACKEND_MOCK'],
)
