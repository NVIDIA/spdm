# SPDX-License-Identifier: Apache-2.0
#
# Vendor-neutral composite attestation core.
#
# Builds the producer-side modules shared by the daemon and the mock
# attester: the deterministic CBOR writer (tinycbor + key ordering),
# detached Claims-Set builder, submodule digest, env.* collection plan,
# tag-602 bundle assembler, and the orchestrator.

composite_sources = files(
    'cbor_det.cpp',
    'claims_set_builder.cpp',
    'submodule_digest.cpp',
    'collection_plan.cpp',
    'evidence_builder.cpp',
    'bundle_assembler.cpp',
    'composite_orchestrator.cpp',
    'pem.cpp',
)

# '.' resolves "cbor_det.hpp"; '..' resolves "composite/..." and
# "platform_attester.hpp".
composite_inc = include_directories('.', '..')

composite_lib = static_library(
    'composite',
    composite_sources,
    implicit_include_directories: false,
    include_directories: composite_inc,
    dependencies: [
        crypto_deps,    # mbedcrypto (SHA-384)
        nlohmann_json,  # collection_plan config parsing
        tinycbor_dep,   # deterministic CBOR
    ],
)

composite_dep = declare_dependency(
    include_directories: composite_inc,
    link_with: composite_lib,
    dependencies: [crypto_deps, nlohmann_json, tinycbor_dep],
)
