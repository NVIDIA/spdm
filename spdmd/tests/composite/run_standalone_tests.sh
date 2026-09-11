#!/usr/bin/env bash
# Local dev helper: standalone build+run of the composite attestation unit
# tests WITHOUT the full meson project (which pulls in libspdmcpp etc.).
# The canonical test path is meson (`meson test`); this script is only a
# fast inner-loop convenience.
#
# Requires: g++-13, system GTest, and mbedtls 3.6.1 static libs. Build the
# latter once with:  make -C subprojects/mbedtls-3.6.1 -j lib
set -euo pipefail

# Repo root = three levels up from this script (spdmd/tests/composite).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SPDMD="$ROOT/spdmd"
MBED="$ROOT/subprojects/mbedtls-3.6.1"
OUT="$ROOT/build_standalone"
mkdir -p "$OUT"

CXX="g++-13"
TCBOR="$ROOT/subprojects/tinycbor-0.6.0/src"
CXXFLAGS="-std=c++23 -O0 -g -Wall -Wextra -DATTESTER_BACKEND_MOCK -I$SPDMD -I$MBED/include -I$TCBOR"
MBEDLIBS="$MBED/library/libmbedx509.a $MBED/library/libmbedcrypto.a"
GTESTLIBS="-lgtest -lgtest_main -lgmock -lpthread"

echo "== compiling composite core + mock into libcomposite.a =="
SRCS=(
  "$SPDMD/composite/cbor_det.cpp"
  "$SPDMD/composite/claims_set_builder.cpp"
  "$SPDMD/composite/submodule_digest.cpp"
  "$SPDMD/composite/collection_plan.cpp"
  "$SPDMD/composite/evidence_builder.cpp"
  "$SPDMD/composite/bundle_assembler.cpp"
  "$SPDMD/composite/composite_orchestrator.cpp"
  "$SPDMD/mock_attester/eat_builder.cpp"
  "$SPDMD/mock_attester/mock_attester.cpp"
  "$TCBOR/cborencoder.c"
  "$TCBOR/cborparser.c"
)
OBJS=()
for s in "${SRCS[@]}"; do
  o="$OUT/$(basename "${s%.*}").o"
  if [[ "$s" == *.c ]]; then
    gcc-13 -O0 -g -I"$TCBOR" -c "$s" -o "$o"
  else
    $CXX $CXXFLAGS -c "$s" -o "$o"
  fi
  OBJS+=("$o")
done
ar rcs "$OUT/libcomposite.a" "${OBJS[@]}"

echo "== building test executables =="
declare -A TESTS=(
  [cbor_det_test]="$SPDMD/tests/composite/cbor_det_test.cpp"
  [claims_set_builder_test]="$SPDMD/tests/composite/claims_set_builder_test.cpp"
  [submodule_digest_test]="$SPDMD/tests/composite/submodule_digest_test.cpp"
  [collection_plan_test]="$SPDMD/tests/composite/collection_plan_test.cpp"
  [evidence_builder_test]="$SPDMD/tests/composite/evidence_builder_test.cpp"
  [bundle_assembler_test]="$SPDMD/tests/composite/bundle_assembler_test.cpp"
  [evidence_pattern_test]="$SPDMD/tests/composite/evidence_pattern_test.cpp"
  [eat_builder_test]="$SPDMD/tests/mock_attester/eat_builder_test.cpp"
  [mock_attester_test]="$SPDMD/tests/mock_attester/mock_attester_test.cpp"
  [composite_orchestrator_test]="$SPDMD/tests/mock_attester/composite_orchestrator_test.cpp"
)
for name in "${!TESTS[@]}"; do
  $CXX $CXXFLAGS "${TESTS[$name]}" "$OUT/libcomposite.a" \
    $MBEDLIBS $GTESTLIBS -o "$OUT/$name"
done

echo "== running tests =="
rc=0
for name in cbor_det_test claims_set_builder_test submodule_digest_test \
            collection_plan_test evidence_builder_test bundle_assembler_test \
            evidence_pattern_test eat_builder_test \
            mock_attester_test composite_orchestrator_test; do
  echo "---- $name ----"
  "$OUT/$name" --gtest_brief=0 2>&1 | tail -4 || rc=1
done
exit $rc
