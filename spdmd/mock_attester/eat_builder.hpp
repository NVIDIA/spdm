/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Composite EAT/COSE_Sign1 builder — internal to the mock attester.
//
// Production attester backends build EAT claims and the COSE_Sign1
// envelope inside their Root-of-Trust. This header exists ONLY so
// MockAttester can produce verifier-compatible composite EAT bytes on a
// developer workstation; it is compiled only when attester-backend=mock.
//
// Format references:
//   RFC 9711 — EAT claims (eat_nonce=10, eat_profile=265, submods=266,
//              measurements=273) + ueid (256, RFC 8392).
//   RFC 9052 — COSE_Sign1, Sig_Structure, ES384 (alg=-35).
//   RFC 8392 — CWT wrapping with tag 61.
//
// All CBOR is produced through the deterministic composite::cbor writer.

#pragma once

#include "composite/types.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd::mock_attester::eat
{

/// COSE algorithm identifier for ES384 (IANA COSE Algorithms).
constexpr int kAlgEs384 = -35;

/// Content type declared in the COSE protected header.
constexpr const char* kContentTypeEatCwt = "application/eat+cwt";

/// Build the deterministic CBOR composite-eat-claims map .
///
/// @param nonce       32-byte verifier nonce -> eat_nonce (10).
/// @param ueid        Lead Attester identifier -> ueid (256).
/// @param profileUri  Composite EAT profile -> eat_profile (265).
/// @param submods     Per-device detached digests -> submods (266),
///                    keyed by env.* with value [hash-alg, digest].
/// @param measurements Lead Attester measurements -> measurements (273).
/// @param platformCorimLocator If present -> Platform CoRIM locator hint.
std::vector<std::uint8_t> buildCompositeClaims(
    std::span<const std::uint8_t, composite::kNonceLen> nonce,
    std::span<const std::uint8_t> ueid, std::string_view profileUri,
    std::span<const composite::SubmoduleRecord> submods,
    std::span<const composite::LeadAttesterMeasurement> measurements,
    const std::optional<std::string>& platformCorimLocator);

/// Build CBOR-encoded COSE protected header: {1: alg, 3: content-type}.
std::vector<std::uint8_t> buildProtectedHeader(int alg = kAlgEs384);

/// Build COSE Sig_Structure per RFC 9052 §4.4 — the bytes the signer
/// signs: ["Signature1", body_protected, h'', payload].
std::vector<std::uint8_t>
    buildSigStructure(std::span<const std::uint8_t> protectedHeader,
                      std::span<const std::uint8_t> payload);

/// Assemble a CWT(COSE_Sign1) token: 61(18([4-tuple])). The unprotected
/// header carries x5chain (label 33) with the DER cert chain.
std::vector<std::uint8_t>
    assembleCwtCoseSign1(std::span<const std::uint8_t> protectedHeader,
                         std::span<const std::vector<std::uint8_t>> x5chainDer,
                         std::span<const std::uint8_t> payload,
                         std::span<const std::uint8_t> signature);

/// Split a PEM cert chain into a vector of DER blobs (leaf-first order
/// preserved from the PEM).
std::vector<std::vector<std::uint8_t>> pemToDerChain(std::string_view pem);

} // namespace spdmd::mock_attester::eat
