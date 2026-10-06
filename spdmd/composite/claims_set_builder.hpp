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

// ClaimsSetBuilder — deterministic CBOR detached Claims-Sets.
//
// Builds one detached Claims-Set per device. The BMC
// preserves device evidence in its native form; it does not translate
// SPDM transcripts, device EATs, or Concise Evidence into platform-
// authored claims.
//
// Record CMW carriage (default; RFC 9999):
//   Claims-Set = { 299 => [ media-type, evidence-bstr, 4 ] }
//   SPDM:       [ "application/spdm-evidence+cbor",
//                 bstr .cbor [ signed-measurements, cert-chain, ? vca ], 4 ]
//   Device EAT: [ "application/eat+cwt", device-token, 4 ]
//
// DirectMap compatibility carriage:
//   Pattern A / C  -> { "signed_measurements", "cert_chain", ?"vca" }
//   Pattern B      -> { "token_format", "device_token" }
//
// cert-chain is concatenated DER certificates. The digest (SubmoduleDigest)
// is computed over the bytes returned here, before any bstr wrapping in the
// tag-602 bundle.

#pragma once

#include "types.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace spdmd::composite
{

inline constexpr std::int64_t kCwtClaimCmw = 299;
inline constexpr std::uint64_t kCmwIndicatorEvidence = 4;
inline constexpr std::string_view kSpdmEvidenceMediaType =
    "application/spdm-evidence+cbor";
inline constexpr std::string_view kEatCwtMediaType = "application/eat+cwt";

/// Build the deterministic CBOR detached Claims-Set for one successfully
/// collected device.
///
/// @param ev        Collected evidence (must have success == true).
/// @param carriage  Detached Claims-Set encoding.
/// @return Encoded Claims-Set bytes (unwrapped — feed to SubmoduleDigest
///         and to BundleAssembler's bstr wrapper).
/// @throws std::invalid_argument on empty required fields.
std::vector<std::uint8_t>
    buildClaimsSet(const CollectedEvidence& ev,
                   EvidenceCarriage carriage = EvidenceCarriage::RecordCmw);

} // namespace spdmd::composite
