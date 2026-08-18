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
//   Pattern A / C  -> spdm-evidence-claims-set
//                       { "signed_measurements", "cert_chain", ?"vca" }
//                     cert_chain is concatenated DER certificates.
//   Pattern B      -> device-eat-claims-set
//                       { "token_format", "device_token" }
//
// The optional CMW-style typed-value form wraps each byte field as
// [content-format, value]; it does not change the evidence semantics.
// The digest (SubmoduleDigest) is computed over the bytes returned here,
// before any bstr wrapping in the tag-602 bundle.

#pragma once

#include "types.hpp"

#include <cstdint>
#include <vector>

namespace spdmd::composite
{

/// CoAP Content-Formats used by the optional typed-value wrapping. These
/// are profile-local placeholders pending registration.
inline constexpr std::uint64_t kCfSpdmMeasurements = 65000;
inline constexpr std::uint64_t kCfConcatenatedDerCertificates = 65001;
inline constexpr std::uint64_t kCfSpdmVca = 65002;

/// Build the deterministic CBOR detached Claims-Set for one successfully
/// collected device.
///
/// @param ev          Collected evidence (must have success == true).
/// @param typedValues When true, wrap SPDM byte fields as CMW-style
///                    [content-format, value] pairs (Pattern A/C only).
/// @return Encoded Claims-Set bytes (unwrapped — feed to SubmoduleDigest
///         and to BundleAssembler's bstr wrapper).
/// @throws std::invalid_argument on empty required fields.
std::vector<std::uint8_t> buildClaimsSet(const CollectedEvidence& ev,
                                         bool typedValues = false);

} // namespace spdmd::composite
