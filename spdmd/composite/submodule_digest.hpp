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

// SubmoduleDigest — SHA-384 over an encoded detached Claims-Set.
//
// Per the composite attestation profile, the detached submodule digest is
// computed over the encoded Claims-Set bytes directly, before the bstr wrapping
// used in the tag-602 bundle and never over a base64 form. This is the single
// value the BMC relays to the Lead Attester per device, and the exact bytes the
// verifier recomputes .

#pragma once

#include "types.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace spdmd::composite
{

/// SHA-384 of arbitrary bytes. Throws std::runtime_error on failure.
std::array<std::uint8_t, kSha384Len> sha384(std::span<const std::uint8_t> b);

/// Build a SubmoduleRecord for @p environmentId from the encoded
/// Claims-Set bytes. hashAlgId is COSE SHA-384 (-43).
SubmoduleRecord makeSubmoduleRecord(std::string environmentId,
                                    std::span<const std::uint8_t> claimsSet);

} // namespace spdmd::composite
