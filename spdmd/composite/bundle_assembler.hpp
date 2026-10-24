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

// BundleAssembler — tag-602 Detached EAT Bundle (RFC 9711, the composite
// attestation profile).
//
//   602([
//     main-token:            bstr .cbor 61(18([...])),   ; signed EAT bytes
//     detached-claims-sets:  { env.* => bstr .cbor cs }  ; per-device
//   ])
//
// The signed composite EAT is wrapped as a byte string; each detached
// Claims-Set is wrapped as `bstr .cbor`. The submodule digest was already
// computed over the unwrapped Claims-Set bytes , so the bytes
// passed here must be exactly those that were digested.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace spdmd::composite
{

/// CBOR tag for an RFC 9711 Detached EAT Bundle.
inline constexpr std::uint64_t kCborTagDetachedEatBundle = 602;

/// Assemble the tag-602 bundle.
///
/// @param compositeEat Signed composite EAT bytes (CWT(COSE_Sign1)).
/// @param detachedClaimsSets Ordered (env.* , encoded Claims-Set bytes)
///        pairs. Keys are emitted in deterministic CBOR order regardless
///        of input order.
/// @return Encoded tag-602 Detached EAT Bundle bytes.
std::vector<std::uint8_t> assembleBundle(
    std::span<const std::uint8_t> compositeEat,
    const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>&
        detachedClaimsSets);

} // namespace spdmd::composite
