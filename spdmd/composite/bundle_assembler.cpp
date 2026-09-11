/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
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

#include "bundle_assembler.hpp"

#include "cbor_det.hpp"

namespace spdmd::composite
{

std::vector<std::uint8_t> assembleBundle(
    std::span<const std::uint8_t> compositeEat,
    const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>&
        detachedClaimsSets)
{
    // detached-claims-sets: map { env.* => bstr .cbor claims-set }.
    cbor::Map csMap;
    for (const auto& [env, cs] : detachedClaimsSets)
    {
        // The value is a byte string whose content is the encoded
        // Claims-Set (bstr .cbor).
        csMap.addText(env, cbor::bytesVal(cs));
    }

    std::vector<std::uint8_t> out;
    cbor::putTag(out, kCborTagDetachedEatBundle);
    cbor::putArrayHeader(out, 2);

    // main-token wrapped as a byte string (bstr .cbor signed-EAT).
    cbor::putBytes(out, compositeEat);

    const std::vector<std::uint8_t> csMapBytes = csMap.encode();
    out.insert(out.end(), csMapBytes.begin(), csMapBytes.end());

    return out;
}

} // namespace spdmd::composite
