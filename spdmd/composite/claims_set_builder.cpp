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

#include "claims_set_builder.hpp"

#include "cbor_det.hpp"

#include <stdexcept>

namespace spdmd::composite
{

namespace
{

// Claims-Set text keys (stable; recognized by verifiers).
constexpr const char* kKeySignedMeasurements = "signed_measurements";
constexpr const char* kKeyCertChain = "cert_chain";
constexpr const char* kKeyVca = "vca";
constexpr const char* kKeyTokenFormat = "token_format";
constexpr const char* kKeyDeviceToken = "device_token";

/// Encode a byte field either plain (bstr) or CMW-style typed
/// ([content-format, value]).
std::vector<std::uint8_t> byteField(std::span<const std::uint8_t> bytes,
                                    bool typedValues,
                                    std::uint64_t contentFormat)
{
    if (!typedValues)
    {
        return cbor::bytesVal(bytes);
    }
    std::vector<std::vector<std::uint8_t>> elems;
    elems.push_back(cbor::uintVal(contentFormat));
    elems.push_back(cbor::bytesVal(bytes));
    return cbor::arrayVal(elems);
}

std::vector<std::uint8_t> buildSpdmEvidence(const CollectedEvidence& ev,
                                            bool typedValues)
{
    if (ev.signedMeasurements.empty())
    {
        throw std::invalid_argument(
            "buildClaimsSet: signed_measurements is empty");
    }
    if (ev.certChainSpdm.empty())
    {
        throw std::invalid_argument("buildClaimsSet: cert_chain is empty");
    }
    if (ev.includeVca && ev.vca.empty())
    {
        throw std::invalid_argument("buildClaimsSet: vca is required");
    }

    cbor::Map m;
    m.addText(
        kKeySignedMeasurements,
        byteField(ev.signedMeasurements, typedValues, kCfSpdmMeasurements));
    m.addText(kKeyCertChain,
              byteField(ev.certChainSpdm, typedValues, kCfSpdmCertChain));
    if (ev.includeVca)
    {
        m.addText(kKeyVca, byteField(ev.vca, typedValues, kCfSpdmVca));
    }
    return m.encode();
}

std::vector<std::uint8_t> buildDeviceEat(const CollectedEvidence& ev)
{
    if (ev.deviceTokenFormat.empty())
    {
        throw std::invalid_argument("buildClaimsSet: token_format is empty");
    }
    if (ev.deviceToken.empty())
    {
        throw std::invalid_argument("buildClaimsSet: device_token is empty");
    }

    cbor::Map m;
    m.addText(kKeyTokenFormat, cbor::textVal(ev.deviceTokenFormat));
    m.addText(kKeyDeviceToken, cbor::bytesVal(ev.deviceToken));
    return m.encode();
}

} // namespace

std::vector<std::uint8_t> buildClaimsSet(const CollectedEvidence& ev,
                                         bool typedValues)
{
    switch (ev.pattern)
    {
        case EvidencePattern::SpdmMeasurements:
            return buildSpdmEvidence(ev, typedValues);
        case EvidencePattern::DeviceEat:
            return buildDeviceEat(ev);
    }
    throw std::invalid_argument("buildClaimsSet: unknown pattern");
}

} // namespace spdmd::composite
