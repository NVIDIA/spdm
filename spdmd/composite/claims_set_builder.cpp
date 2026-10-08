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

// Claims-Set text keys for the DirectMap compatibility carriage.
constexpr const char* kKeySignedMeasurements = "signed_measurements";
constexpr const char* kKeyCertChain = "cert_chain";
constexpr const char* kKeyVca = "vca";
constexpr const char* kKeyTokenFormat = "token_format";
constexpr const char* kKeyDeviceToken = "device_token";

void validateSpdmEvidence(const CollectedEvidence& ev)
{
    if (ev.signedMeasurements.empty())
    {
        throw std::invalid_argument(
            "buildClaimsSet: signed_measurements is empty");
    }
    if (ev.certificateChainDer.empty())
    {
        throw std::invalid_argument("buildClaimsSet: cert_chain is empty");
    }
    if (ev.includeVca && ev.vca.empty())
    {
        throw std::invalid_argument("buildClaimsSet: vca is required");
    }
}

std::vector<std::uint8_t> buildDirectSpdmEvidence(const CollectedEvidence& ev)
{
    validateSpdmEvidence(ev);
    cbor::Map m;
    m.addText(kKeySignedMeasurements, cbor::bytesVal(ev.signedMeasurements));
    m.addText(kKeyCertChain, cbor::bytesVal(ev.certificateChainDer));
    if (ev.includeVca)
    {
        m.addText(kKeyVca, cbor::bytesVal(ev.vca));
    }
    return m.encode();
}

void validateDeviceEat(const CollectedEvidence& ev)
{
    if (ev.deviceTokenFormat.empty())
    {
        throw std::invalid_argument("buildClaimsSet: token_format is empty");
    }
    if (ev.deviceToken.empty())
    {
        throw std::invalid_argument("buildClaimsSet: device_token is empty");
    }
}

std::vector<std::uint8_t> buildDirectDeviceEat(const CollectedEvidence& ev)
{
    validateDeviceEat(ev);
    cbor::Map m;
    m.addText(kKeyTokenFormat, cbor::textVal(ev.deviceTokenFormat));
    m.addText(kKeyDeviceToken, cbor::bytesVal(ev.deviceToken));
    return m.encode();
}

// CWT claim 299 carries one RFC 9999 Record CMW.
std::vector<std::uint8_t> buildRecordCmw(const CollectedEvidence& ev)
{
    std::vector<std::vector<std::uint8_t>> cmw;
    switch (ev.pattern)
    {
        case EvidencePattern::SpdmMeasurements:
        {
            validateSpdmEvidence(ev);
            std::vector<std::vector<std::uint8_t>> spdmEvidence{
                cbor::bytesVal(ev.signedMeasurements),
                cbor::bytesVal(ev.certificateChainDer)};
            if (ev.includeVca)
            {
                spdmEvidence.push_back(cbor::bytesVal(ev.vca));
            }
            cmw = {cbor::textVal(kSpdmEvidenceMediaType),
                   cbor::bytesVal(cbor::arrayVal(spdmEvidence)),
                   cbor::uintVal(kCmwIndicatorEvidence)};
            break;
        }
        case EvidencePattern::DeviceEat:
        {
            validateDeviceEat(ev);
            if (ev.deviceTokenFormat != kEatCwtMediaType)
            {
                throw std::invalid_argument(
                    "buildClaimsSet: unsupported device token format");
            }
            cmw = {cbor::textVal(kEatCwtMediaType),
                   cbor::bytesVal(ev.deviceToken),
                   cbor::uintVal(kCmwIndicatorEvidence)};
            break;
        }
    }

    if (cmw.empty())
    {
        throw std::invalid_argument("buildClaimsSet: unknown evidence pattern");
    }

    cbor::Map claims;
    claims.addInt(kCwtClaimCmw, cbor::arrayVal(cmw));
    return claims.encode();
}

} // namespace

std::vector<std::uint8_t> buildClaimsSet(const CollectedEvidence& ev,
                                         EvidenceCarriage carriage)
{
    switch (carriage)
    {
        case EvidenceCarriage::RecordCmw:
            return buildRecordCmw(ev);
        case EvidenceCarriage::DirectMap:
            switch (ev.pattern)
            {
                case EvidencePattern::SpdmMeasurements:
                    return buildDirectSpdmEvidence(ev);
                case EvidencePattern::DeviceEat:
                    return buildDirectDeviceEat(ev);
            }
            throw std::invalid_argument(
                "buildClaimsSet: unknown evidence pattern");
    }
    throw std::invalid_argument("buildClaimsSet: unknown evidence carriage");
}

} // namespace spdmd::composite
