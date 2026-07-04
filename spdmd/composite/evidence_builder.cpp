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

#include "evidence_builder.hpp"

#include <utility>

namespace spdmd::composite
{
namespace
{

constexpr std::string_view unknownEnvPrefix = "env.unknown.";

bool isV10or11(std::uint8_t v)
{
    return v == 0x10 || v == 0x11;
}

} // namespace

bool isUnknownEnvironmentId(std::string_view env)
{
    return env.rfind(unknownEnvPrefix, 0) == 0;
}

CollectedEvidence makeFailedEvidence(std::uint8_t eid,
                                     std::string environmentId,
                                     std::string errorMsg)
{
    CollectedEvidence ev;
    ev.eid = eid;
    ev.environmentId = std::move(environmentId);
    ev.success = false;
    ev.errorMsg = std::move(errorMsg);
    return ev;
}

CollectedEvidence buildCollectedEvidence(const EvidenceBuilderInput& input)
{
    if (!input.success)
    {
        return makeFailedEvidence(input.eid, input.environmentId,
                                  input.errorMsg.empty() ? "Refresh failed"
                                                         : input.errorMsg);
    }

    CollectedEvidence ev;
    ev.eid = input.eid;
    ev.environmentId = input.environmentId;
    ev.success = true;

    ev.pattern = selectEvidencePattern(input.measurementSpecification,
                                       !input.deviceEatToken.empty());
    if (ev.pattern == EvidencePattern::DeviceEat)
    {
        ev.deviceTokenFormat = "application/eat+cwt";
        ev.deviceToken = input.deviceEatToken;
        return ev;
    }

    ev.signedMeasurements = input.signedMeasurements;
    if (ev.signedMeasurements.empty())
    {
        return makeFailedEvidence(input.eid, input.environmentId,
                                  "missing SPDM signed measurements");
    }

    ev.certChainSpdm = input.certificateChainObject;
    if (ev.certChainSpdm.empty())
    {
        return makeFailedEvidence(input.eid, input.environmentId,
                                  "missing SPDM certificate chain object");
    }

    if (isV10or11(input.spdmVersion))
    {
        ev.vca = input.vcaTranscript;
        if (ev.vca.empty())
        {
            return makeFailedEvidence(input.eid, input.environmentId,
                                      "missing SPDM VCA transcript");
        }
        ev.includeVca = true;
    }

    return ev;
}

} // namespace spdmd::composite
