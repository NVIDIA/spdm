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

#pragma once

#include "types.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace spdmd::composite
{

struct EvidenceBuilderInput
{
    std::string environmentId;
    std::uint8_t eid = 0;
    bool success = false;
    std::string errorMsg;

    std::uint8_t spdmVersion = 0;
    std::uint8_t measurementSpecification = kSpdmMeasurementSpecDmtf;

    std::vector<std::uint8_t> signedMeasurements;
    std::vector<std::uint8_t> certificateChainDer;
    std::vector<std::uint8_t> vcaTranscript;
    std::vector<std::uint8_t> deviceEatToken;
};

CollectedEvidence makeFailedEvidence(std::uint8_t eid,
                                     std::string environmentId,
                                     std::string errorMsg);

CollectedEvidence buildCollectedEvidence(const EvidenceBuilderInput& input);

bool isUnknownEnvironmentId(std::string_view env);

} // namespace spdmd::composite
